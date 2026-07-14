import os
import json as _json
import smtplib
import socket
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Optional

import requests as _requests
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Render's outbound network doesn't support IPv6 — some providers (like Gmail's SMTP)
# resolve to an IPv6 address first, causing "Network is unreachable". Force IPv4-only
# DNS resolution globally so this can't happen on any outbound connection (SMTP, webhooks, APIs).
_original_getaddrinfo = socket.getaddrinfo
def _ipv4_only_getaddrinfo(*args, **kwargs):
    responses = _original_getaddrinfo(*args, **kwargs)
    ipv4_only = [r for r in responses if r[0] == socket.AF_INET]
    return ipv4_only if ipv4_only else responses
socket.getaddrinfo = _ipv4_only_getaddrinfo

# ---------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------
# Models
# ---------------------------------------------------------------
class AppUser(Base):
    __tablename__ = "app_users"
    id = Column(Integer, primary_key=True, index=True)
    user_token = Column(String, unique=True, nullable=False, index=True)  # Google's verified 'sub' claim
    auth_provider = Column(String, nullable=False, default="google")
    business_name = Column(String, nullable=False)
    contact_name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    product = Column(String, nullable=False, default="automate")
    tokens_used = Column(Integer, nullable=False, default=0)
    subscription_status = Column(String, nullable=False, default="free")  # free, paid
    subscription_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_active_at = Column(DateTime, default=datetime.utcnow)


class Connection(Base):
    __tablename__ = "connections"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)  # user-friendly label, e.g. "My Gmail"
    conn_type = Column(String, nullable=False)  # smtp, webhook, http
    config = Column(String, nullable=False)  # JSON-encoded config, type-specific fields
    created_at = Column(DateTime, default=datetime.utcnow)


class MessageLog(Base):
    __tablename__ = "message_logs"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    connection_id = Column(Integer, ForeignKey("connections.id"), nullable=True)
    connection_name = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    body_preview = Column(String, nullable=True)
    status = Column(String, nullable=False, default="sent")  # sent, failed
    error = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------
class AppUserOut(BaseModel):
    id: int
    user_token: str
    auth_provider: str
    business_name: str
    contact_name: Optional[str]
    email: Optional[str]
    product: str
    tokens_used: int
    subscription_status: str
    subscription_expires_at: Optional[datetime]
    created_at: datetime
    last_active_at: datetime
    class Config:
        from_attributes = True


class GoogleAuthRequest(BaseModel):
    credential: str
    business_name: Optional[str] = None


class GoogleAuthResponse(BaseModel):
    owner_token: str
    email: str
    name: Optional[str]
    is_new_user: bool
    user: AppUserOut


class SubscriptionUpdate(BaseModel):
    subscription_status: str


class ConnectionCreate(BaseModel):
    owner_token: str
    name: str
    conn_type: str  # smtp, webhook, http
    config: dict


class ConnectionOut(BaseModel):
    id: int
    name: str
    conn_type: str
    masked_detail: str
    created_at: datetime
    class Config:
        from_attributes = True


class SendMessageRequest(BaseModel):
    owner_token: str
    connection_id: int
    to_address: Optional[str] = None  # who to send to — chosen per message, not fixed on the connection
    subject: Optional[str] = None
    body: str


class MessageLogOut(BaseModel):
    id: int
    connection_name: Optional[str]
    subject: Optional[str]
    body_preview: Optional[str]
    status: str
    error: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True


# ---------------------------------------------------------------
# App
# ---------------------------------------------------------------
app = FastAPI(title="ShreeLix Automate API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok", "service": "ShreeLix Automate API"}


@app.get("/health")
def health():
    return {"status": "healthy"}


# ---------------------------------------------------------------
# Google Sign-In (same verified pattern as Billing)
# ---------------------------------------------------------------
GOOGLE_CLIENT_ID = "121520616317-h33rgmtjgvc1gd2i2dga9i2nnjlmhi9v.apps.googleusercontent.com"
FREE_TOKEN_LIMIT = 100


@app.post("/auth/google", response_model=GoogleAuthResponse)
def google_signin(payload: GoogleAuthRequest, db: Session = Depends(get_db)):
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    try:
        idinfo = google_id_token.verify_oauth2_token(
            payload.credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Google sign-in token")
    except Exception:
        raise HTTPException(status_code=503, detail="Couldn't verify sign-in with Google right now — please try again")

    google_sub = idinfo["sub"]
    email = idinfo.get("email")
    name = idinfo.get("name")

    existing = db.query(AppUser).filter(AppUser.user_token == google_sub).first()

    if existing:
        existing.last_active_at = datetime.utcnow()
        if email and not existing.email:
            existing.email = email
        db.commit()
        db.refresh(existing)
        return GoogleAuthResponse(owner_token=google_sub, email=email, name=name, is_new_user=False, user=existing)

    if not payload.business_name:
        raise HTTPException(status_code=400, detail="business_name is required for first-time sign-in")

    db_user = AppUser(
        user_token=google_sub,
        auth_provider="google",
        business_name=payload.business_name,
        contact_name=name,
        email=email,
        product="automate",
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return GoogleAuthResponse(owner_token=google_sub, email=email, name=name, is_new_user=True, user=db_user)


@app.get("/users/me", response_model=AppUserOut)
def get_my_usage(user_token: str, db: Session = Depends(get_db)):
    user = db.query(AppUser).filter(AppUser.user_token == user_token).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def is_subscription_active(user: AppUser) -> bool:
    if user.subscription_status != "paid":
        return False
    if user.subscription_expires_at is None:
        return False
    return user.subscription_expires_at > datetime.utcnow()


@app.post("/users/track", response_model=AppUserOut)
def track_usage(user_token: str, db: Session = Depends(get_db)):
    user = db.query(AppUser).filter(AppUser.user_token == user_token).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found — register first")

    if is_subscription_active(user):
        user.tokens_used += 1
        user.last_active_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user

    if user.subscription_status == "paid":
        user.subscription_status = "free"

    if user.tokens_used >= FREE_TOKEN_LIMIT:
        db.commit()
        raise HTTPException(status_code=402, detail="Free credits used up — upgrade to continue")

    user.tokens_used += 1
    user.last_active_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------
# Admin
# ---------------------------------------------------------------
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def check_admin(key: str):
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Admin access not configured on the server yet")
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


@app.get("/admin/users", response_model=list[AppUserOut])
def admin_list_users(key: str, db: Session = Depends(get_db)):
    check_admin(key)
    return db.query(AppUser).order_by(AppUser.created_at.desc()).all()


@app.patch("/admin/users/{user_id}/subscription", response_model=AppUserOut)
def admin_update_subscription(user_id: int, update: SubscriptionUpdate, key: str, db: Session = Depends(get_db)):
    check_admin(key)
    if update.subscription_status not in {"free", "paid"}:
        raise HTTPException(status_code=400, detail="subscription_status must be 'free' or 'paid'")
    user = db.query(AppUser).filter(AppUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.subscription_status = update.subscription_status
    if update.subscription_status == "paid":
        user.subscription_expires_at = datetime.utcnow() + timedelta(days=30)
    else:
        user.subscription_expires_at = None
    db.commit()
    db.refresh(user)
    return user


@app.post("/admin/users/{user_id}/renew", response_model=AppUserOut)
def admin_renew_subscription(user_id: int, key: str, db: Session = Depends(get_db)):
    check_admin(key)
    user = db.query(AppUser).filter(AppUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    base = user.subscription_expires_at if (user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow()) else datetime.utcnow()
    user.subscription_status = "paid"
    user.subscription_expires_at = base + timedelta(days=30)
    db.commit()
    db.refresh(user)
    return user


@app.get("/admin/summary")
def admin_summary(key: str, db: Session = Depends(get_db)):
    check_admin(key)
    total_users = db.query(AppUser).count()
    paid_users = db.query(AppUser).filter(AppUser.subscription_status == "paid").count()
    total_connections = db.query(Connection).count()
    total_messages = db.query(MessageLog).count()
    failed_messages = db.query(MessageLog).filter(MessageLog.status == "failed").count()
    return {
        "total_users": total_users,
        "paid_users": paid_users,
        "free_users": total_users - paid_users,
        "total_connections": total_connections,
        "total_messages": total_messages,
        "failed_messages": failed_messages,
    }


# ---------------------------------------------------------------
# Connections
# ---------------------------------------------------------------
def mask_connection_detail(conn_type: str, config: dict) -> str:
    if conn_type == "smtp":
        host = config.get("host", "?")
        username = config.get("username", "?")
        masked_user = username[:2] + "***" + username[-6:] if len(username) > 8 else "***"
        return f"{masked_user} via {host}"
    if conn_type == "webhook":
        url = config.get("url", "")
        return url[:40] + "..." if len(url) > 40 else url
    if conn_type == "http":
        url = config.get("url", "")
        method = config.get("method", "POST")
        return f"{method} {url[:35]}"
    return "Unknown connection"


@app.post("/connections", response_model=ConnectionOut)
def create_connection(payload: ConnectionCreate, db: Session = Depends(get_db)):
    if payload.conn_type not in {"smtp", "webhook", "http"}:
        raise HTTPException(status_code=400, detail="conn_type must be 'smtp', 'webhook', or 'http'")
    db_conn = Connection(
        owner_token=payload.owner_token,
        name=payload.name,
        conn_type=payload.conn_type,
        config=_json.dumps(payload.config),
    )
    db.add(db_conn)
    db.commit()
    db.refresh(db_conn)
    return ConnectionOut(
        id=db_conn.id, name=db_conn.name, conn_type=db_conn.conn_type,
        masked_detail=mask_connection_detail(db_conn.conn_type, payload.config),
        created_at=db_conn.created_at,
    )


@app.get("/connections", response_model=list[ConnectionOut])
def list_connections(owner_token: str, db: Session = Depends(get_db)):
    conns = db.query(Connection).filter(Connection.owner_token == owner_token).order_by(Connection.id.desc()).all()
    result = []
    for c in conns:
        try:
            cfg = _json.loads(c.config)
        except Exception:
            cfg = {}
        result.append(ConnectionOut(
            id=c.id, name=c.name, conn_type=c.conn_type,
            masked_detail=mask_connection_detail(c.conn_type, cfg),
            created_at=c.created_at,
        ))
    return result


@app.delete("/connections/{connection_id}")
def delete_connection(connection_id: int, owner_token: str, db: Session = Depends(get_db)):
    conn = db.query(Connection).filter(Connection.id == connection_id, Connection.owner_token == owner_token).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    db.delete(conn)
    db.commit()
    return {"status": "deleted"}


# ---------------------------------------------------------------
# Sending engine
# ---------------------------------------------------------------
def send_via_smtp(config: dict, subject: str, body: str, to_addr: str):
    host = config["host"]
    port = int(config.get("port", 587))
    username = config["username"]
    password = config["password"]
    from_addr = config.get("from_address", username)
    use_ssl = config.get("use_ssl", port == 465)

    msg = MIMEText(body)
    msg["Subject"] = subject or "(no subject)"
    msg["From"] = from_addr
    msg["To"] = to_addr

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            server.login(username, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())


def send_via_webhook(config: dict, subject: str, body: str):
    url = config["url"]
    payload_key = config.get("payload_key", "text")
    payload = {payload_key: body}
    if subject:
        payload["subject"] = subject
    resp = _requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()


def send_via_http(config: dict, subject: str, body: str):
    method = config.get("method", "POST").upper()
    url = config["url"]
    headers = config.get("headers", {})
    body_template = config.get("body_template", body)
    filled_body = body_template.replace("{{subject}}", subject or "").replace("{{body}}", body)
    resp = _requests.request(method, url, headers=headers, data=filled_body, timeout=15)
    resp.raise_for_status()


@app.post("/send", response_model=MessageLogOut)
def send_message(payload: SendMessageRequest, db: Session = Depends(get_db)):
    conn = db.query(Connection).filter(
        Connection.id == payload.connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    config = _json.loads(conn.config)
    error = None
    status = "sent"
    try:
        if conn.conn_type == "smtp":
            if not payload.to_address:
                raise ValueError("An email address to send to is required")
            send_via_smtp(config, payload.subject or "", payload.body, payload.to_address)
        elif conn.conn_type == "webhook":
            send_via_webhook(config, payload.subject or "", payload.body)
        elif conn.conn_type == "http":
            send_via_http(config, payload.subject or "", payload.body)
        else:
            raise ValueError("Unknown connection type")
    except Exception as e:
        status = "failed"
        error = str(e)[:300]

    log = MessageLog(
        owner_token=payload.owner_token,
        connection_id=conn.id,
        connection_name=conn.name,
        subject=payload.subject,
        body_preview=(payload.body[:120] + "...") if len(payload.body) > 120 else payload.body,
        status=status,
        error=error,
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    if status == "failed":
        raise HTTPException(status_code=502, detail=f"Send failed: {error}")
    return log


@app.get("/logs", response_model=list[MessageLogOut])
def list_message_logs(owner_token: str, db: Session = Depends(get_db)):
    return db.query(MessageLog).filter(MessageLog.owner_token == owner_token).order_by(MessageLog.id.desc()).limit(100).all()
