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


class GmailOAuthCallback(BaseModel):
    owner_token: str
    code: str
    connection_name: str = "My Gmail"


class BulkGoogleOAuthCallback(BaseModel):
    owner_token: str
    code: str
    connection_name: str = "My Google (Bulk Merge)"


class SheetRowsRequest(BaseModel):
    connection_id: int
    owner_token: str
    spreadsheet_id: str
    sheet_range: str = "A1:Z1000"


class BulkSendRequest(BaseModel):
    owner_token: str
    bulk_connection_id: int  # the Google connection with Sheets/Drive access
    spreadsheet_id: str
    sheet_range: str = "A1:Z1000"
    email_column: str  # which column header contains the recipient email
    subject_template: str
    body_template: str


class BulkDocumentSendRequest(BaseModel):
    owner_token: str
    bulk_connection_id: int
    spreadsheet_id: str
    sheet_range: str = "A1:Z1000"
    email_column: str
    slides_template_id: str  # the Google Slides presentation to use as a template
    pdf_filename_template: str = "Document-{{name}}.pdf"
    subject_template: str
    body_template: str


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
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = "https://shreelixtech.github.io/shreelix-automate/automate.html"
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
    if conn_type == "gmail_api":
        email = config.get("email", "your Gmail account")
        return f"{email} (Official Gmail API)"
    if conn_type == "google_bulk":
        email = config.get("email", "your Google account")
        return f"{email} (Sheets + Slides + Drive)"
    return "Unknown connection"


@app.post("/auth/gmail/callback", response_model=ConnectionOut)
def gmail_oauth_callback(payload: GmailOAuthCallback, db: Session = Depends(get_db)):
    """Exchanges the authorization code Google gave us for a refresh token, then saves it as a Connection."""
    if not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="Gmail connection isn't configured on the server yet")

    token_resp = _requests.post("https://oauth2.googleapis.com/token", data={
        "code": payload.code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }, timeout=15)

    if not token_resp.ok:
        raise HTTPException(status_code=502, detail=f"Google rejected the authorization: {token_resp.text[:200]}")

    token_data = token_resp.json()
    refresh_token = token_data.get("refresh_token")
    access_token = token_data.get("access_token")
    if not refresh_token:
        raise HTTPException(status_code=502, detail="Google didn't provide a refresh token — try disconnecting this app's access in your Google Account and connecting again")

    # Get the actual email address this token belongs to, for display purposes
    userinfo_resp = _requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    email = userinfo_resp.json().get("email", "unknown") if userinfo_resp.ok else "unknown"

    config = {"refresh_token": refresh_token, "email": email}
    db_conn = Connection(
        owner_token=payload.owner_token,
        name=payload.connection_name,
        conn_type="gmail_api",
        config=_json.dumps(config),
    )
    db.add(db_conn)
    db.commit()
    db.refresh(db_conn)
    return ConnectionOut(
        id=db_conn.id, name=db_conn.name, conn_type=db_conn.conn_type,
        masked_detail=mask_connection_detail(db_conn.conn_type, config),
        created_at=db_conn.created_at,
    )


def get_fresh_access_token(refresh_token: str) -> str:
    """Exchanges a stored refresh token for a short-lived access token — used before any Google API call."""
    token_resp = _requests.post("https://oauth2.googleapis.com/token", data={
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }, timeout=15)
    if not token_resp.ok:
        raise RuntimeError(f"Couldn't refresh Google access — you may need to reconnect: {token_resp.text[:150]}")
    return token_resp.json()["access_token"]


@app.post("/auth/google-bulk/callback", response_model=ConnectionOut)
def google_bulk_oauth_callback(payload: BulkGoogleOAuthCallback, db: Session = Depends(get_db)):
    """Same OAuth exchange as Gmail, but for the broader Sheets/Slides/Drive scopes used for bulk merge."""
    if not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="This isn't configured on the server yet")

    token_resp = _requests.post("https://oauth2.googleapis.com/token", data={
        "code": payload.code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }, timeout=15)

    if not token_resp.ok:
        raise HTTPException(status_code=502, detail=f"Google rejected the authorization: {token_resp.text[:200]}")

    token_data = token_resp.json()
    refresh_token = token_data.get("refresh_token")
    access_token = token_data.get("access_token")
    if not refresh_token:
        raise HTTPException(status_code=502, detail="Google didn't provide a refresh token — try disconnecting this app's access in your Google Account and connecting again")

    userinfo_resp = _requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    email = userinfo_resp.json().get("email", "unknown") if userinfo_resp.ok else "unknown"

    config = {"refresh_token": refresh_token, "email": email}
    db_conn = Connection(
        owner_token=payload.owner_token,
        name=payload.connection_name,
        conn_type="google_bulk",
        config=_json.dumps(config),
    )
    db.add(db_conn)
    db.commit()
    db.refresh(db_conn)
    return ConnectionOut(
        id=db_conn.id, name=db_conn.name, conn_type=db_conn.conn_type,
        masked_detail=mask_connection_detail(db_conn.conn_type, config),
        created_at=db_conn.created_at,
    )


def extract_spreadsheet_id(input_str: str) -> str:
    """Accepts either a raw Sheet ID or a full Google Sheets URL and returns just the ID."""
    if "/d/" in input_str:
        return input_str.split("/d/")[1].split("/")[0]
    return input_str.strip()


@app.post("/bulk/sheet-rows")
def get_sheet_rows(payload: SheetRowsRequest, db: Session = Depends(get_db)):
    """Reads a Google Sheet and returns rows as a list of {column_name: value} dicts, using the first row as headers."""
    conn = db.query(Connection).filter(
        Connection.id == payload.connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not conn or conn.conn_type != "google_bulk":
        raise HTTPException(status_code=404, detail="Bulk Google connection not found")

    config = _json.loads(conn.config)
    access_token = get_fresh_access_token(config["refresh_token"])
    sheet_id = extract_spreadsheet_id(payload.spreadsheet_id)

    resp = _requests.get(
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{payload.sheet_range}",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Couldn't read the sheet: {resp.text[:200]}")

    values = resp.json().get("values", [])
    if not values:
        return {"headers": [], "rows": []}

    headers = values[0]
    rows = []
    for row in values[1:]:
        row_dict = {}
        for i, header in enumerate(headers):
            row_dict[header] = row[i] if i < len(row) else ""
        rows.append(row_dict)
    return {"headers": headers, "rows": rows}


@app.post("/bulk/send")
def bulk_send(payload: BulkSendRequest, db: Session = Depends(get_db)):
    """Reads every row from a Sheet, fills the message template per row, and sends via Gmail — one send per row."""
    bulk_conn = db.query(Connection).filter(
        Connection.id == payload.bulk_connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not bulk_conn or bulk_conn.conn_type != "google_bulk":
        raise HTTPException(status_code=404, detail="Bulk Google connection not found")

    bulk_config = _json.loads(bulk_conn.config)
    access_token = get_fresh_access_token(bulk_config["refresh_token"])
    sheet_id = extract_spreadsheet_id(payload.spreadsheet_id)

    resp = _requests.get(
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{payload.sheet_range}",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Couldn't read the sheet: {resp.text[:200]}")

    values = resp.json().get("values", [])
    if len(values) < 2:
        raise HTTPException(status_code=400, detail="Sheet has no data rows (needs a header row plus at least one data row)")

    headers = values[0]
    if payload.email_column not in headers:
        raise HTTPException(status_code=400, detail=f"Column '{payload.email_column}' not found in sheet. Found columns: {headers}")

    results = {"sent": 0, "failed": 0, "errors": []}
    from_email = bulk_config.get("email", "me")

    for row in values[1:]:
        row_dict = {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}
        to_addr = row_dict.get(payload.email_column, "").strip()
        if not to_addr:
            results["failed"] += 1
            results["errors"].append("Skipped a row with no email address")
            continue

        subject = payload.subject_template
        body = payload.body_template
        for col, val in row_dict.items():
            subject = subject.replace("{{" + col + "}}", str(val))
            body = body.replace("{{" + col + "}}", str(val))

        try:
            send_via_gmail_api(bulk_config, subject, body, to_addr)
            results["sent"] += 1
            log = MessageLog(
                owner_token=payload.owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=(body[:120] + "...") if len(body) > 120 else body, status="sent",
            )
            db.add(log)
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"{to_addr}: {str(e)[:150]}")
            log = MessageLog(
                owner_token=payload.owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=(body[:120] + "...") if len(body) > 120 else body,
                status="failed", error=str(e)[:300],
            )
            db.add(log)

    db.commit()
    return results


@app.post("/bulk/generate-and-send")
def bulk_generate_and_send(payload: BulkDocumentSendRequest, db: Session = Depends(get_db)):
    """For every row in the sheet: duplicate the Slides template, fill in that row's data,
    export as PDF, email it as an attachment, then clean up the temporary copy."""
    bulk_conn = db.query(Connection).filter(
        Connection.id == payload.bulk_connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not bulk_conn or bulk_conn.conn_type != "google_bulk":
        raise HTTPException(status_code=404, detail="Bulk Google connection not found")

    bulk_config = _json.loads(bulk_conn.config)
    access_token = get_fresh_access_token(bulk_config["refresh_token"])
    sheet_id = extract_spreadsheet_id(payload.spreadsheet_id)

    resp = _requests.get(
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{payload.sheet_range}",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Couldn't read the sheet: {resp.text[:200]}")

    values = resp.json().get("values", [])
    if len(values) < 2:
        raise HTTPException(status_code=400, detail="Sheet has no data rows")

    headers = values[0]
    if payload.email_column not in headers:
        raise HTTPException(status_code=400, detail=f"Column '{payload.email_column}' not found. Found columns: {headers}")

    results = {"sent": 0, "failed": 0, "errors": []}

    for row in values[1:]:
        row_dict = {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}
        to_addr = row_dict.get(payload.email_column, "").strip()
        if not to_addr:
            results["failed"] += 1
            results["errors"].append("Skipped a row with no email address")
            continue

        subject = payload.subject_template
        body = payload.body_template
        filename = payload.pdf_filename_template
        for col, val in row_dict.items():
            subject = subject.replace("{{" + col + "}}", str(val))
            body = body.replace("{{" + col + "}}", str(val))
            filename = filename.replace("{{" + col + "}}", str(val))

        copy_id = None
        row_access_token = None
        try:
            # Fresh access token per row — long bulk jobs can outlast a single token's ~1hr lifetime
            row_access_token = get_fresh_access_token(bulk_config["refresh_token"])
            slides_id = extract_spreadsheet_id(payload.slides_template_id)
            copy_id = duplicate_slides_template(row_access_token, slides_id, f"temp-{filename}")
            fill_slides_placeholders(row_access_token, copy_id, row_dict)
            pdf_bytes = export_slides_as_pdf(row_access_token, copy_id)
            send_via_gmail_api_with_attachment(bulk_config, subject, body, to_addr, pdf_bytes, filename)

            results["sent"] += 1
            db.add(MessageLog(
                owner_token=payload.owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=f"[PDF attached: {filename}] " + (body[:100] if len(body) > 100 else body),
                status="sent",
            ))
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"{to_addr}: {str(e)[:150]}")
            db.add(MessageLog(
                owner_token=payload.owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=f"[PDF generation failed]",
                status="failed", error=str(e)[:300],
            ))
        finally:
            if copy_id and row_access_token:
                delete_drive_file(row_access_token, copy_id)

    db.commit()
    return results


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


def send_via_gmail_api(config: dict, subject: str, body: str, to_addr: str):
    import base64

    refresh_token = config["refresh_token"]
    from_email = config.get("email", "me")

    # Exchange the stored refresh token for a fresh, short-lived access token
    token_resp = _requests.post("https://oauth2.googleapis.com/token", data={
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }, timeout=15)
    if not token_resp.ok:
        raise RuntimeError(f"Couldn't refresh Gmail access — you may need to reconnect this Gmail account: {token_resp.text[:150]}")
    access_token = token_resp.json()["access_token"]

    msg = MIMEText(body)
    msg["Subject"] = subject or "(no subject)"
    msg["From"] = from_email
    msg["To"] = to_addr
    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

    send_resp = _requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"raw": raw_message},
        timeout=15,
    )
    if not send_resp.ok:
        raise RuntimeError(f"Gmail API rejected the send: {send_resp.text[:200]}")


def send_via_gmail_api_with_attachment(config: dict, subject: str, body: str, to_addr: str, attachment_bytes: bytes, attachment_filename: str):
    import base64
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText as _MIMEText
    from email import encoders

    access_token = get_fresh_access_token(config["refresh_token"])
    from_email = config.get("email", "me")

    msg = MIMEMultipart()
    msg["Subject"] = subject or "(no subject)"
    msg["From"] = from_email
    msg["To"] = to_addr
    msg.attach(_MIMEText(body))

    part = MIMEBase("application", "pdf")
    part.set_payload(attachment_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{attachment_filename}"')
    msg.attach(part)

    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    send_resp = _requests.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"raw": raw_message},
        timeout=20,
    )
    if not send_resp.ok:
        raise RuntimeError(f"Gmail API rejected the send: {send_resp.text[:200]}")


def duplicate_slides_template(access_token: str, template_id: str, new_name: str) -> str:
    """Makes a fresh copy of a Slides template via the Drive API. Returns the new file's ID."""
    resp = _requests.post(
        f"https://www.googleapis.com/drive/v3/files/{template_id}/copy",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"name": new_name},
        timeout=20,
    )
    if not resp.ok:
        raise RuntimeError(f"Couldn't duplicate the Slides template: {resp.text[:200]}")
    return resp.json()["id"]


def fill_slides_placeholders(access_token: str, file_id: str, replacements: dict):
    """Replaces every {{column}} placeholder in the copied Slides file with real values, via batchUpdate."""
    requests_body = []
    for placeholder, value in replacements.items():
        requests_body.append({
            "replaceAllText": {
                "containsText": {"text": "{{" + placeholder + "}}", "matchCase": True},
                "replaceText": str(value),
            }
        })
    resp = _requests.post(
        f"https://slides.googleapis.com/v1/presentations/{file_id}:batchUpdate",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"requests": requests_body},
        timeout=20,
    )
    if not resp.ok:
        raise RuntimeError(f"Couldn't fill in the template: {resp.text[:200]}")


def export_slides_as_pdf(access_token: str, file_id: str) -> bytes:
    """Exports a Google Slides file as PDF bytes via the Drive API."""
    resp = _requests.get(
        f"https://www.googleapis.com/drive/v3/files/{file_id}/export",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"mimeType": "application/pdf"},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"Couldn't export the document as PDF: {resp.text[:200]}")
    return resp.content


def delete_drive_file(access_token: str, file_id: str):
    """Cleans up the temporary duplicated file after we've exported it — best-effort, doesn't raise on failure."""
    try:
        _requests.delete(
            f"https://www.googleapis.com/drive/v3/files/{file_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
    except Exception:
        pass  # cleanup failure shouldn't break the actual send


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
        elif conn.conn_type == "gmail_api":
            if not payload.to_address:
                raise ValueError("An email address to send to is required")
            send_via_gmail_api(config, payload.subject or "", payload.body, payload.to_address)
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
