import os
import json as _json
import smtplib
import socket
import hmac
import hashlib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Optional

import requests as _requests
from fastapi import FastAPI, HTTPException, Depends, Request
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


class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    connection_id = Column(Integer, ForeignKey("connections.id"), nullable=False)
    name = Column(String, nullable=False)
    mode = Column(String, nullable=False, default="single")  # "single", "bulk_send", "bulk_document"
    to_address = Column(String, nullable=True)  # used when mode="single" with smtp/gmail_api connections
    subject = Column(String, nullable=True)
    body = Column(String, nullable=False)
    frequency = Column(String, nullable=False, default="daily")  # "daily" or "once"
    scheduled_time = Column(String, nullable=False)  # "HH:MM", 24-hour
    scheduled_date = Column(String, nullable=True)  # "YYYY-MM-DD", only used when frequency="once"
    is_active = Column(String, nullable=False, default="yes")  # "yes"/"no" — pause without deleting
    last_run_at = Column(DateTime, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)  # how many times we've retried the CURRENT failure
    max_retries = Column(Integer, nullable=False, default=3)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Bulk mode fields — used when mode="bulk_send" or "bulk_document"
    spreadsheet_id = Column(String, nullable=True)
    sheet_range = Column(String, nullable=True, default="A1:Z1000")
    email_column = Column(String, nullable=True)
    slides_template_id = Column(String, nullable=True)  # used only when mode="bulk_document"
    pdf_filename_template = Column(String, nullable=True)
    # Optional per-row condition for bulk modes — skip a row unless it passes. Blank = send to every row.
    condition_column = Column(String, nullable=True)
    condition_operator = Column(String, nullable=True)  # "equals", "not_equals", "greater_than", "less_than", "contains"
    condition_value = Column(String, nullable=True)


class WorkflowStep(Base):
    """Additional steps chained after a schedule's primary action (its own connection_id/to_address/
    subject/body count as 'Step 1' automatically). Only supported for mode='single' schedules."""
    __tablename__ = "workflow_steps"
    id = Column(Integer, primary_key=True, index=True)
    schedule_id = Column(Integer, ForeignKey("schedules.id"), nullable=False)
    step_order = Column(Integer, nullable=False, default=1)  # 2, 3, 4... (1 is the schedule's own primary action)
    connection_id = Column(Integer, ForeignKey("connections.id"), nullable=False)
    to_address = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    body = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class InboundWebhook(Base):
    """A unique URL an external service can POST to, which triggers a configured action here.
    This is the reverse of our other connectors — instead of us sending out, something notifies us in."""
    __tablename__ = "inbound_webhooks"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    token = Column(String, unique=True, nullable=False, index=True)  # the secret part of the URL
    name = Column(String, nullable=False)
    connection_id = Column(Integer, ForeignKey("connections.id"), nullable=False)  # where the resulting action gets sent
    to_address = Column(String, nullable=True)
    subject_template = Column(String, nullable=True)  # can use {{field}} from the incoming payload
    body_template = Column(String, nullable=False)
    # Optional condition — only fire the action if this passes. Left blank = always fire.
    condition_field = Column(String, nullable=True)  # which key in the incoming JSON payload to check
    condition_operator = Column(String, nullable=True)  # "equals", "not_equals", "greater_than", "less_than", "contains"
    condition_value = Column(String, nullable=True)
    is_active = Column(String, nullable=False, default="yes")
    trigger_count = Column(Integer, nullable=False, default=0)
    last_triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    business_name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    message = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")  # "open", "resolved"
    created_at = Column(DateTime, default=datetime.utcnow)


class Payment(Base):
    """Real money audit trail — every Razorpay order created and every verified payment gets logged here,
    regardless of success or failure, so nothing about actual payments is ever silently lost."""
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    owner_token = Column(String, nullable=False, index=True)
    razorpay_order_id = Column(String, nullable=False, index=True)
    razorpay_payment_id = Column(String, nullable=True)
    amount = Column(Integer, nullable=False)  # in paise
    status = Column(String, nullable=False, default="created")  # "created", "verified", "signature_failed"
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)


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
    condition_column: Optional[str] = None
    condition_operator: Optional[str] = None
    condition_value: Optional[str] = None


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
    condition_column: Optional[str] = None
    condition_operator: Optional[str] = None
    condition_value: Optional[str] = None


class ScheduleCreate(BaseModel):
    owner_token: str
    connection_id: int
    name: str
    mode: str = "single"  # "single", "bulk_send", "bulk_document"
    to_address: Optional[str] = None
    subject: Optional[str] = None
    body: str
    frequency: str = "daily"  # "daily" or "once"
    scheduled_time: str  # "HH:MM"
    scheduled_date: Optional[str] = None  # "YYYY-MM-DD", required if frequency="once"
    spreadsheet_id: Optional[str] = None
    sheet_range: str = "A1:Z1000"
    email_column: Optional[str] = None
    slides_template_id: Optional[str] = None
    pdf_filename_template: Optional[str] = None
    condition_column: Optional[str] = None
    condition_operator: Optional[str] = None
    condition_value: Optional[str] = None


class ScheduleOut(BaseModel):
    id: int
    connection_id: int
    name: str
    mode: str
    to_address: Optional[str]
    subject: Optional[str]
    body: str
    frequency: str
    scheduled_time: str
    scheduled_date: Optional[str]
    is_active: str
    last_run_at: Optional[datetime]
    created_at: datetime
    spreadsheet_id: Optional[str]
    sheet_range: Optional[str]
    email_column: Optional[str]
    slides_template_id: Optional[str]
    pdf_filename_template: Optional[str]
    condition_column: Optional[str]
    condition_operator: Optional[str]
    condition_value: Optional[str]
    retry_count: int
    max_retries: int
    class Config:
        from_attributes = True


class ScheduleToggle(BaseModel):
    owner_token: str
    is_active: bool


class WorkflowStepCreate(BaseModel):
    owner_token: str
    connection_id: int
    to_address: Optional[str] = None
    subject: Optional[str] = None
    body: str


class WorkflowStepOut(BaseModel):
    id: int
    schedule_id: int
    step_order: int
    connection_id: int
    to_address: Optional[str]
    subject: Optional[str]
    body: str
    created_at: datetime
    class Config:
        from_attributes = True


class InboundWebhookCreate(BaseModel):
    owner_token: str
    name: str
    connection_id: int
    to_address: Optional[str] = None
    subject_template: Optional[str] = None
    body_template: str
    condition_field: Optional[str] = None
    condition_operator: Optional[str] = None
    condition_value: Optional[str] = None


class InboundWebhookOut(BaseModel):
    id: int
    token: str
    name: str
    connection_id: int
    to_address: Optional[str]
    subject_template: Optional[str]
    body_template: str
    condition_field: Optional[str]
    condition_operator: Optional[str]
    condition_value: Optional[str]
    is_active: str
    trigger_count: int
    last_triggered_at: Optional[datetime]
    created_at: datetime
    class Config:
        from_attributes = True


class SupportTicketCreate(BaseModel):
    owner_token: str
    business_name: Optional[str] = None
    email: Optional[str] = None
    message: str


class SupportTicketOut(BaseModel):
    id: int
    business_name: Optional[str]
    email: Optional[str]
    message: str
    status: str
    created_at: datetime
    class Config:
        from_attributes = True


class CreateOrderRequest(BaseModel):
    owner_token: str


class CreateOrderResponse(BaseModel):
    order_id: str
    amount: int
    currency: str
    key_id: str


class VerifyPaymentRequest(BaseModel):
    owner_token: str
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


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

RAZORPAY_KEY_ID = "rzp_test_THRRlsDu9ixHo8"
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
SUBSCRIPTION_PRICE_PAISE = 29900  # ₹299.00 — Razorpay amounts are always in paise


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
    if conn_type in {"google_bulk", "google"}:
        email = config.get("email", "your Google account")
        return f"{email} (Gmail + Sheets + Slides + Drive)"
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
        conn_type="google",
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


def evaluate_condition(field_value, operator, expected_value) -> bool:
    """Shared condition check — used for both bulk-row filtering and inbound webhook triggers.
    No condition set (operator/expected_value blank) always passes."""
    if not operator or expected_value is None or expected_value == "":
        return True
    field_str = "" if field_value is None else str(field_value).strip()
    expected_str = str(expected_value).strip()
    try:
        if operator == "equals":
            return field_str == expected_str
        if operator == "not_equals":
            return field_str != expected_str
        if operator == "contains":
            return expected_str.lower() in field_str.lower()
        if operator == "greater_than":
            return float(field_str) > float(expected_str)
        if operator == "less_than":
            return float(field_str) < float(expected_str)
    except (ValueError, TypeError):
        return False  # e.g. comparing "abc" > "5" numerically — treat as not matching rather than crashing
    return True


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
    if not conn or conn.conn_type not in {"google_bulk", "google"}:
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


GMAIL_DAILY_SAFETY_LIMIT = 450  # Gmail's real cap is ~500/day for regular accounts — stop safely before hitting it


def get_todays_send_count(db: Session, connection_id: int) -> int:
    today_start = now_ist().replace(hour=0, minute=0, second=0, microsecond=0) - IST_OFFSET  # convert back to UTC for the DB comparison
    return db.query(MessageLog).filter(
        MessageLog.connection_id == connection_id,
        MessageLog.status == "sent",
        MessageLog.created_at >= today_start,
    ).count()


def run_bulk_email_send(db: Session, owner_token: str, bulk_conn: Connection, spreadsheet_id: str,
                          sheet_range: str, email_column: str, subject_template: str, body_template: str,
                          condition_column: Optional[str] = None, condition_operator: Optional[str] = None,
                          condition_value: Optional[str] = None) -> dict:
    """Core logic: read every row from a Sheet, personalize, send via Gmail. Used by both the
    immediate 'Send Now' button and scheduled bulk sends — one tested code path for both."""
    bulk_config = _json.loads(bulk_conn.config)
    try:
        access_token = get_fresh_access_token(bulk_config["refresh_token"])
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    sheet_id = extract_spreadsheet_id(spreadsheet_id)

    resp = _requests.get(
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{sheet_range}",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Couldn't read the sheet: {resp.text[:200]}")

    values = resp.json().get("values", [])
    if len(values) < 2:
        raise HTTPException(status_code=400, detail="Sheet has no data rows (needs a header row plus at least one data row)")

    headers = values[0]
    if email_column not in headers:
        raise HTTPException(status_code=400, detail=f"Column '{email_column}' not found in sheet. Found columns: {headers}")

    results = {"sent": 0, "failed": 0, "skipped_by_condition": 0, "stopped_early_rate_limit": False, "errors": []}
    sent_today = get_todays_send_count(db, bulk_conn.id)

    for row in values[1:]:
        if sent_today >= GMAIL_DAILY_SAFETY_LIMIT:
            results["stopped_early_rate_limit"] = True
            results["errors"].append(f"Stopped early — approaching Gmail's daily sending limit ({GMAIL_DAILY_SAFETY_LIMIT}/day). Remaining rows will need to send tomorrow or via a different connection.")
            break

        row_dict = {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}

        if condition_column and not evaluate_condition(row_dict.get(condition_column), condition_operator, condition_value):
            results["skipped_by_condition"] += 1
            continue

        to_addr = row_dict.get(email_column, "").strip()
        if not to_addr:
            results["failed"] += 1
            results["errors"].append("Skipped a row with no email address")
            continue

        subject = subject_template
        body = body_template
        for col, val in row_dict.items():
            subject = subject.replace("{{" + col + "}}", str(val))
            body = body.replace("{{" + col + "}}", str(val))

        try:
            send_via_gmail_api(bulk_config, subject, body, to_addr)
            results["sent"] += 1
            sent_today += 1
            db.add(MessageLog(
                owner_token=owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=(body[:120] + "...") if len(body) > 120 else body, status="sent",
            ))
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"{to_addr}: {str(e)[:150]}")
            db.add(MessageLog(
                owner_token=owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=(body[:120] + "...") if len(body) > 120 else body,
                status="failed", error=str(e)[:300],
            ))

    db.commit()
    return results


@app.post("/bulk/send")
def bulk_send(payload: BulkSendRequest, db: Session = Depends(get_db)):
    bulk_conn = db.query(Connection).filter(
        Connection.id == payload.bulk_connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not bulk_conn or bulk_conn.conn_type not in {"google_bulk", "google"}:
        raise HTTPException(status_code=404, detail="Bulk Google connection not found")
    return run_bulk_email_send(
        db, payload.owner_token, bulk_conn, payload.spreadsheet_id, payload.sheet_range,
        payload.email_column, payload.subject_template, payload.body_template,
        payload.condition_column, payload.condition_operator, payload.condition_value,
    )


def run_bulk_document_send(db: Session, owner_token: str, bulk_conn: Connection, spreadsheet_id: str,
                             sheet_range: str, email_column: str, slides_template_id: str,
                             pdf_filename_template: str, subject_template: str, body_template: str,
                             condition_column: Optional[str] = None, condition_operator: Optional[str] = None,
                             condition_value: Optional[str] = None) -> dict:
    """Core logic: for every row, duplicate the Slides template, fill it in, export as PDF,
    email it as an attachment. Used by both the immediate button and scheduled sends."""
    bulk_config = _json.loads(bulk_conn.config)
    try:
        access_token = get_fresh_access_token(bulk_config["refresh_token"])
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    sheet_id = extract_spreadsheet_id(spreadsheet_id)

    resp = _requests.get(
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/{sheet_range}",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Couldn't read the sheet: {resp.text[:200]}")

    values = resp.json().get("values", [])
    if len(values) < 2:
        raise HTTPException(status_code=400, detail="Sheet has no data rows")

    headers = values[0]
    if email_column not in headers:
        raise HTTPException(status_code=400, detail=f"Column '{email_column}' not found. Found columns: {headers}")

    results = {"sent": 0, "failed": 0, "skipped_by_condition": 0, "stopped_early_rate_limit": False, "errors": []}
    sent_today = get_todays_send_count(db, bulk_conn.id)

    for row in values[1:]:
        if sent_today >= GMAIL_DAILY_SAFETY_LIMIT:
            results["stopped_early_rate_limit"] = True
            results["errors"].append(f"Stopped early — approaching Gmail's daily sending limit ({GMAIL_DAILY_SAFETY_LIMIT}/day).")
            break

        row_dict = {headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))}

        if condition_column and not evaluate_condition(row_dict.get(condition_column), condition_operator, condition_value):
            results["skipped_by_condition"] += 1
            continue

        to_addr = row_dict.get(email_column, "").strip()
        if not to_addr:
            results["failed"] += 1
            results["errors"].append("Skipped a row with no email address")
            continue

        subject = subject_template
        body = body_template
        filename = pdf_filename_template
        for col, val in row_dict.items():
            subject = subject.replace("{{" + col + "}}", str(val))
            body = body.replace("{{" + col + "}}", str(val))
            filename = filename.replace("{{" + col + "}}", str(val))

        copy_id = None
        row_access_token = None
        try:
            row_access_token = get_fresh_access_token(bulk_config["refresh_token"])
            slides_id = extract_spreadsheet_id(slides_template_id)
            copy_id = duplicate_slides_template(row_access_token, slides_id, f"temp-{filename}")
            fill_slides_placeholders(row_access_token, copy_id, row_dict)
            pdf_bytes = export_slides_as_pdf(row_access_token, copy_id)
            send_via_gmail_api_with_attachment(bulk_config, subject, body, to_addr, pdf_bytes, filename)

            results["sent"] += 1
            sent_today += 1
            db.add(MessageLog(
                owner_token=owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview=f"[PDF attached: {filename}] " + (body[:100] if len(body) > 100 else body),
                status="sent",
            ))
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"{to_addr}: {str(e)[:150]}")
            db.add(MessageLog(
                owner_token=owner_token, connection_id=bulk_conn.id, connection_name=bulk_conn.name,
                subject=subject, body_preview="[PDF generation failed]",
                status="failed", error=str(e)[:300],
            ))
        finally:
            if copy_id and row_access_token:
                delete_drive_file(row_access_token, copy_id)

    db.commit()
    return results


@app.post("/bulk/generate-and-send")
def bulk_generate_and_send(payload: BulkDocumentSendRequest, db: Session = Depends(get_db)):
    bulk_conn = db.query(Connection).filter(
        Connection.id == payload.bulk_connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not bulk_conn or bulk_conn.conn_type not in {"google_bulk", "google"}:
        raise HTTPException(status_code=404, detail="Bulk Google connection not found")
    return run_bulk_document_send(
        db, payload.owner_token, bulk_conn, payload.spreadsheet_id, payload.sheet_range,
        payload.email_column, payload.slides_template_id, payload.pdf_filename_template,
        payload.subject_template, payload.body_template,
        payload.condition_column, payload.condition_operator, payload.condition_value,
    )


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

    # Schedules require a connection (can't be null) — block deletion rather than silently breaking them
    dependent_schedules = db.query(Schedule).filter(Schedule.connection_id == connection_id).count()
    if dependent_schedules > 0:
        raise HTTPException(
            status_code=400,
            detail=f"This connection is used by {dependent_schedules} schedule(s). Delete or reassign those schedules first, then try again."
        )

    # History logs can safely be unlinked (they already store the connection's name as text)
    db.query(MessageLog).filter(MessageLog.connection_id == connection_id).update({MessageLog.connection_id: None})

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

    msg = MIMEText(body, "html")
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

    msg = MIMEText(body, "html")
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
    msg.attach(_MIMEText(body, "html"))

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


# ---- Support Tickets ----
@app.post("/support-tickets", response_model=SupportTicketOut)
def create_support_ticket(payload: SupportTicketCreate, db: Session = Depends(get_db)):
    ticket = SupportTicket(
        owner_token=payload.owner_token,
        business_name=payload.business_name,
        email=payload.email,
        message=payload.message,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


@app.get("/support-tickets", response_model=list[SupportTicketOut])
def list_my_support_tickets(owner_token: str, db: Session = Depends(get_db)):
    return db.query(SupportTicket).filter(SupportTicket.owner_token == owner_token).order_by(SupportTicket.id.desc()).all()


@app.get("/admin/support-tickets", response_model=list[SupportTicketOut])
def admin_list_support_tickets(key: str, db: Session = Depends(get_db)):
    check_admin(key)
    return db.query(SupportTicket).order_by(SupportTicket.id.desc()).all()


@app.patch("/admin/support-tickets/{ticket_id}/resolve")
def admin_resolve_ticket(ticket_id: int, key: str, db: Session = Depends(get_db)):
    check_admin(key)
    ticket = db.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ticket.status = "resolved"
    db.commit()
    return {"status": "resolved"}


# ---- Razorpay Payments ----
@app.post("/razorpay/create-order", response_model=CreateOrderResponse)
def create_razorpay_order(payload: CreateOrderRequest, db: Session = Depends(get_db)):
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=503, detail="Payments aren't configured on the server yet")

    user = db.query(AppUser).filter(AppUser.user_token == payload.owner_token).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    resp = _requests.post(
        "https://api.razorpay.com/v1/orders",
        auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
        json={
            "amount": SUBSCRIPTION_PRICE_PAISE,
            "currency": "INR",
            "notes": {"owner_token": payload.owner_token, "product": "shreelix-automate-pro"},
        },
        timeout=15,
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Razorpay rejected the order: {resp.text[:200]}")

    order_data = resp.json()
    db.add(Payment(
        owner_token=payload.owner_token,
        razorpay_order_id=order_data["id"],
        amount=SUBSCRIPTION_PRICE_PAISE,
        status="created",
    ))
    db.commit()

    return CreateOrderResponse(
        order_id=order_data["id"], amount=SUBSCRIPTION_PRICE_PAISE, currency="INR", key_id=RAZORPAY_KEY_ID,
    )


@app.post("/razorpay/verify-payment")
def verify_razorpay_payment(payload: VerifyPaymentRequest, db: Session = Depends(get_db)):
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=503, detail="Payments aren't configured on the server yet")

    payment_record = db.query(Payment).filter(Payment.razorpay_order_id == payload.razorpay_order_id).first()
    if not payment_record:
        raise HTTPException(status_code=404, detail="No matching order found")

    # Razorpay's documented signature scheme: HMAC-SHA256(order_id + "|" + payment_id, key_secret)
    expected_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, payload.razorpay_signature):
        payment_record.status = "signature_failed"
        db.commit()
        raise HTTPException(status_code=400, detail="Payment verification failed — signature mismatch")

    payment_record.razorpay_payment_id = payload.razorpay_payment_id
    payment_record.status = "verified"
    payment_record.verified_at = datetime.utcnow()

    user = db.query(AppUser).filter(AppUser.user_token == payload.owner_token).first()
    if not user:
        db.commit()
        raise HTTPException(status_code=404, detail="User not found — payment verified but couldn't upgrade the account, contact support")

    base = user.subscription_expires_at if (user.subscription_expires_at and user.subscription_expires_at > datetime.utcnow()) else datetime.utcnow()
    user.subscription_status = "paid"
    user.subscription_expires_at = base + timedelta(days=30)
    db.commit()

    return {"status": "verified", "subscription_expires_at": user.subscription_expires_at}


@app.get("/dashboard/summary")
def dashboard_summary(owner_token: str, db: Session = Depends(get_db)):
    today_start = now_ist().replace(hour=0, minute=0, second=0, microsecond=0) - IST_OFFSET  # UTC equivalent of "today" in IST

    total_connections = db.query(Connection).filter(Connection.owner_token == owner_token).count()

    all_logs = db.query(MessageLog).filter(MessageLog.owner_token == owner_token)
    total_sent = all_logs.filter(MessageLog.status == "sent").count()
    total_failed = all_logs.filter(MessageLog.status == "failed").count()
    sent_today = all_logs.filter(MessageLog.status == "sent", MessageLog.created_at >= today_start).count()

    all_schedules = db.query(Schedule).filter(Schedule.owner_token == owner_token)
    total_schedules = all_schedules.count()
    active_schedules = all_schedules.filter(Schedule.is_active == "yes").count()
    schedules_retrying = all_schedules.filter(Schedule.retry_count > 0).count()

    all_hooks = db.query(InboundWebhook).filter(InboundWebhook.owner_token == owner_token)
    total_inbound = all_hooks.count()
    active_inbound = all_hooks.filter(InboundWebhook.is_active == "yes").count()
    inbound_fires_total = db.query(InboundWebhook).filter(InboundWebhook.owner_token == owner_token).all()
    total_inbound_triggers_fired = sum(h.trigger_count for h in inbound_fires_total)

    recent_failures = all_logs.filter(MessageLog.status == "failed").order_by(MessageLog.id.desc()).limit(5).all()

    return {
        "total_connections": total_connections,
        "total_sent": total_sent,
        "total_failed": total_failed,
        "sent_today": sent_today,
        "total_schedules": total_schedules,
        "active_schedules": active_schedules,
        "schedules_currently_retrying": schedules_retrying,
        "total_inbound_triggers": total_inbound,
        "active_inbound_triggers": active_inbound,
        "inbound_triggers_fired_total": total_inbound_triggers_fired,
        "recent_failures": [
            {"subject": l.subject, "connection_name": l.connection_name, "error": l.error, "created_at": l.created_at.isoformat()}
            for l in recent_failures
        ],
    }


# ==================== Scheduling ====================
IST_OFFSET = timedelta(hours=5, minutes=30)  # India Standard Time — this product's users are India-based


def now_ist() -> datetime:
    return datetime.utcnow() + IST_OFFSET


@app.post("/schedules", response_model=ScheduleOut)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db)):
    conn = db.query(Connection).filter(
        Connection.id == payload.connection_id, Connection.owner_token == payload.owner_token
    ).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    if payload.frequency not in {"daily", "once"}:
        raise HTTPException(status_code=400, detail="frequency must be 'daily' or 'once'")
    if payload.frequency == "once" and not payload.scheduled_date:
        raise HTTPException(status_code=400, detail="scheduled_date is required for a one-time schedule")
    if payload.mode not in {"single", "bulk_send", "bulk_document"}:
        raise HTTPException(status_code=400, detail="mode must be 'single', 'bulk_send', or 'bulk_document'")

    if payload.mode == "single":
        if conn.conn_type in {"smtp", "gmail_api"} and not payload.to_address:
            raise HTTPException(status_code=400, detail="An email address to send to is required for this connection type")
    else:
        if conn.conn_type not in {"google_bulk", "google"}:
            raise HTTPException(status_code=400, detail="Bulk modes require a Google connection with Sheets/Slides/Drive access — reconnect Google if this one was created before that was available")
        if not payload.spreadsheet_id or not payload.email_column:
            raise HTTPException(status_code=400, detail="Sheet URL and email column are required for bulk schedules")
        if payload.mode == "bulk_document" and not payload.slides_template_id:
            raise HTTPException(status_code=400, detail="A Slides template is required for document-generation schedules")

    db_schedule = Schedule(
        owner_token=payload.owner_token,
        connection_id=payload.connection_id,
        name=payload.name,
        mode=payload.mode,
        to_address=payload.to_address,
        subject=payload.subject,
        body=payload.body,
        frequency=payload.frequency,
        scheduled_time=payload.scheduled_time,
        scheduled_date=payload.scheduled_date,
        spreadsheet_id=payload.spreadsheet_id,
        sheet_range=payload.sheet_range,
        email_column=payload.email_column,
        slides_template_id=payload.slides_template_id,
        pdf_filename_template=payload.pdf_filename_template,
        condition_column=payload.condition_column,
        condition_operator=payload.condition_operator,
        condition_value=payload.condition_value,
    )
    db.add(db_schedule)
    db.commit()
    db.refresh(db_schedule)
    return db_schedule


@app.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(owner_token: str, db: Session = Depends(get_db)):
    return db.query(Schedule).filter(Schedule.owner_token == owner_token).order_by(Schedule.id.desc()).all()


@app.patch("/schedules/{schedule_id}/toggle", response_model=ScheduleOut)
def toggle_schedule(schedule_id: int, payload: ScheduleToggle, db: Session = Depends(get_db)):
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.owner_token == payload.owner_token).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.is_active = "yes" if payload.is_active else "no"
    db.commit()
    db.refresh(schedule)
    return schedule


@app.post("/schedules/{schedule_id}/steps", response_model=WorkflowStepOut)
def add_workflow_step(schedule_id: int, payload: WorkflowStepCreate, db: Session = Depends(get_db)):
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.owner_token == payload.owner_token).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.mode != "single":
        raise HTTPException(status_code=400, detail="Multi-step workflows are only supported for 'single recipient' schedules right now")
    conn = db.query(Connection).filter(Connection.id == payload.connection_id, Connection.owner_token == payload.owner_token).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    if conn.conn_type in {"smtp", "gmail_api", "google"} and not payload.to_address:
        raise HTTPException(status_code=400, detail="An email address to send to is required for this connection type")

    existing_count = db.query(WorkflowStep).filter(WorkflowStep.schedule_id == schedule_id).count()
    db_step = WorkflowStep(
        schedule_id=schedule_id,
        step_order=existing_count + 2,  # step 1 is the schedule's own primary action
        connection_id=payload.connection_id,
        to_address=payload.to_address,
        subject=payload.subject,
        body=payload.body,
    )
    db.add(db_step)
    db.commit()
    db.refresh(db_step)
    return db_step


@app.get("/schedules/{schedule_id}/steps", response_model=list[WorkflowStepOut])
def list_workflow_steps(schedule_id: int, owner_token: str, db: Session = Depends(get_db)):
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.owner_token == owner_token).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return db.query(WorkflowStep).filter(WorkflowStep.schedule_id == schedule_id).order_by(WorkflowStep.step_order).all()


@app.delete("/schedules/{schedule_id}/steps/{step_id}")
def delete_workflow_step(schedule_id: int, step_id: int, owner_token: str, db: Session = Depends(get_db)):
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.owner_token == owner_token).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    step = db.query(WorkflowStep).filter(WorkflowStep.id == step_id, WorkflowStep.schedule_id == schedule_id).first()
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    db.delete(step)
    db.commit()
    return {"status": "deleted"}


@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, owner_token: str, db: Session = Depends(get_db)):
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id, Schedule.owner_token == owner_token).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.query(WorkflowStep).filter(WorkflowStep.schedule_id == schedule_id).delete()
    db.delete(schedule)
    db.commit()
    return {"status": "deleted"}


# ==================== Inbound Webhooks (reverse trigger — external services notify us) ====================
import secrets as _secrets


@app.post("/inbound-webhooks", response_model=InboundWebhookOut)
def create_inbound_webhook(payload: InboundWebhookCreate, db: Session = Depends(get_db)):
    conn = db.query(Connection).filter(Connection.id == payload.connection_id, Connection.owner_token == payload.owner_token).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    if conn.conn_type in {"smtp", "gmail_api", "google", "google_bulk"} and not payload.to_address:
        raise HTTPException(status_code=400, detail="An email address to send to is required for this connection type")

    token = _secrets.token_urlsafe(24)
    db_hook = InboundWebhook(
        owner_token=payload.owner_token,
        token=token,
        name=payload.name,
        connection_id=payload.connection_id,
        to_address=payload.to_address,
        subject_template=payload.subject_template,
        body_template=payload.body_template,
        condition_field=payload.condition_field,
        condition_operator=payload.condition_operator,
        condition_value=payload.condition_value,
    )
    db.add(db_hook)
    db.commit()
    db.refresh(db_hook)
    return db_hook


@app.get("/inbound-webhooks", response_model=list[InboundWebhookOut])
def list_inbound_webhooks(owner_token: str, db: Session = Depends(get_db)):
    return db.query(InboundWebhook).filter(InboundWebhook.owner_token == owner_token).order_by(InboundWebhook.id.desc()).all()


@app.delete("/inbound-webhooks/{hook_id}")
def delete_inbound_webhook(hook_id: int, owner_token: str, db: Session = Depends(get_db)):
    hook = db.query(InboundWebhook).filter(InboundWebhook.id == hook_id, InboundWebhook.owner_token == owner_token).first()
    if not hook:
        raise HTTPException(status_code=404, detail="Inbound webhook not found")
    db.delete(hook)
    db.commit()
    return {"status": "deleted"}


@app.patch("/inbound-webhooks/{hook_id}/toggle")
def toggle_inbound_webhook(hook_id: int, owner_token: str, is_active: bool, db: Session = Depends(get_db)):
    hook = db.query(InboundWebhook).filter(InboundWebhook.id == hook_id, InboundWebhook.owner_token == owner_token).first()
    if not hook:
        raise HTTPException(status_code=404, detail="Inbound webhook not found")
    hook.is_active = "yes" if is_active else "no"
    db.commit()
    return {"status": "updated"}


@app.post("/inbound/{token}")
async def trigger_inbound_webhook(token: str, request: Request, db: Session = Depends(get_db)):
    """The public URL external services POST to. No auth required here by design — the random,
    unguessable token itself is what protects this, same pattern Slack/Stripe/GitHub webhooks use."""
    hook = db.query(InboundWebhook).filter(InboundWebhook.token == token).first()
    if not hook:
        raise HTTPException(status_code=404, detail="Unknown webhook")
    if hook.is_active != "yes":
        raise HTTPException(status_code=403, detail="This webhook is paused")

    try:
        payload_data = await request.json()
        if not isinstance(payload_data, dict):
            payload_data = {}
    except Exception:
        payload_data = {}  # non-JSON body — still let it trigger, just no placeholders to fill

    if hook.condition_field and not evaluate_condition(payload_data.get(hook.condition_field), hook.condition_operator, hook.condition_value):
        return {"status": "skipped", "reason": "condition not met"}

    conn = db.query(Connection).filter(Connection.id == hook.connection_id).first()
    if not conn:
        raise HTTPException(status_code=500, detail="The connection this webhook uses no longer exists")

    subject = hook.subject_template or ""
    body = hook.body_template
    for key, val in payload_data.items():
        subject = subject.replace("{{" + key + "}}", str(val))
        body = body.replace("{{" + key + "}}", str(val))

    try:
        execute_single_send(db, hook.owner_token, conn, subject, body, hook.to_address)
        hook.trigger_count += 1
        hook.last_triggered_at = datetime.utcnow()
        db.commit()
        return {"status": "triggered"}
    except Exception as e:
        db.add(MessageLog(
            owner_token=hook.owner_token, connection_id=conn.id, connection_name=conn.name,
            subject=subject, body_preview="[Inbound webhook trigger failed]",
            status="failed", error=str(e)[:300],
        ))
        db.commit()
        raise HTTPException(status_code=502, detail=f"Trigger action failed: {str(e)[:200]}")


def is_schedule_due(schedule: Schedule, current: datetime) -> bool:
    """Checks if a schedule should fire right now, in IST. Tolerant of the checker running every
    few minutes rather than at the exact minute — 'due' means 'we've passed the target time and
    haven't run yet today' (daily) or 'haven't run at all' (once)."""
    if schedule.is_active != "yes":
        return False

    try:
        target_hour, target_minute = map(int, schedule.scheduled_time.split(":"))
    except (ValueError, AttributeError):
        return False

    current_minutes = current.hour * 60 + current.minute
    target_minutes = target_hour * 60 + target_minute
    past_target_time = current_minutes >= target_minutes

    if schedule.frequency == "once":
        if schedule.last_run_at is not None:
            return False  # already ran once, never again
        if schedule.scheduled_date != current.strftime("%Y-%m-%d"):
            return False  # not the right date yet (or already past — we don't retroactively fire missed schedules)
        return past_target_time

    if schedule.frequency == "daily":
        if not past_target_time:
            return False
        if schedule.last_run_at is not None:
            last_run_ist = schedule.last_run_at + IST_OFFSET
            if last_run_ist.strftime("%Y-%m-%d") == current.strftime("%Y-%m-%d"):
                return False  # already ran today
        return True

    return False


def execute_single_send(db: Session, owner_token: str, conn: Connection, subject: str, body: str, to_address: Optional[str]):
    """Sends one message through one connection and logs the result. Raises on failure (caller decides how to handle it)."""
    config = _json.loads(conn.config)
    if conn.conn_type == "smtp":
        send_via_smtp(config, subject or "", body, to_address)
    elif conn.conn_type in {"gmail_api", "google", "google_bulk"}:
        send_via_gmail_api(config, subject or "", body, to_address)
    elif conn.conn_type == "webhook":
        send_via_webhook(config, subject or "", body)
    elif conn.conn_type == "http":
        send_via_http(config, subject or "", body)
    else:
        raise ValueError(f"Unknown connection type: {conn.conn_type}")

    db.add(MessageLog(
        owner_token=owner_token, connection_id=conn.id, connection_name=conn.name,
        subject=subject, body_preview=(body[:120] + "...") if len(body) > 120 else body,
        status="sent",
    ))


@app.post("/schedules/run-due")
@app.get("/schedules/run-due")
def run_due_schedules(db: Session = Depends(get_db)):
    """The endpoint an external free cron pinger hits every few minutes. Checks every active
    schedule across every user, and runs whichever ones are due right now."""
    current = now_ist()
    all_schedules = db.query(Schedule).filter(Schedule.is_active == "yes").all()
    results = {"checked": len(all_schedules), "ran": 0, "failed": 0, "errors": []}

    for schedule in all_schedules:
        if not is_schedule_due(schedule, current):
            continue

        conn = db.query(Connection).filter(Connection.id == schedule.connection_id).first()
        if not conn:
            continue

        try:
            if schedule.mode == "bulk_send":
                bulk_result = run_bulk_email_send(
                    db, schedule.owner_token, conn, schedule.spreadsheet_id, schedule.sheet_range or "A1:Z1000",
                    schedule.email_column, schedule.subject or "", schedule.body,
                    schedule.condition_column, schedule.condition_operator, schedule.condition_value,
                )
                results["ran"] += 1
                results["errors"].extend(bulk_result.get("errors", []))
            elif schedule.mode == "bulk_document":
                bulk_result = run_bulk_document_send(
                    db, schedule.owner_token, conn, schedule.spreadsheet_id, schedule.sheet_range or "A1:Z1000",
                    schedule.email_column, schedule.slides_template_id, schedule.pdf_filename_template or "Document-{{name}}.pdf",
                    schedule.subject or "", schedule.body,
                    schedule.condition_column, schedule.condition_operator, schedule.condition_value,
                )
                results["ran"] += 1
                results["errors"].extend(bulk_result.get("errors", []))
            else:
                # Step 1: the schedule's own primary action
                execute_single_send(db, schedule.owner_token, conn, schedule.subject, schedule.body, schedule.to_address)
                results["ran"] += 1

                # Steps 2, 3, 4...: additional chained actions, each independent — one failing doesn't stop the rest
                steps = db.query(WorkflowStep).filter(WorkflowStep.schedule_id == schedule.id).order_by(WorkflowStep.step_order).all()
                for step in steps:
                    step_conn = db.query(Connection).filter(Connection.id == step.connection_id).first()
                    if not step_conn:
                        results["errors"].append(f"Schedule '{schedule.name}' step {step.step_order}: connection no longer exists")
                        continue
                    try:
                        execute_single_send(db, schedule.owner_token, step_conn, step.subject, step.body, step.to_address)
                    except Exception as step_error:
                        results["errors"].append(f"Schedule '{schedule.name}' step {step.step_order}: {str(step_error)[:150]}")
                        db.add(MessageLog(
                            owner_token=schedule.owner_token, connection_id=step_conn.id, connection_name=step_conn.name,
                            subject=step.subject, body_preview=f"[Workflow step {step.step_order} failed]",
                            status="failed", error=str(step_error)[:300],
                        ))

            schedule.last_run_at = datetime.utcnow()
            schedule.retry_count = 0  # success — reset the retry counter
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"Schedule '{schedule.name}': {str(e)[:150]}")
            db.add(MessageLog(
                owner_token=schedule.owner_token, connection_id=conn.id, connection_name=conn.name,
                subject=schedule.subject, body_preview="[Scheduled send failed]",
                status="failed", error=str(e)[:300],
            ))
            schedule.retry_count += 1
            if schedule.retry_count >= schedule.max_retries:
                # Given up for now — mark as attempted so it waits for its next natural cycle (tomorrow, etc.)
                schedule.last_run_at = datetime.utcnow()
                schedule.retry_count = 0
                results["errors"].append(f"Schedule '{schedule.name}': gave up after {schedule.max_retries} retries")
            # else: leave last_run_at untouched — it'll be picked up and retried on the next run-due check

    db.commit()
    return results
