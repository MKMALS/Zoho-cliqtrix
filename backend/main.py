import os
import uuid
import hashlib
import hmac
import secrets
import shutil
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import httpx
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Optional: Twilio for OTP SMS
try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

load_dotenv()

# Config from env
WORKABLE_SUBDOMAIN = os.getenv("WORKABLE_SUBDOMAIN")  # e.g. "yourcompany"
WORKABLE_API_KEY = os.getenv("WORKABLE_API_KEY")      # API key string
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

# Database (SQLite)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Twilio client (optional)
twilio_client = None
if TwilioClient and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

app = FastAPI(title="HR Middleware (Workable)")

# Models
class OTPModel(Base):
    __tablename__ = "otp_sessions"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, index=True)
    otp_hash = Column(String)
    salt = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    verified = Column(Boolean, default=False)

class ApplicationModel(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    job_shortcode = Column(String, index=True)
    candidate_name = Column(String)
    candidate_email = Column(String, index=True)
    candidate_phone = Column(String)
    resume_path = Column(String)
    workable_candidate_id = Column(String, nullable=True)
    workable_application_id = Column(String, nullable=True)
    status = Column(String, default="submitted")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Pydantic schemas
class SendOTPRequest(BaseModel):
    phone: str

class VerifyOTPRequest(BaseModel):
    phone: str
    otp: str

class ApplyRequest(BaseModel):
    job_shortcode: str
    name: str
    email: EmailStr
    phone: str
    expected_salary: str = None
    notice_period: str = None
    resume_url: str = None  # optional if file uploaded

# Utils
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_otp(otp: str, salt: str):
    return hmac.new(salt.encode(), otp.encode(), hashlib.sha256).hexdigest()

def generate_otp():
    return f"{secrets.randbelow(900000)+100000}"  # 6 digits

# Workable helper
def workable_headers():
    if not WORKABLE_API_KEY or not WORKABLE_SUBDOMAIN:
        raise RuntimeError("WORKABLE_API_KEY and WORKABLE_SUBDOMAIN must be set in env")
    return {
        "Authorization": f"Bearer {WORKABLE_API_KEY}",
        "Accept": "application/json",
    }

# Endpoints

@app.get("/jobs")
async def get_jobs(page: int = 1, limit: int = 20):
    """
    Fetch open jobs from Workable and return normalized list.
    """
    url = f"https://www.workable.com/spi/v3/accounts/{WORKABLE_SUBDOMAIN}/jobs"
    params = {"page": page, "limit": limit}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=workable_headers(), params=params)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch jobs from Workable")
    data = resp.json()
    # Normalize basic fields for SalesIQ carousel
    items = []
    for job in data.get("jobs", []):
        items.append({
            "shortcode": job.get("shortcode"),
            "title": job.get("title"),
            "location": job.get("location"),
            "department": job.get("department"),
            "remote": job.get("remote"),
            "description": job.get("description")[:250] if job.get("description") else "",
            "posted_date": job.get("published_at")
        })
    return {"jobs": items, "meta": data.get("meta", {})}

@app.get("/jobs/{shortcode}")
async def get_job_detail(shortcode: str):
    """
    Fetch single job details from Workable
    """
    url = f"https://www.workable.com/spi/v3/accounts/{WORKABLE_SUBDOMAIN}/jobs/{shortcode}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=workable_headers())
    if resp.status_code != 200:
        raise HTTPException(status_code=404, detail="Job not found in Workable")
    data = resp.json()
    # return as-is (Workable's job object)
    return data

@app.post("/send-otp")
async def send_otp(payload: SendOTPRequest, db=Depends(get_db)):
    """
    Generate OTP, store hashed in DB and send via Twilio (or log)
    """
    phone = payload.phone.strip()
    otp = generate_otp()
    salt = secrets.token_hex(16)
    otp_hash = hash_otp(otp, salt)
    now = datetime.utcnow()
    expires = now + timedelta(minutes=OTP_EXPIRY_MINUTES)

    # store session (replace existing for same phone)
    # simple approach: delete previous entries for same phone
    db.query(OTPModel).filter(OTPModel.phone == phone).delete()
    db.add(OTPModel(phone=phone, otp_hash=otp_hash, salt=salt, created_at=now, expires_at=expires, verified=False))
    db.commit()

    # send SMS via Twilio if configured
    if twilio_client and TWILIO_FROM:
        try:
            twilio_client.messages.create(
                body=f"Your verification code is {otp}",
                from_=TWILIO_FROM,
                to=phone
            )
        except Exception as e:
            # fallback to logging
            print("Twilio send error:", e)
            print(f"OTP for {phone}: {otp}")
    else:
        # For testing: print OTP to server logs
        print(f"[DEV] OTP for {phone}: {otp}")

    return {"success": True, "message": "OTP sent (if Twilio configured)."}

@app.post("/verify-otp")
async def verify_otp(payload: VerifyOTPRequest, db=Depends(get_db)):
    phone = payload.phone.strip()
    otp = payload.otp.strip()
    record = db.query(OTPModel).filter(OTPModel.phone == phone).order_by(OTPModel.created_at.desc()).first()
    if not record:
        raise HTTPException(status_code=404, detail="No OTP session found for this phone")
    if record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP expired")
    calc_hash = hash_otp(otp, record.salt)
    if not hmac.compare_digest(calc_hash, record.otp_hash):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    record.verified = True
    db.add(record)
    db.commit()
    return {"success": True, "message": "Phone verified"}

@app.post("/apply")
async def apply(
    job_shortcode: str = Form(...),
    name: str = Form(...),
    email: EmailStr = Form(...),
    phone: str = Form(...),
    expected_salary: str = Form(None),
    notice_period: str = Form(None),
    otp_phone: str = Form(...),
    otp_code: str = Form(...),
    resume: UploadFile = File(None),
    resume_url: str = Form(None),
    db=Depends(get_db)
):
    # Verify OTP
    record = db.query(OTPModel).filter(OTPModel.phone == otp_phone.strip()).order_by(OTPModel.created_at.desc()).first()
    if not record or not record.verified:
        # If not yet verified, attempt to verify with provided otp_code
        if not record:
            raise HTTPException(status_code=400, detail="OTP session not found")
        if record.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="OTP expired")
        calc_hash = hash_otp(otp_code.strip(), record.salt)
        if not hmac.compare_digest(calc_hash, record.otp_hash):
            raise HTTPException(status_code=400, detail="Invalid OTP")
        record.verified = True
        db.add(record)
        db.commit()

    # Save resume if uploaded
    resume_path = None
    if resume:
        filename = f"{uuid.uuid4().hex}_{resume.filename}"
        safe_path = os.path.join(UPLOAD_DIR, filename)
        # Basic check: limit size to 10MB
        contents = await resume.read()
        if len(contents) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Resume too large (max 10MB)")
        with open(safe_path, "wb") as f:
            f.write(contents)
        resume_path = safe_path
    elif resume_url:
        resume_path = resume_url  # external link

    # Create application record locally
    app_rec = ApplicationModel(
        job_shortcode=job_shortcode,
        candidate_name=name,
        candidate_email=str(email),
        candidate_phone=phone,
        resume_path=resume_path,
        status="submitted",
    )
    db.add(app_rec)
    db.commit()
    db.refresh(app_rec)

    # Submit to Workable
    # Workable apply endpoint expects multipart form (candidate data + resume file)
    # If we saved resume locally, we will re-open file and POST as multipart
    workable_url = f"https://www.workable.com/spi/v3/accounts/{WORKABLE_SUBDOMAIN}/jobs/{job_shortcode}/candidates"
    headers = workable_headers()
    # Prepare multipart request using requests (sync) because httpx multipart with file upload is bit more verbose.
    import requests
    multipart = {
        "first_name": (None, name.split(" ")[0] if " " in name else name),
        "last_name": (None, name.split(" ", 1)[1] if " " in name else ""),
        "email": (None, str(email)),
        "phone": (None, phone),
        "source": (None, "SalesIQ-Bot"),
    }
    # optional fields
    if expected_salary:
        multipart["expected_salary"] = (None, expected_salary)
    if notice_period:
        multipart["notice_period"] = (None, notice_period)

    files = None
    file_handle = None
    if resume and resume_path and os.path.exists(resume_path):
        file_handle = open(resume_path, "rb")
        files = {"resume": (os.path.basename(resume_path), file_handle, "application/octet-stream")}

    resp = requests.post(workable_url, headers=headers, files=files, data={k: v[1] for k, v in multipart.items()})
    if file_handle:
        file_handle.close()

    if resp.status_code not in (200, 201, 202):
        # Save failure status
        app_rec.status = "failed_to_submit"
        db.add(app_rec)
        db.commit()
        raise HTTPException(status_code=502, detail=f"Workable API error: {resp.status_code} {resp.text}")

    # Workable returns the created candidate object
    resp_json = resp.json()
    # For Workable, response may include candidate id in different fields; store raw JSON as string (simple)
    try:
        # try getting candidate id
        candidate_id = resp_json.get("candidate", {}).get("id") or resp_json.get("id")
    except Exception:
        candidate_id = None

    app_rec.workable_candidate_id = candidate_id
    app_rec.workable_application_id = candidate_id
    app_rec.status = "applied"
    db.add(app_rec)
    db.commit()

    return {"success": True, "applicationId": app_rec.id, "workable_response": resp_json}

@app.get("/myjobs")
async def my_jobs(email: EmailStr, db=Depends(get_db)):
    """
    Fetch applications by email from local DB. Optionally you can fetch live from Workable by email search,
    but Workable may require different endpoints; keeping local DB is faster for 'My Jobs'
    """
    items = db.query(ApplicationModel).filter(ApplicationModel.candidate_email == str(email)).order_by(ApplicationModel.created_at.desc()).all()
    out = []
    for it in items:
        out.append({
            "id": it.id,
            "job_shortcode": it.job_shortcode,
            "name": it.candidate_name,
            "email": it.candidate_email,
            "phone": it.candidate_phone,
            "resume": it.resume_path,
            "status": it.status,
            "created_at": it.created_at.isoformat()
        })
    return {"applications": out}
