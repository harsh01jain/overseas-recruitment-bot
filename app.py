from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from contextlib import contextmanager
from psycopg2.pool import SimpleConnectionPool
from datetime import datetime, timedelta
from jose import jwt, JWTError
import requests
import os
import logging
import smtplib
import bcrypt
import hmac
import hashlib
import html
import re
import time
import json
import threading
from collections import defaultdict
from threading import Lock
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# ====================================
# APP SETUP (SINGLE INSTANCE)
# ====================================

app = FastAPI()

from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )
        if request.url.path.startswith(
            ("/dashboard", "/candidates", "/users", "/settings")
        ):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate"
            )
            response.headers["Pragma"] = "no-cache"
        return response


app.add_middleware(SecurityHeadersMiddleware)

templates = Jinja2Templates(directory="templates")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ====================================
# ENVIRONMENT VARIABLES
# ====================================

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
WHATSAPP_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET")

HR_PHONE = os.getenv("HR_PHONE")
HR_EMAIL = os.getenv("HR_EMAIL")

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

OFFICE_ADDRESS = os.getenv("OFFICE_ADDRESS", "Riyadh Office")
CONTACT_NUMBER = os.getenv("CONTACT_NUMBER", "+966 XX XXX XXXX")

# ====================================
# STARTUP SECURITY CHECK
# ====================================

REQUIRED_ENV_VARS = [
    "VERIFY_TOKEN", "WHATSAPP_TOKEN", "PHONE_NUMBER_ID",
    "WHATSAPP_APP_SECRET", "SECRET_KEY", "DB_PASSWORD"
]

missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
if missing:
    raise RuntimeError(
        f"SECURITY ERROR: Missing required environment "
        f"variables: {missing}\n"
        f"Set these in your .env file before starting."
    )

if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECURITY ERROR: SECRET_KEY must be at least 32 "
        "characters long.\n"
        "Generate one with: python -c "
        "\"import secrets; print(secrets.token_hex(32))\""
    )

logging.info("✅ Security environment check passed.")

# ====================================
# DATABASE
# ====================================

import urllib.parse

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    result = urllib.parse.urlparse(DATABASE_URL)
    db_pool = SimpleConnectionPool(
        1, 10,
        host=result.hostname,
        port=result.port,
        database=result.path[1:],
        user=result.username,
        password=result.password
    )
else:
    db_pool = SimpleConnectionPool(
        1, 10,
        host="localhost",
        database="overseas_bot3",
        user="postgres",
        password=os.getenv("DB_PASSWORD")
    )


@contextmanager
def get_cursor():
    conn = db_pool.getconn()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"DB error: {e}")
        raise
    finally:
        cursor.close()
        db_pool.putconn(conn)


# ====================================
# SECURITY: INPUT SANITIZATION
# ====================================

MAX_LENGTHS = {
    "name": 100,
    "profession": 150,
    "nationality": 100,
    "city": 100,
    "documents": 500,
    "note": 1000,
    "generic": 200,
}


def sanitize_text(text: str, field: str = "generic") -> str:
    if not text:
        return ""
    text = html.escape(text.strip())
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    max_len = MAX_LENGTHS.get(field, MAX_LENGTHS["generic"])
    text = text[:max_len]
    return text.strip()


def is_valid_phone(phone: str) -> bool:
    digits = re.sub(r'\D', '', phone)
    return 7 <= len(digits) <= 15


def mask_phone(phone: str) -> str:
    if len(phone) <= 6:
        return "***"
    return phone[:3] + "***" + phone[-4:]


# ====================================
# SECURITY: WEBHOOK SIGNATURE VERIFICATION
# ====================================

def verify_webhook_signature(
    payload_body: bytes, signature_header: str
) -> bool:
    if not signature_header:
        logging.warning(
            "⚠️ Webhook received without signature header"
        )
        return False

    if not signature_header.startswith("sha256="):
        logging.warning("⚠️ Invalid signature format")
        return False

    expected_signature = signature_header[7:]

    computed = hmac.new(
        WHATSAPP_APP_SECRET.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    is_valid = hmac.compare_digest(computed, expected_signature)

    if not is_valid:
        logging.warning(
            "🚨 SECURITY: Webhook signature mismatch — "
            "possible spoofing attempt"
        )

    return is_valid


# ====================================
# SECURITY: RATE LIMITING
# ====================================

class RateLimiter:
    def __init__(self):
        self._lock = Lock()
        self._counts = defaultdict(list)

    def is_allowed(
        self, phone: str,
        max_requests: int = 20,
        window_seconds: int = 60
    ) -> bool:
        now = time.time()
        with self._lock:
            self._counts[phone] = [
                t for t in self._counts[phone]
                if now - t < window_seconds
            ]
            if len(self._counts[phone]) >= max_requests:
                return False
            self._counts[phone].append(now)
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            inactive = [
                phone for phone, times in self._counts.items()
                if not times or now - max(times) > 300
            ]
            for phone in inactive:
                del self._counts[phone]


rate_limiter = RateLimiter()


# ====================================
# SETTINGS LOADER (CACHED)
# ====================================

class SettingsCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._settings = {}
        self._loaded = False

    def load(self):
        with self._lock:
            try:
                with get_cursor() as cursor:
                    cursor.execute(
                        "SELECT setting_key, setting_value "
                        "FROM bot_settings"
                    )
                    rows = cursor.fetchall()
                self._settings = {
                    row[0]: row[1] for row in rows
                }
                self._loaded = True
                logging.info(
                    f"✅ Settings loaded: "
                    f"{len(self._settings)} entries"
                )
            except Exception as e:
                logging.error(f"Failed to load settings: {e}")
                if not self._settings:
                    self._settings = {}

    def get(self, key: str, default: str = "") -> str:
        if not self._loaded:
            self.load()
        return self._settings.get(key, default)

    def get_bool(
        self, key: str, default: bool = True
    ) -> bool:
        val = self.get(key, str(default)).lower()
        return val in ("true", "1", "yes", "on")

    def reload(self):
        self.load()

    def all_settings(self) -> dict:
        if not self._loaded:
            self.load()
        return dict(self._settings)


bot_settings = SettingsCache()
bot_settings.load()


# ====================================
# DYNAMIC MESSAGE BUILDERS
# ====================================

def build_menu_text() -> str:
    s = bot_settings
    greeting = s.get(
        "welcome_greeting",
        "Welcome to Overseas Recruitment!"
    )
    subtitle = s.get(
        "welcome_subtitle",
        "We help you find great jobs abroad 🌍"
    )
    opt1 = s.get("menu_option_1", "View available jobs")
    opt2 = s.get("menu_option_2", "Start application")
    opt3 = s.get("menu_option_3", "Recruitment process")
    opt4 = s.get("menu_option_4", "Check application")
    opt5 = s.get("menu_option_5", "Talk to someone")

    return (
        f"👋 *{greeting}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"{subtitle}\n\n"
        f"Choose an option:\n\n"
        f"📌 Type *1* or *jobs* → {opt1}\n"
        f"📌 Type *2* or *apply* → {opt2}\n"
        f"📌 Type *3* or *process* → {opt3}\n"
        f"📌 Type *4* or *status* → {opt4}\n"
        f"📌 Type *5* or *contact* → {opt5}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"💡 To apply, first type *jobs*\n"
        f"then type *apply 1* (with the job number)"
    )


def build_process_text() -> str:
    s = bot_settings
    steps = []
    emojis = [
        "1️⃣", "2️⃣", "3️⃣", "4️⃣",
        "5️⃣", "6️⃣", "7️⃣", "8️⃣"
    ]
    for i in range(1, 9):
        step_text = s.get(f"process_step_{i}", "")
        if step_text:
            steps.append(
                f"{emojis[i-1]} *Step {i}*\n   {step_text}"
            )

    disclaimer = s.get(
        "process_disclaimer",
        "This process requires time, commitment, and "
        "financial readiness from the candidate."
    )
    steps_block = "\n\n".join(steps)

    return (
        f"📋 *Recruitment Process*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Here's how the process works:\n\n"
        f"{steps_block}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ *Important:*\n"
        f"{disclaimer}\n\n"
        f"Type *apply 1* to start your application\n"
        f"Type *hi* for main menu"
    )


def build_contact_text() -> str:
    s = bot_settings
    phone = s.get("contact_phone", CONTACT_NUMBER)
    email = s.get(
        "contact_email", "info@overseasrecruitment.com"
    )
    days = s.get("working_days", "Sunday – Thursday")
    hours = s.get("working_hours", "11:00 AM – 5:00 PM")

    return (
        f"📞 *Contact Us / Other Queries*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"If you have questions or need help:\n\n"
        f"📞 *Call/WhatsApp:* {phone}\n"
        f"📧 *Email:* {email}\n\n"
        f"🕐 *Working Hours:*\n"
        f"{days}\n"
        f"{hours}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Our team will be happy to assist!\n\n"
        f"Type *hi* for main menu."
    )


def build_cost_text() -> str:
    s = bot_settings
    phone = s.get("contact_phone", CONTACT_NUMBER)
    cost_info = s.get(
        "cost_info_text",
        "Exact costs depend on country & job type. "
        "Contact us for details."
    )

    return (
        f"💰 *Cost Information*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Typical costs include:\n\n"
        f"📄 *Visa Processing Fee*\n"
        f"   Government charges for visa\n\n"
        f"🏢 *Service Fee*\n"
        f"   Recruitment service charges\n\n"
        f"✈️ *Travel & Accommodation*\n"
        f"   Flight tickets and initial stay\n\n"
        f"📋 *Document Processing*\n"
        f"   Translation & attestation\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"💡 *{cost_info}*\n\n"
        f"📞 Contact us: {phone}\n\n"
        f"Type *hi* for menu."
    )


def build_not_ready_text() -> str:
    s = bot_settings
    msg = s.get(
        "not_ready_message",
        "No problem! Thank you for your interest. "
        "Come back when you're ready."
    )
    phone = s.get("contact_phone", CONTACT_NUMBER)

    return (
        f"👍 *{msg}*\n\n"
        f"📞 Questions: {phone}\n\n"
        f"Type *hi* for main menu."
    )


def build_already_applied_text(
    job_position: str, job_country: str
) -> str:
    s = bot_settings
    msg = s.get(
        "already_applied_message",
        "You already applied for this job!"
    )

    return (
        f"⚠️ *{msg}*\n\n"
        f"Job: {job_position} in {job_country}\n\n"
        f"Type *status* to check your application.\n"
        f"Type *jobs* to see other openings."
    )


def get_work_preferences() -> dict:
    s = bot_settings
    pref_map = {}

    # For each option, use value if set,
    # otherwise strip emojis from option text
    for i in range(1, 4):
        option_text = s.get(
            f"work_pref_option_{i}", ""
        )
        value_text = s.get(
            f"work_pref_value_{i}", ""
        )

        # If value is empty, derive from option
        # by removing emoji characters
        if not value_text and option_text:
            import re as _re
            value_text = _re.sub(
                r'[^\w\s/\-]', '', option_text
            ).strip()

        if not value_text:
            continue

        # Map number key
        pref_map[str(i)] = value_text

        # Map keyword variations
        for keyword in (
            value_text.lower()
            .replace("/", " ")
            .split()
        ):
            if len(keyword) > 1:
                pref_map[keyword] = value_text

    # Extra aliases for "any" option
    val3 = pref_map.get("3", "Any Available")
    pref_map["anything"] = val3
    pref_map["all"] = val3

    return pref_map


# ====================================
# SECURITY: LOGIN BRUTE FORCE PROTECTION
# ====================================

class LoginProtection:
    def __init__(self):
        self._lock = Lock()
        self._attempts = defaultdict(list)
        self._locked = defaultdict(float)

    MAX_ATTEMPTS = 5
    WINDOW_SECONDS = 300
    LOCKOUT_SECONDS = 900

    def is_locked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._locked:
                if time.time() < self._locked[ip]:
                    return True
                else:
                    del self._locked[ip]
                    self._attempts[ip] = []
            return False

    def record_failure(self, ip: str):
        now = time.time()
        with self._lock:
            self._attempts[ip] = [
                t for t in self._attempts[ip]
                if now - t < self.WINDOW_SECONDS
            ]
            self._attempts[ip].append(now)
            if len(self._attempts[ip]) >= self.MAX_ATTEMPTS:
                self._locked[ip] = now + self.LOCKOUT_SECONDS
                logging.warning(
                    f"🚨 SECURITY: IP {ip} locked out after "
                    f"{self.MAX_ATTEMPTS} failed login attempts"
                )

    def record_success(self, ip: str):
        with self._lock:
            self._attempts.pop(ip, None)
            self._locked.pop(ip, None)

    def remaining_attempts(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            recent = [
                t for t in self._attempts.get(ip, [])
                if now - t < self.WINDOW_SECONDS
            ]
            return max(0, self.MAX_ATTEMPTS - len(recent))


login_protection = LoginProtection()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ====================================
# SECURITY: STEP VALIDATION WHITELIST
# ====================================

VALID_STEPS = {
    "ask_name", "ask_profession", "ask_nationality",
    "ask_city", "ask_work_preference", "ask_experience",
    "ask_documents", "ask_process_ready", "ask_next_step",
    "ask_office_day", "ask_office_time",
    "ask_call_day", "ask_call_time",
    "confirm_whatsapp"
}


# ====================================
# AUTH HELPERS
# ====================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"), hashed.encode("utf-8")
    )


def create_token(
    user_id: int, username: str, role: str
) -> str:
    expire = datetime.utcnow() + timedelta(
        hours=TOKEN_EXPIRE_HOURS
    )
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM]
        )
        if not all(
            k in payload
            for k in ["user_id", "username", "role"]
        ):
            return None
        return payload
    except JWTError:
        return None


# ====================================
# FLAGS
# ====================================

FLAGS = {
    "germany": "🇩🇪", "poland": "🇵🇱", "czech": "🇨🇿",
    "netherlands": "🇳🇱", "uk": "🇬🇧", "canada": "🇨🇦",
    "australia": "🇦🇺", "dubai": "🇦🇪", "uae": "🇦🇪",
    "saudi": "🇸🇦", "qatar": "🇶🇦", "usa": "🇺🇸",
    "india": "🇮🇳", "italy": "🇮🇹", "spain": "🇪🇸",
    "france": "🇫🇷", "japan": "🇯🇵", "korea": "🇰🇷"
}


def get_flag(country: str) -> str:
    if not country:
        return "🏳️"
    for key, flag in FLAGS.items():
        if key in country.lower():
            return flag
    return "🏳️"


# ====================================
# STATE MANAGEMENT
# ====================================

def get_state(phone: str):
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT step, job_id, job_name, full_name, "
            "current_profession, nationality, current_city, "
            "work_preference, years_experience, "
            "documents_available, "
            "process_ready, next_step, preferred_day, "
            "preferred_time "
            "FROM conversation_state WHERE phone = %s",
            (phone,)
        )
        row = cursor.fetchone()

    if not row:
        return None

    step = row[0]

    if step and step not in VALID_STEPS:
        logging.warning(
            f"🚨 SECURITY: Invalid step '{step}' for "
            f"{mask_phone(phone)} — clearing state"
        )
        clear_state(phone)
        return None

    return {
        "step": step,
        "job_id": row[1],
        "job_name": row[2],
        "full_name": row[3],
        "current_profession": row[4],
        "nationality": row[5],
        "current_city": row[6],
        "work_preference": row[7],
        "years_experience": row[8],
        "documents_available": row[9],
        "process_ready": row[10],
        "next_step": row[11],
        "preferred_day": row[12],
        "preferred_time": row[13],
    }


def set_state(phone: str, data: dict):
    step = data.get("step")
    if step and step not in VALID_STEPS:
        logging.error(
            f"🚨 SECURITY: Attempted to set invalid "
            f"step '{step}' — blocked"
        )
        return

    with get_cursor() as cursor:
        cursor.execute("""
            INSERT INTO conversation_state
                (phone, step, job_id, job_name, full_name,
                 current_profession, nationality,
                 current_city, work_preference,
                 years_experience, documents_available,
                 process_ready, next_step, preferred_day,
                 preferred_time, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    CURRENT_TIMESTAMP)
            ON CONFLICT (phone) DO UPDATE SET
                step                = EXCLUDED.step,
                job_id              = EXCLUDED.job_id,
                job_name            = EXCLUDED.job_name,
                full_name           = EXCLUDED.full_name,
                current_profession  = EXCLUDED.current_profession,
                nationality         = EXCLUDED.nationality,
                current_city        = EXCLUDED.current_city,
                work_preference     = EXCLUDED.work_preference,
                years_experience    = EXCLUDED.years_experience,
                documents_available = EXCLUDED.documents_available,
                process_ready       = EXCLUDED.process_ready,
                next_step           = EXCLUDED.next_step,
                preferred_day       = EXCLUDED.preferred_day,
                preferred_time      = EXCLUDED.preferred_time,
                updated_at          = CURRENT_TIMESTAMP
        """, (
            phone,
            data.get("step"),
            data.get("job_id"),
            data.get("job_name"),
            data.get("full_name"),
            data.get("current_profession"),
            data.get("nationality"),
            data.get("current_city"),
            data.get("work_preference"),
            data.get("years_experience"),
            data.get("documents_available"),
            data.get("process_ready"),
            data.get("next_step"),
            data.get("preferred_day"),
            data.get("preferred_time"),
        ))


def clear_state(phone: str):
    with get_cursor() as cursor:
        cursor.execute(
            "DELETE FROM conversation_state WHERE phone = %s",
            (phone,)
        )


# ====================================
# SEND MESSAGE
# ====================================

def send_text(to: str, message: str) -> bool:
    url = (
        f"https://graph.facebook.com/v19.0/"
        f"{PHONE_NUMBER_ID}/messages"
    )
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }
    try:
        response = requests.post(
            url, headers=headers, json=payload, timeout=10
        )
        result = response.json()
        if "error" in result:
            logging.error(
                f"WhatsApp API error for {mask_phone(to)}: "
                f"{result['error'].get('message')}"
            )
            return False
        logging.info(f"✅ Sent to {mask_phone(to)}")
        return True
    except Exception as e:
        logging.error(
            f"Send failed to {mask_phone(to)}: {e}"
        )
        return False


# ====================================
# HR NOTIFICATIONS
# ====================================

def notify_hr_whatsapp(data: dict):
    if not HR_PHONE:
        return

    job_name = data.get("job_name", "N/A")
    msg = (
        "🆕 *New Candidate Application!*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 Name:        {data.get('full_name', 'N/A')}\n"
        f"📞 Phone:       +{data.get('phone', 'N/A')}\n"
        f"💼 Applied For: {job_name}\n"
        f"👷 Profession:  "
        f"{data.get('current_profession', 'N/A')}\n"
        f"🌍 Nationality: "
        f"{data.get('nationality', 'N/A')}\n"
        f"📍 City:        "
        f"{data.get('current_city', 'N/A')}\n"
        f"🎯 Preference:  "
        f"{data.get('work_preference', 'N/A')}\n"
        f"📅 Experience:  "
        f"{data.get('years_experience', 'N/A')}\n"
        f"📄 Documents:   "
        f"{data.get('documents_available', 'N/A')}\n"
        f"📋 Next Step:   "
        f"{data.get('next_step', 'N/A')}\n"
    )
    if data.get("next_step") == "call_back":
        msg += (
            f"📅 Call Day:   "
            f"{data.get('preferred_day', 'N/A')}\n"
            f"⏰ Call Time:  "
            f"{data.get('preferred_time', 'N/A')}\n"
        )
    elif data.get("next_step") == "office_visit":
        msg += (
            f"📅 Visit Day:  "
            f"{data.get('preferred_day', 'N/A')}\n"
            f"⏰ Visit Time: "
            f"{data.get('preferred_time', 'N/A')}\n"
        )
    msg += "\nCheck dashboard for full details."
    try:
        send_text(HR_PHONE, msg)
    except Exception as e:
        logging.error(f"HR WhatsApp failed: {e}")


def notify_hr_email(data: dict):
    if not HR_EMAIL or not SMTP_EMAIL or not SMTP_PASSWORD:
        return
    job_name = data.get("job_name", "N/A")
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_EMAIL
        msg["To"] = HR_EMAIL
        msg["Subject"] = (
            f"New Application: "
            f"{data.get('full_name', 'Unknown')} - "
            f"{data.get('current_profession', 'Unknown')} - "
            f"{data.get('nationality', 'Unknown')}"
        )
        body = (
            f"New Candidate Application\n"
            f"========================\n\n"
            f"Name:        {data.get('full_name', 'N/A')}\n"
            f"Phone:       +{data.get('phone', 'N/A')}\n"
            f"Applied For: {job_name}\n"
            f"Profession:  "
            f"{data.get('current_profession', 'N/A')}\n"
            f"Nationality: "
            f"{data.get('nationality', 'N/A')}\n"
            f"City:        "
            f"{data.get('current_city', 'N/A')}\n"
            f"Work Pref:   "
            f"{data.get('work_preference', 'N/A')}\n"
            f"Experience:  "
            f"{data.get('years_experience', 'N/A')}\n"
            f"Documents:   "
            f"{data.get('documents_available', 'N/A')}\n"
            f"Next Step:   "
            f"{data.get('next_step', 'N/A')}\n"
        )
        if data.get("next_step") == "call_back":
            body += (
                f"Call Day:    "
                f"{data.get('preferred_day', 'N/A')}\n"
                f"Call Time:   "
                f"{data.get('preferred_time', 'N/A')}\n"
            )
        elif data.get("next_step") == "office_visit":
            body += (
                f"Visit Day:   "
                f"{data.get('preferred_day', 'N/A')}\n"
                f"Visit Time:  "
                f"{data.get('preferred_time', 'N/A')}\n"
            )
        body += "\nCheck dashboard for full details."
        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, HR_EMAIL, msg.as_string())
        server.quit()
        logging.info("HR email sent")
    except Exception as e:
        logging.error(f"HR email failed: {e}")


# ====================================
# GET JOBS TEXT
# ====================================

def get_jobs_text() -> str:
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, "
            "requirements "
            "FROM jobs "
            "WHERE is_active = TRUE "
            "AND (is_deleted = FALSE OR is_deleted IS NULL) "
            "ORDER BY id"
        )
        rows = cursor.fetchall()

    if not rows:
        return (
            "😕 *No jobs available right now.*\n\n"
            "All positions are currently closed.\n"
            "Please check back later!\n\n"
            "Type *hi* for menu."
        )

    message = "🌍 *Available Job Offers*\n"
    message += "━━━━━━━━━━━━━━━━━━━━━\n\n"
    for r in rows:
        flag = get_flag(r[1])
        message += (
            f"*Job #{r[0]}*\n"
            f"{flag} Country: {r[1]}\n"
            f"💼 Position: {r[2]}\n"
            f"💰 Salary: {r[3]}\n"
        )
        if r[4]:
            message += f"📋 Requirements: {r[4]}\n"
        message += "─────────────────\n\n"

    message += (
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "✅ *How to apply:*\n\n"
        "Type *apply* followed by the job number.\n\n"
        "Examples:\n"
        "👉 *apply 1* → Apply for Job #1\n"
        "👉 *apply 3* → Apply for Job #3\n\n"
        "⚠️ Only active positions are shown above.\n\n"
        "Type *hi* for main menu."
    )
    return message


# ====================================
# CHECK STATUS
# ====================================

def check_status(phone: str) -> str:
    with get_cursor() as cursor:
        cursor.execute("""
            SELECT
                c.full_name,
                c.current_profession,
                c.nationality,
                c.work_preference,
                c.years_experience,
                c.status,
                c.next_step,
                c.preferred_time,
                c.preferred_day,
                c.created_at,
                c.job_id,
                j.position,
                j.country,
                j.is_active,
                j.is_deleted
            FROM candidates c
            LEFT JOIN jobs j ON c.job_id = j.id
            WHERE c.phone = %s
            ORDER BY c.created_at DESC
        """, (phone,))
        rows = cursor.fetchall()

    if not rows:
        return (
            "📭 *No applications found.*\n\n"
            "You haven't applied yet.\n\n"
            "Type *jobs* to see available openings\n"
            "then type *apply 1* to start."
        )

    message = "📋 *Your Applications*\n"
    message += "━━━━━━━━━━━━━━━━━━━━━\n\n"

    for i, r in enumerate(rows, 1):
        full_name = r[0]
        profession = r[1]
        nationality = r[2]
        work_pref = r[3]
        experience = r[4]
        status = r[5]
        next_step = r[6]
        pref_time = r[7]
        pref_day = r[8]
        created_at = r[9]
        job_id = r[10]
        job_position = r[11]
        job_country = r[12]
        job_is_active = r[13]
        job_is_deleted = r[14]

        date = (
            created_at.strftime("%d %b %Y")
            if created_at else "N/A"
        )

        if job_id and job_is_deleted:
            job_display = "⛔ *Position Removed*"
            job_status_line = (
                "🚫 This position has been removed.\n"
            )
        elif job_id and job_position is None:
            job_display = "⛔ *Position Removed*"
            job_status_line = (
                "🚫 This position has been removed.\n"
            )
        elif job_position and job_is_active is False:
            flag = get_flag(job_country or "")
            job_display = (
                f"{flag} {job_position} – {job_country}"
            )
            job_status_line = (
                "⏸️ This position is currently "
                "*closed/expired*.\n"
            )
        elif job_position and job_is_active:
            flag = get_flag(job_country or "")
            job_display = (
                f"{flag} {job_position} – {job_country}"
            )
            job_status_line = "✅ Position is open.\n"
        else:
            job_display = "General Application"
            job_status_line = ""

        message += f"*Application #{i}*\n"
        if full_name:
            message += f"👤 Name: {full_name}\n"
        message += f"💼 Applied For: {job_display}\n"
        if job_status_line:
            message += job_status_line
        message += (
            f"👷 Profession: {profession or 'N/A'}\n"
            f"🌍 Nationality: {nationality or 'N/A'}\n"
            f"🎯 Preference: {work_pref or 'N/A'}\n"
            f"📅 Experience: {experience or 'N/A'}\n"
            f"📌 Status: *{status}*\n"
        )
        if next_step == "call_back":
            message += (
                f"📞 Call Back: {pref_day or ''} "
                f"at {pref_time or ''}\n"
            )
        elif next_step == "office_visit":
            message += (
                f"🏢 Office Visit: {pref_day or ''} "
                f"at {pref_time or ''}\n"
            )
        message += (
            f"📅 Applied: {date}\n"
            f"─────────────────\n\n"
        )

    message += "Type *hi* for menu."
    return message


# ====================================
# STATIC MAPS (kept for time/day logic)
# ====================================

DAY_MAP = {
    "1": "Sunday", "sunday": "Sunday", "sun": "Sunday",
    "2": "Monday", "monday": "Monday", "mon": "Monday",
    "3": "Tuesday", "tuesday": "Tuesday", "tue": "Tuesday",
    "4": "Wednesday", "wednesday": "Wednesday",
    "wed": "Wednesday",
    "5": "Thursday", "thursday": "Thursday",
    "thu": "Thursday",
}

OFFICE_TIME_MAP = {
    "1": "11:00 AM", "11:00": "11:00 AM",
    "11": "11:00 AM",
    "2": "11:30 AM", "11:30": "11:30 AM",
    "3": "12:00 PM", "12:00": "12:00 PM",
    "12": "12:00 PM",
    "4": "12:30 PM", "12:30": "12:30 PM",
    "5": "1:00 PM", "1:00": "1:00 PM",
    "13:00": "1:00 PM",
    "6": "1:30 PM", "1:30": "1:30 PM",
    "13:30": "1:30 PM",
    "7": "2:00 PM", "2:00": "2:00 PM",
    "14:00": "2:00 PM",
    "8": "2:30 PM", "2:30": "2:30 PM",
    "14:30": "2:30 PM",
    "9": "3:00 PM", "3:00": "3:00 PM",
    "15:00": "3:00 PM",
    "10": "3:30 PM", "3:30": "3:30 PM",
    "15:30": "3:30 PM",
    "11": "4:00 PM", "4:00": "4:00 PM",
    "16:00": "4:00 PM",
}

CALL_TIME_MAP = {
    **OFFICE_TIME_MAP,
    "12": "4:30 PM", "4:30": "4:30 PM",
    "16:30": "4:30 PM",
}


# ====================================
# WEBHOOK
# ====================================

@app.get("/webhook")
async def verify_webhook(request: Request):
    params = request.query_params
    if (
        params.get("hub.mode") == "subscribe"
        and params.get("hub.verify_token") == VERIFY_TOKEN
    ):
        logging.info("✅ Webhook verified by Meta")
        return int(params.get("hub.challenge"))
    logging.warning("⚠️ Webhook verification failed")
    return {"error": "Verification failed"}


@app.post("/webhook")
async def receive_message(request: Request):

    raw_body = await request.body()
    signature = request.headers.get(
        "X-Hub-Signature-256", ""
    )

    if not verify_webhook_signature(raw_body, signature):
        logging.warning(
            "🚨 SECURITY: Rejected unsigned/invalid "
            "webhook request"
        )
        return {"status": "ok"}

    try:
        data = json.loads(raw_body)
        value = data["entry"][0]["changes"][0]["value"]

        if "messages" not in value:
            return {"status": "ok"}

        message = value["messages"][0]
        sender = message["from"]
        msg_type = message.get("type", "")

        if not is_valid_phone(sender):
            logging.warning(
                f"🚨 SECURITY: Invalid phone format: "
                f"{sender[:20]}"
            )
            return {"status": "ok"}

        if not rate_limiter.is_allowed(
            sender, max_requests=20, window_seconds=60
        ):
            logging.warning(
                f"🚨 SECURITY: Rate limit exceeded for "
                f"{mask_phone(sender)}"
            )
            send_text(
                sender,
                "⚠️ Too many messages. Please wait a "
                "minute before trying again."
            )
            return {"status": "ok"}

        if msg_type == "text":
            text = message["text"]["body"].strip()
            text_lower = text.lower()
        elif msg_type == "interactive":
            interactive = message.get("interactive", {})
            int_type = interactive.get("type", "")
            if int_type == "button_reply":
                text = interactive["button_reply"].get(
                    "title", ""
                )
            elif int_type == "list_reply":
                text = interactive["list_reply"].get(
                    "title", ""
                )
            else:
                text = ""
            text_lower = text.lower()
        else:
            send_text(
                sender,
                "🙏 I can only read text messages.\n\n"
                "Please type *hi* to see the menu."
            )
            return {"status": "ok"}

        if len(text) > 1000:
            logging.warning(
                f"⚠️ Oversized message from "
                f"{mask_phone(sender)}: {len(text)} chars"
            )
            send_text(
                sender,
                "⚠️ Your message is too long. "
                "Please send a shorter reply."
            )
            return {"status": "ok"}

        logging.info(
            f"📩 From {mask_phone(sender)}: {text[:100]}"
        )

        state = get_state(sender)

        # ── Cancel ──
        if text_lower in [
            "cancel", "stop", "back", "exit",
            "quit", "menu", "restart"
        ]:
            clear_state(sender)
            send_text(sender, "❌ Cancelled.\n")
            send_text(sender, build_menu_text())
            return {"status": "ok"}

        # ── In-progress application ──
        if state is not None:
            await handle_application_flow(
                sender, text, text_lower, state
            )
            return {"status": "ok"}

        # ── Menu ──
        if text_lower in [
            "hi", "hello", "hey", "start", "help",
            "hii", "hiii", "helo", "main menu"
        ]:
            send_text(sender, build_menu_text())
            return {"status": "ok"}

        # ── Jobs ──
        if text_lower in [
            "1", "jobs", "job", "openings",
            "vacancies", "offers", "view jobs"
        ]:
            send_text(sender, get_jobs_text())
            return {"status": "ok"}

        # ── Process ──
        if text_lower in [
            "3", "process", "visa", "visa process",
            "procedure", "how", "steps"
        ]:
            send_text(sender, build_process_text())
            return {"status": "ok"}

        # ── Status ──
        if text_lower in [
            "4", "status", "check", "my status",
            "application", "my application"
        ]:
            send_text(sender, check_status(sender))
            return {"status": "ok"}

        # ── Contact ──
        if text_lower in [
            "5", "contact", "consultant", "talk", "call",
            "agent", "other", "question", "help me",
            "speak", "query"
        ]:
            send_text(sender, build_contact_text())
            return {"status": "ok"}

        # ── Costs ──
        if text_lower in [
            "costs", "cost", "price", "fees", "charges"
        ]:
            send_text(sender, build_cost_text())
            return {"status": "ok"}

        # ── Apply ──
        if text_lower.startswith("apply") or text_lower == "2":

            if text_lower in ["apply", "2"]:
                send_text(sender, (
                    "📋 *To apply, specify a job "
                    "number.*\n\n"
                    "Type *apply* followed by the "
                    "job number.\n\n"
                    "Examples:\n"
                    "👉 *apply 1* → Apply for Job #1\n"
                    "👉 *apply 3* → Apply for Job #3\n\n"
                    "Type *jobs* to see available "
                    "positions."
                ))
                return {"status": "ok"}

            parts = text_lower.split()
            if len(parts) != 2 or not parts[1].isdigit():
                send_text(sender, (
                    "⚠️ *Incorrect format!*\n\n"
                    "Type *apply* followed by the "
                    "job number.\n\n"
                    "Examples:\n"
                    "👉 *apply 1* → Apply for "
                    "Job #1\n\n"
                    "Type *jobs* to see available "
                    "positions."
                ))
                return {"status": "ok"}

            job_id_raw = int(parts[1])
            if job_id_raw <= 0 or job_id_raw > 999999:
                send_text(sender, (
                    "❌ Invalid job number.\n\n"
                    "Type *jobs* to see available "
                    "positions."
                ))
                return {"status": "ok"}

            job_id = job_id_raw

            with get_cursor() as cursor:
                cursor.execute(
                    "SELECT id, position, country, "
                    "salary, is_active, is_deleted "
                    "FROM jobs WHERE id = %s",
                    (job_id,)
                )
                job = cursor.fetchone()

            if not job:
                send_text(sender, (
                    f"❌ *Job #{job_id} no longer "
                    f"exists.*\n\n"
                    "Type *jobs* to see available "
                    "positions."
                ))
                return {"status": "ok"}

            if job[5]:
                send_text(sender, (
                    f"❌ *Job #{job_id} has been "
                    f"removed.*\n\n"
                    "Type *jobs* to see available "
                    "positions."
                ))
                return {"status": "ok"}

            if not job[4]:
                send_text(sender, (
                    f"⏸️ *Job #{job_id} – {job[1]} "
                    f"({job[2]})*\n\n"
                    "This position is currently "
                    "*closed/expired*.\n\n"
                    "Type *jobs* to see open positions."
                ))
                return {"status": "ok"}

            with get_cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM candidates "
                    "WHERE phone = %s AND job_id = %s",
                    (sender, job_id)
                )
                existing = cursor.fetchone()

            if existing:
                send_text(
                    sender,
                    build_already_applied_text(
                        job[1], job[2]
                    )
                )
                return {"status": "ok"}

            flag = get_flag(job[2])
            job_name = f"{job[1]} ({job[2]})"

            set_state(sender, {
                "step": "ask_name",
                "job_id": job[0],
                "job_name": job_name,
                "full_name": None,
                "current_profession": None,
                "nationality": None,
                "current_city": None,
                "work_preference": None,
                "years_experience": None,
                "documents_available": None,
                "process_ready": None,
                "next_step": None,
                "preferred_day": None,
                "preferred_time": None,
            })

            logging.info(
                f"Application started: "
                f"{mask_phone(sender)} → job {job_id}"
            )

            s = bot_settings
            q1_text = s.get(
                "question_1_text",
                "What is your *full name*?"
            )
            q1_example = s.get(
                "question_1_example",
                "Example: Ahmed Al-Rashid"
            )

            send_text(sender, (
                f"📝 *Starting Application*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"You're applying for:\n\n"
                f"{flag} *{job[1]}*\n"
                f"📍 Country: {job[2]}\n"
                f"💰 Salary: {job[3]}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"I'll ask you a few quick questions.\n"
                f"This takes about 2–3 minutes.\n\n"
                f"❓ *Question 1 of 9*\n\n"
                f"{q1_text}\n\n"
                f"{q1_example}\n\n"
                f"💡 Type *cancel* anytime to stop."
            ))
            return {"status": "ok"}

        # ── Unknown ──
        s = bot_settings
        opt1 = s.get(
            "menu_option_1", "View available jobs"
        )
        opt2 = s.get(
            "menu_option_2", "Start application"
        )
        opt3 = s.get(
            "menu_option_3", "Recruitment process"
        )
        opt4 = s.get(
            "menu_option_4", "Check application"
        )
        opt5 = s.get(
            "menu_option_5", "Talk to someone"
        )

        send_text(sender, (
            "🤔 *I didn't understand that.*\n\n"
            "Here's what you can type:\n\n"
            f"📌 *1* or *jobs* → {opt1}\n"
            f"📌 *2* or *apply 1* → {opt2}\n"
            f"📌 *3* or *process* → {opt3}\n"
            f"📌 *4* or *status* → {opt4}\n"
            f"📌 *5* or *contact* → {opt5}\n\n"
            "💡 Type *hi* for the main menu!"
        ))

    except KeyError as e:
        logging.error(f"KeyError in webhook: {e}")
    except Exception as e:
        logging.error(f"Webhook error: {e}")

    return {"status": "ok"}


# ====================================
# APPLICATION FLOW (DYNAMIC)
# ====================================

async def handle_application_flow(
    sender: str, text: str, text_lower: str, state: dict
):
    step = state["step"]
    s = bot_settings

    # ── Q1: Full Name ──
    if step == "ask_name":
        if len(text.strip()) < 2:
            q1_example = s.get(
                "question_1_example",
                "Example: Ahmed Al-Rashid"
            )
            send_text(sender, (
                f"⚠️ *Please enter your full name.*\n\n"
                f"{q1_example}\n\n"
                f"Type *cancel* to go back to menu."
            ))
            return

        state["full_name"] = sanitize_text(text, "name")
        state["step"] = "ask_profession"
        set_state(sender, state)

        q2_text = s.get(
            "question_2_text",
            "What is your *current job/profession*?"
        )
        q2_example = s.get(
            "question_2_example",
            "For example: Electrician, Driver, "
            "Plumber, etc."
        )

        send_text(sender, (
            f"✅ Name: *{state['full_name']}*\n\n"
            f"❓ *Question 2 of 9*\n\n"
            f"{q2_text}\n\n"
            f"{q2_example}\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q2: Profession ──
    if step == "ask_profession":
        if len(text.strip()) < 2:
            q2_example = s.get(
                "question_2_example",
                "For example: Electrician, Driver, "
                "Plumber, etc."
            )
            send_text(sender, (
                f"⚠️ *Please enter your current "
                f"profession.*\n\n"
                f"{q2_example}\n\n"
                f"Type *cancel* to go back to menu."
            ))
            return

        state["current_profession"] = sanitize_text(
            text, "profession"
        )
        state["step"] = "ask_nationality"
        set_state(sender, state)

        q3_text = s.get(
            "question_3_text",
            "What is your *nationality*?"
        )
        q3_example = s.get(
            "question_3_example",
            "For example: Indian, Pakistani, "
            "Filipino, etc."
        )

        send_text(sender, (
            f"✅ Profession: "
            f"*{state['current_profession']}*\n\n"
            f"❓ *Question 3 of 9*\n\n"
            f"{q3_text}\n\n"
            f"{q3_example}\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q3: Nationality ──
    if step == "ask_nationality":
        if len(text.strip()) < 2:
            send_text(sender, (
                "⚠️ *Please enter your nationality.*\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["nationality"] = sanitize_text(
            text, "nationality"
        )
        state["step"] = "ask_city"
        set_state(sender, state)

        q4_text = s.get(
            "question_4_text",
            "What is your *current city/location*?"
        )

        send_text(sender, (
            f"✅ Nationality: "
            f"*{state['nationality']}*\n\n"
            f"❓ *Question 4 of 9*\n\n"
            f"{q4_text}\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q4: City ──
    if step == "ask_city":
        if len(text.strip()) < 2:
            send_text(sender, (
                "⚠️ *Please enter your current city.*"
                "\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["current_city"] = sanitize_text(text, "city")
        state["step"] = "ask_work_preference"
        set_state(sender, state)

        q5_text = s.get(
            "question_5_text",
            "What is your *work preference*?"
        )
        opt1 = s.get(
            "work_pref_option_1", "Saudi Arabia 🇸🇦"
        )
        opt2 = s.get(
            "work_pref_option_2", "Poland / Europe 🇵🇱"
        )
        opt3 = s.get(
            "work_pref_option_3",
            "Any available opportunity"
        )

        send_text(sender, (
            f"✅ City: *{state['current_city']}*\n\n"
            f"❓ *Question 5 of 9*\n\n"
            f"{q5_text}\n\n"
            f"👉 *1* – {opt1}\n"
            f"👉 *2* – {opt2}\n"
            f"👉 *3* – {opt3}\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q5: Work Preference ──
    if step == "ask_work_preference":
        pref_map = get_work_preferences()
        preference = pref_map.get(text_lower)

        if not preference:
            opt1 = s.get(
                "work_pref_option_1",
                "Saudi Arabia 🇸🇦"
            )
            opt2 = s.get(
                "work_pref_option_2",
                "Poland / Europe 🇵🇱"
            )
            opt3 = s.get(
                "work_pref_option_3",
                "Any available opportunity"
            )
            send_text(sender, (
                f"⚠️ *Please choose one option:*\n\n"
                f"👉 *1* – {opt1}\n"
                f"👉 *2* – {opt2}\n"
                f"👉 *3* – {opt3}\n\n"
                f"Type *cancel* to go back to menu."
            ))
            return

        state["work_preference"] = preference
        state["step"] = "ask_experience"
        set_state(sender, state)

        q6_text = s.get(
            "question_6_text",
            "How many *years of experience* do "
            "you have?"
        )

        send_text(sender, (
            f"✅ Work Preference: *{preference}*\n\n"
            f"❓ *Question 6 of 9*\n\n"
            f"{q6_text}\n"
            f"as {state['current_profession']}?\n\n"
            f"For example: 0, 1, 2, 5, 10\n"
            f"Or type *fresher* if no experience.\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q6: Experience ──
    if step == "ask_experience":
        exp_text = text.strip()
        exp_num = ""
        for word in exp_text.split():
            if word.isdigit():
                exp_num = word
                break
        if exp_text.isdigit():
            exp_num = exp_text

        fresher_words = [
            "no", "none", "zero", "fresher",
            "fresh", "nil", "0"
        ]

        if not exp_num and not any(
            w in text_lower for w in fresher_words
        ):
            send_text(sender, (
                "⚠️ *Please enter number of years.*"
                "\n\n"
                "For example: *0*, *2*, *5*, *10*\n"
                "Or type *fresher* if no experience."
                "\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        if exp_num and int(exp_num) > 99:
            exp_num = "99"

        experience = (
            "Fresher (0 years)"
            if (
                any(w in text_lower for w in fresher_words)
                and not exp_num
            )
            else f"{exp_num} years"
        )

        state["years_experience"] = experience
        state["step"] = "ask_documents"
        set_state(sender, state)

        q7_text = s.get(
            "question_7_text",
            "Which *documents* do you currently have?"
        )
        q7_example = s.get(
            "question_7_example",
            "Passport, Iqama, Driving License, "
            "Experience Certificate, "
            "Educational Certificates"
        )

        send_text(sender, (
            f"✅ Experience: *{experience}*\n\n"
            f"❓ *Question 7 of 9*\n\n"
            f"{q7_text}\n\n"
            f"📄 {q7_example}\n\n"
            f"Type them separated by commas.\n"
            f"Example: *Passport, Iqama, "
            f"Driving License*\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Q7: Documents ──
    if step == "ask_documents":
        if len(text.strip()) < 2:
            send_text(sender, (
                "⚠️ *Please list your documents.*\n\n"
                "Example: *Passport, Iqama, "
                "Driving License*\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["documents_available"] = sanitize_text(
            text, "documents"
        )
        state["step"] = "ask_process_ready"
        set_state(sender, state)

        q8_text = s.get(
            "question_8_text",
            "Are you ready to proceed and support "
            "this process financially?"
        )
        disclaimer = s.get(
            "process_disclaimer",
            "This process requires time, commitment, "
            "and financial readiness from the candidate."
        )

        send_text(sender, (
            f"✅ Documents noted!\n\n"
            f"❓ *Question 8 of 9 (Important)*\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 *Recruitment Process Overview:*\n\n"
            f"1. Registration for the process\n"
            f"2. Work permit application by employer\n"
            f"3. After approval, embassy appointment\n"
            f"4. Document package preparation\n"
            f"5. Visa interview at embassy\n"
            f"6. Visa decision by embassy\n"
            f"7. Travel after visa approval\n\n"
            f"⚠️ *Important:*\n"
            f"{disclaimer}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"*{q8_text}*\n\n"
            f"Reply *yes* or *no*"
        ))
        return

    # ── Q8: Process Ready ──
    if step == "ask_process_ready":
        yes_words = [
            "yes", "y", "yeah", "yep", "sure",
            "ready", "ha", "haan", "ok", "okay"
        ]
        no_words = [
            "no", "n", "nope", "nah", "not ready",
            "nahi", "not yet"
        ]

        if text_lower in yes_words:
            ready = True
        elif text_lower in no_words:
            ready = False
        else:
            send_text(sender, (
                "⚠️ *Please reply with Yes or No.*"
                "\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        if not ready:
            clear_state(sender)
            send_text(sender, build_not_ready_text())
            return

        state["process_ready"] = True
        state["step"] = "ask_next_step"
        set_state(sender, state)

        q9_text = s.get(
            "question_9_text",
            "How would you like to proceed?"
        )
        office_addr = s.get(
            "office_address", OFFICE_ADDRESS
        )
        working_days = s.get(
            "working_days", "Sunday – Thursday"
        )

        send_text(sender, (
            f"✅ Great! You're ready to proceed!\n\n"
            f"❓ *Question 9 of 9 (Last one!)*\n\n"
            f"{q9_text}\n\n"
            f"👉 *1* – Visit our {office_addr}\n"
            f"        {working_days}, "
            f"11:00 AM – 4:30 PM\n\n"
            f"👉 *2* – Schedule a call back\n"
            f"        {working_days}, "
            f"11:00 AM – 5:00 PM\n\n"
            f"Type *1* or *2*"
        ))
        return

    # ── Q9: Next Step ──
    if step == "ask_next_step":
        if text_lower in [
            "1", "office", "visit", "riyadh"
        ]:
            next_step = "office_visit"
        elif text_lower in [
            "2", "call", "callback", "call back", "phone"
        ]:
            next_step = "call_back"
        else:
            office_addr = s.get(
                "office_address", OFFICE_ADDRESS
            )
            send_text(sender, (
                "⚠️ *Please choose:*\n\n"
                f"👉 *1* – Visit {office_addr}\n"
                "👉 *2* – Schedule a call back\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["next_step"] = next_step

        if next_step == "office_visit":
            state["step"] = "ask_office_day"
            set_state(sender, state)
            office_addr = s.get(
                "office_address", OFFICE_ADDRESS
            )
            send_text(sender, (
                f"🏢 *{office_addr} Visit*\n\n"
                "Which day would you prefer?\n\n"
                "👉 *1* – Sunday\n"
                "👉 *2* – Monday\n"
                "👉 *3* – Tuesday\n"
                "👉 *4* – Wednesday\n"
                "👉 *5* – Thursday\n\n"
                "Office hours: 11:00 AM – 4:30 PM\n\n"
                "Type *cancel* to go back to menu."
            ))
        else:
            state["step"] = "ask_call_day"
            set_state(sender, state)
            send_text(sender, (
                "📞 *Schedule Call Back*\n\n"
                "Which day would you prefer?\n\n"
                "👉 *1* – Sunday\n"
                "👉 *2* – Monday\n"
                "👉 *3* – Tuesday\n"
                "👉 *4* – Wednesday\n"
                "👉 *5* – Thursday\n\n"
                "Type *cancel* to go back to menu."
            ))
        return

    # ── Office Day ──
    if step == "ask_office_day":
        day = DAY_MAP.get(text_lower)
        if not day:
            send_text(sender, (
                "⚠️ *Please choose a day (1-5):*\n\n"
                "👉 *1* Sun  👉 *2* Mon  "
                "👉 *3* Tue\n"
                "👉 *4* Wed  👉 *5* Thu\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["preferred_day"] = day
        state["step"] = "ask_office_time"
        set_state(sender, state)

        send_text(sender, (
            f"✅ Day: *{day}*\n\n"
            f"What time would you prefer?\n\n"
            f"👉 *1* – 11:00 AM\n"
            f"👉 *2* – 11:30 AM\n"
            f"👉 *3* – 12:00 PM\n"
            f"👉 *4* – 12:30 PM\n"
            f"👉 *5* – 1:00 PM\n"
            f"👉 *6* – 1:30 PM\n"
            f"👉 *7* – 2:00 PM\n"
            f"👉 *8* – 2:30 PM\n"
            f"👉 *9* – 3:00 PM\n"
            f"👉 *10* – 3:30 PM\n"
            f"👉 *11* – 4:00 PM\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Office Time ──
    if step == "ask_office_time":
        time_slot = OFFICE_TIME_MAP.get(text_lower)
        if not time_slot:
            send_text(sender, (
                "⚠️ *Please choose a time (1-11).*"
                "\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["preferred_time"] = time_slot
        state["step"] = "confirm_whatsapp"
        set_state(sender, state)

        send_text(sender, (
            f"✅ Office Visit: "
            f"*{state['preferred_day']}* "
            f"at *{time_slot}*\n\n"
            f"📱 *Last step!*\n\n"
            f"Can we confirm that this WhatsApp\n"
            f"number (+{sender}) is the best way\n"
            f"to reach you?\n\n"
            f"Reply *yes* to confirm\n"
            f"Or type a *different number*"
        ))
        return

    # ── Call Day ──
    if step == "ask_call_day":
        day = DAY_MAP.get(text_lower)
        if not day:
            send_text(sender, (
                "⚠️ *Please choose a day (1-5):*\n\n"
                "👉 *1* Sun  👉 *2* Mon  "
                "👉 *3* Tue\n"
                "👉 *4* Wed  👉 *5* Thu\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["preferred_day"] = day
        state["step"] = "ask_call_time"
        set_state(sender, state)

        send_text(sender, (
            f"✅ Day: *{day}*\n\n"
            f"What time would you prefer the call?"
            f"\n\n"
            f"👉 *1* – 11:00 AM\n"
            f"👉 *2* – 11:30 AM\n"
            f"👉 *3* – 12:00 PM\n"
            f"👉 *4* – 12:30 PM\n"
            f"👉 *5* – 1:00 PM\n"
            f"👉 *6* – 1:30 PM\n"
            f"👉 *7* – 2:00 PM\n"
            f"👉 *8* – 2:30 PM\n"
            f"👉 *9* – 3:00 PM\n"
            f"👉 *10* – 3:30 PM\n"
            f"👉 *11* – 4:00 PM\n"
            f"👉 *12* – 4:30 PM\n\n"
            f"Type *cancel* to go back to menu."
        ))
        return

    # ── Call Time ──
    if step == "ask_call_time":
        time_slot = CALL_TIME_MAP.get(text_lower)
        if not time_slot:
            send_text(sender, (
                "⚠️ *Please choose a time (1-12).*"
                "\n\n"
                "Type *cancel* to go back to menu."
            ))
            return

        state["preferred_time"] = time_slot
        state["step"] = "confirm_whatsapp"
        set_state(sender, state)

        send_text(sender, (
            f"✅ Call Back: "
            f"*{state['preferred_day']}* "
            f"at *{time_slot}*\n\n"
            f"📱 *Last step!*\n\n"
            f"Can we confirm that this WhatsApp\n"
            f"number (+{sender}) is the best way\n"
            f"to reach you?\n\n"
            f"Reply *yes* to confirm\n"
            f"Or type a *different number*"
        ))
        return

    # ── Confirm WhatsApp ──
    if step == "confirm_whatsapp":

        if not state.get("job_id"):
            logging.error(
                f"🚨 SECURITY: confirm_whatsapp reached "
                f"without job_id for "
                f"{mask_phone(sender)} — aborting"
            )
            clear_state(sender)
            send_text(sender, (
                "❌ Something went wrong with your "
                "application.\n\n"
                "Please start again.\n"
                "Type *jobs* to see available positions."
            ))
            return

        confirmed_phone = sender
        confirm_words = [
            "yes", "y", "yeah", "yep", "sure",
            "ok", "okay", "confirm", "ha", "haan"
        ]

        if text_lower not in confirm_words:
            digits = re.sub(r'\D', '', text)
            if is_valid_phone(digits):
                confirmed_phone = digits
            else:
                send_text(sender, (
                    "⚠️ *Please enter a valid phone "
                    "number*\n"
                    "*or reply Yes to confirm current "
                    "number.*\n\n"
                    f"Current number: +{sender}\n\n"
                    "Type *cancel* to go back to menu."
                ))
                return

        try:
            with get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO candidates
                        (phone, full_name,
                         current_profession,
                         nationality, current_city,
                         work_preference,
                         years_experience,
                         documents_available,
                         process_ready, next_step,
                         preferred_day, preferred_time,
                         job_id, status)
                    VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                         %s,%s,%s,%s)
                """, (
                    confirmed_phone,
                    state.get("full_name"),
                    state.get("current_profession"),
                    state.get("nationality"),
                    state.get("current_city"),
                    state.get("work_preference"),
                    state.get("years_experience"),
                    state.get("documents_available"),
                    state.get("process_ready"),
                    state.get("next_step"),
                    state.get("preferred_day"),
                    state.get("preferred_time"),
                    state.get("job_id"),
                    "New"
                ))

            logging.info(
                f"✅ Candidate saved: "
                f"{mask_phone(confirmed_phone)} "
                f"→ job {state.get('job_id')}"
            )

            success_title = s.get(
                "application_success_message",
                "Application Submitted Successfully!"
            )
            office_addr = s.get(
                "office_address", OFFICE_ADDRESS
            )

            if state.get("next_step") == "office_visit":
                next_info = (
                    f"🏢 *Office Visit*\n"
                    f"📅 Day: "
                    f"{state.get('preferred_day')}\n"
                    f"⏰ Time: "
                    f"{state.get('preferred_time')}\n"
                    f"📍 Location: {office_addr}\n\n"
                    f"Your appointment will be "
                    f"confirmed\n"
                    f"shortly via WhatsApp."
                )
            else:
                next_info = (
                    f"📞 *Call Back*\n"
                    f"📅 Day: "
                    f"{state.get('preferred_day')}\n"
                    f"⏰ Time: "
                    f"{state.get('preferred_time')}\n\n"
                    f"Our team will contact you at\n"
                    f"your selected time."
                )

            reply = (
                f"🎉 *{success_title}*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"Here's your summary:\n\n"
                f"👤 Name: "
                f"*{state.get('full_name')}*\n"
                f"💼 Applied For: "
                f"*{state.get('job_name')}*\n"
                f"👷 Profession: "
                f"*{state.get('current_profession')}*\n"
                f"🌍 Nationality: "
                f"*{state.get('nationality')}*\n"
                f"📍 City: "
                f"*{state.get('current_city')}*\n"
                f"🎯 Preference: "
                f"*{state.get('work_preference')}*\n"
                f"📅 Experience: "
                f"*{state.get('years_experience')}*\n"
                f"📄 Documents: "
                f"*{state.get('documents_available')}*\n"
                f"📞 Contact: +{confirmed_phone}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"*Next Step:*\n\n{next_info}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"Type *status* to check your "
                f"application.\n"
                f"Type *hi* for main menu."
            )

            hr_data = {
                "phone": confirmed_phone,
                "full_name": state.get("full_name"),
                "job_name": state.get("job_name"),
                "current_profession": state.get(
                    "current_profession"
                ),
                "nationality": state.get("nationality"),
                "current_city": state.get("current_city"),
                "work_preference": state.get(
                    "work_preference"
                ),
                "years_experience": state.get(
                    "years_experience"
                ),
                "documents_available": state.get(
                    "documents_available"
                ),
                "next_step": state.get("next_step"),
                "preferred_day": state.get(
                    "preferred_day"
                ),
                "preferred_time": state.get(
                    "preferred_time"
                ),
            }

            if s.get_bool(
                "hr_notification_enabled", True
            ):
                notify_hr_whatsapp(hr_data)

            if s.get_bool("hr_email_enabled", True):
                notify_hr_email(hr_data)

        except Exception as e:
            logging.error(
                f"Save error for "
                f"{mask_phone(sender)}: {e}"
            )
            reply = (
                "❌ *Something went wrong.*\n\n"
                "Please try again later.\n"
                "Type *hi* for menu."
            )

        clear_state(sender)
        send_text(sender, reply)
        return

    # ── Unknown step ──
    logging.error(
        f"🚨 Unknown step '{step}' for "
        f"{mask_phone(sender)} — clearing state"
    )
    clear_state(sender)
    send_text(sender, (
        "❌ Something went wrong.\n\n"
        "Let's start over.\n"
        "Type *hi* for main menu."
    ))


# ====================================
# SETTINGS MANAGEMENT
# ====================================

SETTING_CATEGORIES = [
    ("company", "🏢 Company Information"),
    ("messages", "💬 Welcome & Menu Messages"),
    ("questions", "❓ Bot Questions"),
    ("preferences", "🎯 Work Preference Options"),
    ("process", "📋 Recruitment Process Steps"),
    ("confirmations", "✅ Confirmation Messages"),
    ("costs", "💰 Cost Information"),
    ("notifications", "🔔 Notification Settings"),
]


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute("""
            SELECT id, setting_key, setting_value,
                   setting_type, category, label,
                   description, display_order
            FROM bot_settings
            ORDER BY display_order, id
        """)
        rows = cursor.fetchall()

    # Keys to hide from UI (auto-managed internally)
    hidden_keys = {
        "work_pref_value_1",
        "work_pref_value_2",
        "work_pref_value_3",
    }

    grouped = {}
    for row in rows:
        setting_key = row[1]

        # Skip internal fields
        if setting_key in hidden_keys:
            continue

        cat = row[4]
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append({
            "id": row[0],
            "key": setting_key,
            "value": row[2],
            "type": row[3],
            "category": row[4],
            "label": row[5],
            "description": row[6],
            "display_order": row[7],
        })

    categories = []
    for cat_key, cat_label in SETTING_CATEGORIES:
        if cat_key in grouped:
            categories.append(
                (cat_key, cat_label, grouped[cat_key])
            )

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "user": user,
        "active_page": "settings",
        "categories": categories,
        "success": (
            request.query_params.get("saved") == "1"
        ),
    })


@app.post("/settings")
async def save_settings(request: Request):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    form_data = await request.form()
    updated_count = 0

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT setting_key FROM bot_settings"
        )
        valid_keys = {
            row[0] for row in cursor.fetchall()
        }

        for key, value in form_data.items():
            if not key.startswith("setting_"):
                continue

            setting_key = key[8:]

            if setting_key not in valid_keys:
                logging.warning(
                    f"🚨 SECURITY: Unknown setting key "
                    f"'{setting_key}' from "
                    f"{user.get('username')}"
                )
                continue

            clean_value = sanitize_text(
                str(value), "documents"
            )
            if len(clean_value) > 2000:
                clean_value = clean_value[:2000]

            cursor.execute("""
                UPDATE bot_settings
                SET setting_value = %s,
                    updated_at = CURRENT_TIMESTAMP,
                    updated_by = %s
                WHERE setting_key = %s
            """, (
                clean_value,
                user["user_id"],
                setting_key
            ))

            updated_count += 1

        # ── Auto-sync work preference values ──
        # Strip emojis from option text to create
        # clean stored values automatically
        for i in range(1, 4):
            opt_key = f"work_pref_option_{i}"
            val_key = f"work_pref_value_{i}"

            option_text = ""
            for form_key, form_value in form_data.items():
                if form_key == f"setting_{opt_key}":
                    option_text = str(form_value)
                    break

            if option_text:
                # Strip emojis and special characters
                clean_value = re.sub(
                    r'[^\w\s/\-]', '', option_text
                ).strip()

                cursor.execute("""
                    UPDATE bot_settings
                    SET setting_value = %s,
                        updated_at = CURRENT_TIMESTAMP,
                        updated_by = %s
                    WHERE setting_key = %s
                """, (
                    clean_value,
                    user["user_id"],
                    val_key
                ))

    bot_settings.reload()

    logging.info(
        f"✅ Settings updated: {updated_count} values "
        f"by {user.get('username')}"
    )

    return RedirectResponse(
        url="/settings?saved=1", status_code=303
    )

@app.post("/settings/reset")
def reset_settings(request: Request):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(url="/login", status_code=303)

    logging.warning(
        f"⚠️ Settings reset requested by "
        f"{user.get('username')}"
    )
    bot_settings.reload()

    return RedirectResponse(
        url="/settings?saved=1", status_code=303
    )


# ====================================
# AUTH ROUTES
# ====================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(
            url="/dashboard", status_code=303
        )
    return templates.TemplateResponse("login.html", {
        "request": request, "error": None
    })


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    ip = get_client_ip(request)

    if login_protection.is_locked(ip):
        logging.warning(
            f"🚨 SECURITY: Locked IP {ip} attempted login"
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": (
                "Too many failed attempts. "
                "Please try again in 15 minutes."
            )
        })

    username = sanitize_text(
        username.strip(), "generic"
    )[:100]

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, username, password_hash, "
            "full_name, role, is_active "
            "FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()

    if (
        not user
        or not user[5]
        or not verify_password(password, user[2])
    ):
        login_protection.record_failure(ip)
        remaining = login_protection.remaining_attempts(ip)

        if not user or not user[5]:
            error_msg = "Invalid username or password"
        else:
            error_msg = (
                f"Invalid username or password. "
                f"{remaining} attempt(s) remaining."
            )

        logging.warning(
            f"⚠️ Failed login for '{username}' "
            f"from IP {ip}"
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": error_msg
        })

    login_protection.record_success(ip)
    logging.info(f"✅ Login: {username} from IP {ip}")

    token = create_token(user[0], user[1], user[4])
    response = RedirectResponse(
        url="/dashboard", status_code=303
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=TOKEN_EXPIRE_HOURS * 3600
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(
        url="/login", status_code=303
    )
    response.delete_cookie("access_token")
    return response


# ====================================
# DASHBOARD
# ====================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )
    return RedirectResponse(
        url="/dashboard", status_code=303
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM jobs "
            "WHERE is_active = TRUE "
            "AND (is_deleted = FALSE "
            "OR is_deleted IS NULL)"
        )
        total_jobs = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM candidates"
        )
        total_candidates = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM candidates "
            "WHERE status = 'New'"
        )
        new_candidates = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM candidates "
            "WHERE next_step = 'call_back'"
        )
        pending_calls = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM candidates "
            "WHERE next_step = 'office_visit'"
        )
        pending_visits = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM candidates "
            "WHERE status = 'In Process'"
        )
        in_process = cursor.fetchone()[0]

        cursor.execute("""
            SELECT c.id, c.phone, c.full_name,
                   c.current_profession,
                   c.nationality, c.status,
                   c.next_step, c.created_at
            FROM candidates c
            ORDER BY c.created_at DESC LIMIT 10
        """)
        recent = cursor.fetchall()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "active_page": "dashboard",
        "total_jobs": total_jobs,
        "total_candidates": total_candidates,
        "new_candidates": new_candidates,
        "pending_calls": pending_calls,
        "pending_visits": pending_visits,
        "in_process": in_process,
        "recent": recent,
    })


# ====================================
# JOB MANAGEMENT
# ====================================

@app.get("/jobs", response_class=HTMLResponse)
def view_jobs(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, "
            "requirements, is_active "
            "FROM jobs "
            "WHERE (is_deleted = FALSE "
            "OR is_deleted IS NULL) "
            "ORDER BY id"
        )
        rows = cursor.fetchall()

    return templates.TemplateResponse("jobs.html", {
        "request": request, "user": user,
        "active_page": "jobs", "jobs": rows
    })


@app.post("/add-job")
def add_job(
    request: Request,
    country: str = Form(...),
    position: str = Form(...),
    salary: str = Form(...),
    requirements: str = Form("")
):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    country = sanitize_text(country, "generic")[:100]
    position = sanitize_text(position, "generic")[:200]
    salary = sanitize_text(salary, "generic")[:100]
    requirements = sanitize_text(
        requirements, "documents"
    )[:500]

    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO jobs "
            "(country, position, salary, requirements) "
            "VALUES (%s, %s, %s, %s)",
            (country, position, salary, requirements)
        )
    logging.info(
        f"Job added by {user.get('username')}: "
        f"{position} in {country}"
    )
    return RedirectResponse(url="/jobs", status_code=303)


@app.get("/edit-job/{job_id}", response_class=HTMLResponse)
def edit_job_page(request: Request, job_id: int):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, "
            "requirements, is_active "
            "FROM jobs WHERE id = %s "
            "AND (is_deleted = FALSE "
            "OR is_deleted IS NULL)",
            (job_id,)
        )
        job = cursor.fetchone()

    if not job:
        return RedirectResponse(
            url="/jobs", status_code=303
        )

    return templates.TemplateResponse("edit_job.html", {
        "request": request, "user": user,
        "active_page": "jobs", "job": job
    })


@app.post("/update-job/{job_id}")
def update_job(
    request: Request, job_id: int,
    country: str = Form(...),
    position: str = Form(...),
    salary: str = Form(...),
    requirements: str = Form("")
):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    country = sanitize_text(country, "generic")[:100]
    position = sanitize_text(position, "generic")[:200]
    salary = sanitize_text(salary, "generic")[:100]
    requirements = sanitize_text(
        requirements, "documents"
    )[:500]

    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE jobs SET country=%s, position=%s, "
            "salary=%s, requirements=%s WHERE id=%s",
            (country, position, salary,
             requirements, job_id)
        )
    logging.info(
        f"Job {job_id} updated by "
        f"{user.get('username')}"
    )
    return RedirectResponse(url="/jobs", status_code=303)


@app.get("/toggle-job/{job_id}")
def toggle_job(request: Request, job_id: int):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE jobs SET is_active = NOT is_active "
            "WHERE id = %s",
            (job_id,)
        )
    return RedirectResponse(url="/jobs", status_code=303)


@app.get("/delete-job/{job_id}")
def delete_job(request: Request, job_id: int):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE jobs SET is_active = FALSE, "
            "is_deleted = TRUE WHERE id = %s",
            (job_id,)
        )
    logging.info(
        f"Job {job_id} soft-deleted by "
        f"{user.get('username')}"
    )
    return RedirectResponse(url="/jobs", status_code=303)


# ====================================
# CANDIDATE MANAGEMENT
# ====================================

@app.get("/candidates", response_class=HTMLResponse)
def view_candidates(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    VALID_STATUSES = {
        "New", "In Process", "Interview Scheduled",
        "Documents Pending", "Work Permit Applied",
        "Embassy Appointment", "Visa Interview",
        "Approved", "Rejected", "Cancelled"
    }
    VALID_NEXT_STEPS = {"call_back", "office_visit"}

    status_filter = request.query_params.get(
        "status", ""
    )
    next_step_filter = request.query_params.get(
        "next_step", ""
    )

    if status_filter not in VALID_STATUSES:
        status_filter = ""
    if next_step_filter not in VALID_NEXT_STEPS:
        next_step_filter = ""

    query = """
        SELECT c.id, c.phone, c.full_name,
               c.current_profession,
               c.nationality, c.current_city,
               c.work_preference,
               c.years_experience,
               c.documents_available,
               c.process_ready, c.next_step,
               c.preferred_day, c.preferred_time,
               c.status, c.created_at, c.notes
        FROM candidates c
    """
    conditions, params = [], []
    if status_filter:
        conditions.append("c.status = %s")
        params.append(status_filter)
    if next_step_filter:
        conditions.append("c.next_step = %s")
        params.append(next_step_filter)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY c.created_at DESC"

    with get_cursor() as cursor:
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

    return templates.TemplateResponse("candidates.html", {
        "request": request, "user": user,
        "active_page": "candidates",
        "candidates": rows,
        "status_filter": status_filter,
        "next_step_filter": next_step_filter,
    })


@app.get(
    "/candidate/{candidate_id}",
    response_class=HTMLResponse
)
def view_candidate_detail(
    request: Request, candidate_id: int
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    candidate = job = None
    notes = []

    try:
        with get_cursor() as cursor:
            cursor.execute("""
                SELECT c.id, c.phone, c.full_name,
                       c.current_profession,
                       c.nationality, c.current_city,
                       c.work_preference,
                       c.years_experience,
                       c.documents_available,
                       c.process_ready, c.next_step,
                       c.preferred_day,
                       c.preferred_time, c.status,
                       c.created_at, c.notes, c.job_id
                FROM candidates c WHERE c.id = %s
            """, (candidate_id,))
            candidate = cursor.fetchone()

        if not candidate:
            return RedirectResponse(
                url="/candidates", status_code=303
            )

        if candidate[16]:
            with get_cursor() as cursor:
                cursor.execute(
                    "SELECT id, country, position, "
                    "salary FROM jobs WHERE id = %s",
                    (candidate[16],)
                )
                job = cursor.fetchone()

        with get_cursor() as cursor:
            cursor.execute("""
                SELECT cn.id, cn.note, cn.created_at,
                       COALESCE(u.full_name,
                                'Unknown User')
                FROM candidate_notes cn
                LEFT JOIN users u
                    ON cn.user_id = u.id
                WHERE cn.candidate_id = %s
                ORDER BY cn.created_at DESC
            """, (candidate_id,))
            notes = cursor.fetchall()

    except Exception as e:
        logging.error(f"Candidate detail error: {e}")
        return RedirectResponse(
            url="/candidates", status_code=303
        )

    return templates.TemplateResponse(
        "candidate_detail.html", {
            "request": request, "user": user,
            "active_page": "candidates",
            "candidate": candidate,
            "job": job, "notes": notes,
        }
    )


@app.post("/update-candidate-status/{candidate_id}")
def update_candidate_status(
    request: Request, candidate_id: int,
    status: str = Form(...)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    VALID_STATUSES = {
        "New", "In Process", "Interview Scheduled",
        "Documents Pending", "Work Permit Applied",
        "Embassy Appointment", "Visa Interview",
        "Approved", "Rejected", "Cancelled"
    }
    if status not in VALID_STATUSES:
        logging.warning(
            f"🚨 SECURITY: Invalid status '{status}' "
            f"by {user.get('username')}"
        )
        return RedirectResponse(
            url=f"/candidate/{candidate_id}",
            status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE candidates SET status=%s, "
            "updated_at=CURRENT_TIMESTAMP "
            "WHERE id=%s",
            (status, candidate_id)
        )
    logging.info(
        f"Status updated: candidate {candidate_id} "
        f"→ '{status}' by {user.get('username')}"
    )
    return RedirectResponse(
        url=f"/candidate/{candidate_id}",
        status_code=303
    )


@app.post("/add-note/{candidate_id}")
def add_note(
    request: Request, candidate_id: int,
    note: str = Form(...)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(
            url="/login", status_code=303
        )

    clean_note = sanitize_text(note, "note")
    if not clean_note:
        return RedirectResponse(
            url=f"/candidate/{candidate_id}",
            status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO candidate_notes "
            "(candidate_id, user_id, note) "
            "VALUES (%s, %s, %s)",
            (candidate_id, user["user_id"], clean_note)
        )
    return RedirectResponse(
        url=f"/candidate/{candidate_id}",
        status_code=303
    )


@app.get("/delete-candidate/{candidate_id}")
def delete_candidate(
    request: Request, candidate_id: int
):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "DELETE FROM candidates WHERE id = %s",
            (candidate_id,)
        )

    logging.info(
        f"Candidate {candidate_id} deleted by "
        f"{user.get('username')}"
    )
    return RedirectResponse(
        url="/candidates", status_code=303
    )


# ====================================
# USER MANAGEMENT
# ====================================

@app.get("/users", response_class=HTMLResponse)
def view_users(request: Request):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, username, full_name, role, "
            "email, is_active, created_at "
            "FROM users ORDER BY id"
        )
        rows = cursor.fetchall()

    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "active_page": "users", "users": rows
    })


@app.post("/add-user")
def add_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form("staff"),
    email: str = Form("")
):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(url="/login", status_code=303)

    if role not in {"admin", "staff"}:
        role = "staff"

    def get_users_page(error_msg):
        with get_cursor() as cursor:
            cursor.execute(
                "SELECT id, username, full_name, role, "
                "email, is_active, created_at "
                "FROM users ORDER BY id"
            )
            rows = cursor.fetchall()
        return templates.TemplateResponse("users.html", {
            "request": request,
            "user": user,
            "active_page": "users",
            "users": rows,
            "error": error_msg,
        })

    if len(password) < 8:
        logging.warning(
            f"⚠️ Weak password attempt when adding "
            f"user by {user.get('username')}"
        )
        return get_users_page(
            "Password must be at least 8 characters."
        )

    username_clean = sanitize_text(username.strip(), "generic")[:100]
    full_name_clean = sanitize_text(full_name.strip(), "name")[:200]
    email_clean = sanitize_text(email.strip(), "generic")[:200]

    if not re.match(r'^[a-zA-Z0-9_\.]+$', username_clean):
        return get_users_page(
            "Username can only contain letters, numbers, underscores, and dots. No spaces allowed."
        )

    hashed = hash_password(password)
    try:
        with get_cursor() as cursor:
            cursor.execute(
                "INSERT INTO users "
                "(username, password_hash, full_name, "
                "role, email, created_by) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (username_clean, hashed, full_name_clean,
                 role, email_clean, user["user_id"])
            )
        logging.info(
            f"User added: '{username_clean}' ({role}) "
            f"by {user.get('username')}"
        )
        return RedirectResponse(url="/users?success=1", status_code=303)
    except Exception as e:
        logging.error(f"Add user error: {e}")
        if "duplicate key" in str(e):
            return get_users_page(
                f"Username '{username_clean}' already exists. Please choose a different username."
            )
        return get_users_page(
            "Failed to add user. Please try again."
        )

@app.get("/toggle-user/{user_id}")
def toggle_user(request: Request, user_id: int):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    if user["user_id"] == user_id:
        return RedirectResponse(
            url="/users", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE users SET is_active = NOT is_active "
            "WHERE id = %s",
            (user_id,)
        )
    return RedirectResponse(
        url="/users", status_code=303
    )


@app.post("/reset-password/{user_id}")
def reset_password(
    request: Request, user_id: int,
    new_password: str = Form(...)
):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    if len(new_password) < 8:
        return RedirectResponse(
            url="/users", status_code=303
        )

    hashed = hash_password(new_password)
    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE users SET password_hash = %s "
            "WHERE id = %s",
            (hashed, user_id)
        )
    logging.info(
        f"Password reset for user {user_id} "
        f"by {user.get('username')}"
    )
    return RedirectResponse(
        url="/users", status_code=303
    )


@app.get("/delete-user/{user_id}")
def delete_user(request: Request, user_id: int):
    user = get_current_user(request)
    if not user or user.get("role") != "admin":
        return RedirectResponse(
            url="/login", status_code=303
        )

    if user["user_id"] == user_id:
        return RedirectResponse(
            url="/users", status_code=303
        )

    with get_cursor() as cursor:
        cursor.execute(
            "DELETE FROM users WHERE id = %s",
            (user_id,)
        )

    logging.info(
        f"User {user_id} deleted by "
        f"{user.get('username')}"
    )
    return RedirectResponse(
        url="/users", status_code=303
    )