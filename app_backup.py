from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from contextlib import contextmanager
from psycopg2.pool import SimpleConnectionPool
import requests
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
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

HR_PHONE = os.getenv("HR_PHONE")
HR_EMAIL = os.getenv("HR_EMAIL")

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))


# ====================================
# DATABASE
# ====================================

db_pool = SimpleConnectionPool(
    1, 10,
    host="localhost",
    database="overseas_bot",
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


def get_flag(country):
    if not country:
        return "🏳️"
    for key, flag in FLAGS.items():
        if key in country.lower():
            return flag
    return "🏳️"


# ====================================
# STATE MANAGEMENT
# ====================================

def get_state(phone):
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT step, job_id, job_name, age, experience "
            "FROM conversation_state WHERE phone = %s",
            (phone,)
        )
        row = cursor.fetchone()

    if not row:
        return None

    return {
        "step": row[0],
        "job_id": row[1],
        "job_name": row[2],
        "age": row[3],
        "experience": row[4]
    }


def set_state(phone, data):
    with get_cursor() as cursor:
        cursor.execute("""
            INSERT INTO conversation_state
                (phone, step, job_id, job_name, age, experience, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (phone)
            DO UPDATE SET
                step = EXCLUDED.step,
                job_id = EXCLUDED.job_id,
                job_name = EXCLUDED.job_name,
                age = EXCLUDED.age,
                experience = EXCLUDED.experience,
                updated_at = CURRENT_TIMESTAMP
        """, (
            phone,
            data.get("step"),
            data.get("job_id"),
            data.get("job_name"),
            data.get("age"),
            data.get("experience")
        ))


def clear_state(phone):
    with get_cursor() as cursor:
        cursor.execute(
            "DELETE FROM conversation_state WHERE phone = %s",
            (phone,)
        )


# ====================================
# SEND MESSAGE
# ====================================

def send_text(to, message):
    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"

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
        response = requests.post(url, headers=headers, json=payload)
        result = response.json()

        if "error" in result:
            logging.error(f"WhatsApp error: {result['error'].get('message')}")
            return False

        logging.info(f"✅ Sent to {to}")
        return True

    except Exception as e:
        logging.error(f"Send failed: {e}")
        return False


# ====================================
# MAIN MENU
# ====================================

MENU_TEXT = (
    "👋 *Welcome to Overseas Recruitment!*\n"
    "━━━━━━━━━━━━━━━━━━━━━\n\n"
    "We help you find great jobs abroad 🌍\n\n"
    "Choose an option:\n\n"
    "📌 Type *jobs* → View available jobs\n"
    "📌 Type *visa* → Visa process info\n"
    "📌 Type *costs* → Cost details\n"
    "📌 Type *consultant* → Talk to someone\n"
    "📌 Type *status* → Check your application\n\n"
    "━━━━━━━━━━━━━━━━━━━━━\n"
    "💡 To apply for a job, first type *jobs*\n"
    "then type *apply 1* (with the job number)"
)


# ====================================
# HR NOTIFICATIONS
# ====================================

def notify_hr_whatsapp(phone, job, age, experience, english):
    if not HR_PHONE:
        return

    message = (
        "🆕 *New Candidate Application!*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📞 Phone: +{phone}\n"
        f"💼 Job: {job}\n"
        f"📅 Age: {age}\n"
        f"🔧 Experience: {experience}\n"
        f"🗣️ English: {english}\n\n"
        "Check dashboard for full details."
    )

    try:
        send_text(HR_PHONE, message)
    except Exception as e:
        logging.error(f"HR notification failed: {e}")


def notify_hr_email(phone, job, age, experience, english):
    if not HR_EMAIL or not SMTP_EMAIL or not SMTP_PASSWORD:
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_EMAIL
        msg["To"] = HR_EMAIL
        msg["Subject"] = f"New Application: {job}"

        body = (
            f"New Candidate Application\n"
            f"========================\n\n"
            f"Phone: +{phone}\n"
            f"Job: {job}\n"
            f"Age: {age}\n"
            f"Experience: {experience}\n"
            f"English: {english}\n\n"
            f"Check dashboard for details."
        )

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
# GET JOBS
# ====================================

def get_jobs_text():
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, requirements "
            "FROM jobs ORDER BY id"
        )
        rows = cursor.fetchall()

    if not rows:
        return (
            "😕 *No jobs available right now.*\n\n"
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
        "Type *hi* for main menu."
    )

    return message


# ====================================
# CHECK STATUS
# ====================================

def check_status(phone):
    with get_cursor() as cursor:
        cursor.execute("""
            SELECT j.position, j.country, c.age,
                   c.experience, c.english_level, c.status, c.created_at
            FROM candidates c
            JOIN jobs j ON c.job_id = j.id
            WHERE c.phone = %s
            ORDER BY c.created_at DESC
        """, (phone,))
        rows = cursor.fetchall()

    if not rows:
        return (
            "📭 *No applications found.*\n\n"
            "You haven't applied for any job yet.\n\n"
            "Type *jobs* to see available openings\n"
            "then type *apply 1* to apply."
        )

    message = "📋 *Your Applications*\n"
    message += "━━━━━━━━━━━━━━━━━━━━━\n\n"

    for i, r in enumerate(rows, 1):
        flag = get_flag(r[1])
        date = r[6].strftime("%d %b %Y") if r[6] else "N/A"

        message += (
            f"*Application #{i}*\n"
            f"{flag} Job: {r[0]} – {r[1]}\n"
            f"📅 Age: {r[2]}\n"
            f"🔧 Experience: {r[3]}\n"
            f"🗣️ English: {r[4]}\n"
            f"📌 Status: *{r[5]}*\n"
            f"📅 Applied: {date}\n"
            f"─────────────────\n\n"
        )

    message += "Type *hi* for menu."
    return message


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
        logging.info("Webhook verified")
        return int(params.get("hub.challenge"))

    return {"error": "Verification failed"}


@app.post("/webhook")
async def receive_message(request: Request):
    data = await request.json()

    try:
        value = data["entry"][0]["changes"][0]["value"]

        if "messages" not in value:
            return {"status": "ok"}

        message = value["messages"][0]
        sender = message["from"]
        msg_type = message.get("type", "")

        # ---------------------------------
        # Get text from message
        # ---------------------------------

        if msg_type == "text":
            text = message["text"]["body"].strip()
            text_lower = text.lower()

        elif msg_type == "interactive":
            interactive = message.get("interactive", {})
            int_type = interactive.get("type", "")

            if int_type == "button_reply":
                text = interactive["button_reply"].get("title", "")
            elif int_type == "list_reply":
                text = interactive["list_reply"].get("title", "")
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

        logging.info(f"📩 From {sender}: {text}")

        # ---------------------------------
        # Get current state
        # ---------------------------------

        state = get_state(sender)

        # =================================
        # PRIORITY 1: CANCEL (works anytime)
        # =================================

        if text_lower in ["cancel", "stop", "back", "exit", "quit", "menu", "restart"]:
            clear_state(sender)
            send_text(sender, "❌ Cancelled.\n")
            send_text(sender, build_menu_text())
            return {"status": "ok"}

        # =================================
        # PRIORITY 2: APPLICATION FLOW
        # (If user is in middle of applying)
        # =================================

        if state is not None:

            step = state["step"]

            # ---- STEP 1: AGE ----

            if step == "ask_age":

                if not text_lower.isdigit():
                    send_text(
                        sender,
                        "⚠️ *Please enter a number for your age.*\n\n"
                        "For example: *25*\n\n"
                        "Type *cancel* to go back to menu."
                    )
                    return {"status": "ok"}

                age = int(text_lower)

                if age < 18 or age > 65:
                    send_text(
                        sender,
                        "⚠️ *Age must be between 18 and 65.*\n\n"
                        "Please enter your correct age.\n\n"
                        "Type *cancel* to go back to menu."
                    )
                    return {"status": "ok"}

                # Save age and move to next step
                state["age"] = age
                state["step"] = "ask_experience"
                set_state(sender, state)

                logging.info(f"State updated: age={age}, step=ask_experience")

                send_text(
                    sender,
                    f"✅ Age: *{age}*\n\n"
                    f"❓ *Question 2 of 3*\n\n"
                    f"Do you have any work experience?\n\n"
                    f"Reply *yes* or *no*"
                )
                return {"status": "ok"}

            # ---- STEP 2: EXPERIENCE ----

            if step == "ask_experience":

                if text_lower in ["yes", "y", "yeah", "yep", "ha", "haan"]:
                    experience = "Yes"
                elif text_lower in ["no", "n", "nope", "nah", "nahi"]:
                    experience = "No"
                else:
                    send_text(
                        sender,
                        "⚠️ *Please reply with Yes or No.*\n\n"
                        "Do you have work experience?\n\n"
                        "Type *cancel* to go back to menu."
                    )
                    return {"status": "ok"}

                # Save experience and move to next step
                state["experience"] = experience
                state["step"] = "ask_english"
                set_state(sender, state)

                logging.info(f"State updated: experience={experience}, step=ask_english")

                send_text(
                    sender,
                    f"✅ Experience: *{experience}*\n\n"
                    f"❓ *Question 3 of 3 (Last one!)*\n\n"
                    f"What is your English level?\n\n"
                    f"Type one of these:\n"
                    f"👉 *beginner*\n"
                    f"👉 *intermediate*\n"
                    f"👉 *fluent*"
                )
                return {"status": "ok"}

            # ---- STEP 3: ENGLISH LEVEL ----

            if step == "ask_english":

                english_map = {
                    "beginner": "Beginner",
                    "basic": "Beginner",
                    "low": "Beginner",
                    "intermediate": "Intermediate",
                    "medium": "Intermediate",
                    "moderate": "Intermediate",
                    "good": "Intermediate",
                    "fluent": "Fluent",
                    "advanced": "Fluent",
                    "excellent": "Fluent",
                    "native": "Fluent"
                }

                english = english_map.get(text_lower)

                if not english:
                    send_text(
                        sender,
                        "⚠️ *Please choose one:*\n\n"
                        "👉 *beginner* – Basic level\n"
                        "👉 *intermediate* – Can communicate\n"
                        "👉 *fluent* – Speak well\n\n"
                        "Type *cancel* to go back to menu."
                    )
                    return {"status": "ok"}

                # Check for duplicate application
                try:
                    with get_cursor() as cursor:
                        cursor.execute(
                            "SELECT id FROM candidates "
                            "WHERE phone = %s AND job_id = %s",
                            (sender, state["job_id"])
                        )
                        existing = cursor.fetchone()

                    if existing:
                        clear_state(sender)
                        send_text(
                            sender,
                            "⚠️ *You already applied for this job!*\n\n"
                            "You can't apply twice for the same position.\n\n"
                            "Type *status* to check your application.\n"
                            "Type *jobs* to see other openings."
                        )
                        return {"status": "ok"}

                    # SAVE TO DATABASE
                    with get_cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO candidates
                                (phone, job_id, age, experience, english_level, status)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (
                            sender,
                            state["job_id"],
                            state["age"],
                            state["experience"],
                            english,
                            "New"
                        ))

                    logging.info(
                        f"✅ Candidate saved: {sender} for job {state['job_id']}"
                    )

                    # Success message
                    reply = (
                        "🎉 *Application Submitted Successfully!*\n"
                        "━━━━━━━━━━━━━━━━━━━━━\n\n"
                        "Here's your application summary:\n\n"
                        f"🏢 Job: *{state['job_name']}*\n"
                        f"📅 Age: *{state['age']}*\n"
                        f"🔧 Experience: *{state['experience']}*\n"
                        f"🗣️ English: *{english}*\n"
                        f"📞 Phone: +{sender}\n\n"
                        "━━━━━━━━━━━━━━━━━━━━━\n\n"
                        "✅ What happens next?\n\n"
                        "1. Our team reviews your profile\n"
                        "2. You'll get a call within 24-48 hours\n"
                        "3. We guide you through the visa process\n\n"
                        "Type *status* to check your application.\n"
                        "Type *hi* for main menu."
                    )

                    # Notify HR
                    notify_hr_whatsapp(
                        sender, state["job_name"],
                        state["age"], state["experience"], english
                    )
                    notify_hr_email(
                        sender, state["job_name"],
                        state["age"], state["experience"], english
                    )

                except Exception as e:
                    logging.error(f"Save error: {e}")
                    reply = (
                        "❌ *Something went wrong.*\n\n"
                        "Please try again.\n"
                        "Type *hi* for menu."
                    )

                clear_state(sender)
                send_text(sender, reply)
                return {"status": "ok"}

        # =================================
        # MAIN COMMANDS (No active state)
        # =================================

        # ---- MENU ----

        if text_lower in ["hi", "hello", "hey", "start", "help", "hii", "hiii"]:
            send_text(sender, MENU_TEXT)
            return {"status": "ok"}

        # ---- VIEW JOBS ----

        if text_lower in ["jobs", "job", "openings", "vacancies", "offers"]:
            send_text(sender, get_jobs_text())
            return {"status": "ok"}

        # ---- VISA ----

        if text_lower in ["visa", "visa process"]:
            reply = (
                "🛂 *Visa Process*\n"
                "━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Here's how we help you:\n\n"
                "1️⃣ *Choose a Job*\n"
                "   Browse our job offers\n\n"
                "2️⃣ *Apply*\n"
                "   Type *apply 1* with job number\n\n"
                "3️⃣ *Documents*\n"
                "   We tell you exactly what's needed\n\n"
                "4️⃣ *Visa Filing*\n"
                "   We handle all paperwork\n\n"
                "5️⃣ *Approval*\n"
                "   Usually takes 4–8 weeks\n\n"
                "6️⃣ *Travel*\n"
                "   We arrange tickets & stay\n\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "📞 Type *consultant* to talk to someone.\n"
                "📋 Type *jobs* to see openings.\n"
                "👉 Type *hi* for menu."
            )
            send_text(sender, reply)
            return {"status": "ok"}

        # ---- COSTS ----

        if text_lower in ["costs", "cost", "price", "fees", "charges"]:
            reply = (
                "💰 *Cost Information*\n"
                "━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Typical costs include:\n\n"
                "📄 *Visa Processing Fee*\n"
                "   Government charges for visa\n\n"
                "🏢 *Agency Service Fee*\n"
                "   Our recruitment service\n\n"
                "✈️ *Travel & Accommodation*\n"
                "   Flight tickets and initial stay\n\n"
                "📋 *Document Translation*\n"
                "   If documents need translation\n\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "💡 *Exact costs depend on the country and job.*\n\n"
                "📞 Type *consultant* for a detailed breakdown.\n"
                "👉 Type *hi* for menu."
            )
            send_text(sender, reply)
            return {"status": "ok"}

        # ---- CONSULTANT ----

        if text_lower in ["consultant", "talk", "call", "contact", "agent"]:
            reply = (
                "👨‍💼 *Talk to a Consultant*\n"
                "━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Our team is available:\n\n"
                "🕐 Mon–Fri: 9:00 AM – 6:00 PM\n"
                "🕐 Saturday: 10:00 AM – 2:00 PM\n"
                "🚫 Sunday: Closed\n\n"
                "📞 Phone: +48 XXX XXX XXX\n"
                "📧 Email: info@overseasrecruitment.com\n\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "✅ We've noted your request!\n"
                "A consultant will contact you on this\n"
                "WhatsApp number within *24 hours*.\n\n"
                "👉 Type *hi* for menu."
            )
            notify_hr_whatsapp(sender, "Requested Consultant", "-", "-", "-")
            send_text(sender, reply)
            return {"status": "ok"}

        # ---- STATUS ----

        if text_lower in ["status", "check", "my status", "application"]:
            send_text(sender, check_status(sender))
            return {"status": "ok"}

        # ---- APPLY ----

        if text_lower.startswith("apply"):

            parts = text_lower.split()

            # Validate format
            if len(parts) != 2 or not parts[1].isdigit():
                send_text(
                    sender,
                    "⚠️ *Incorrect format!*\n\n"
                    "To apply, type *apply* followed by the job number.\n\n"
                    "Examples:\n"
                    "👉 *apply 1* → Apply for Job #1\n"
                    "👉 *apply 3* → Apply for Job #3\n\n"
                    "Type *jobs* first to see available positions."
                )
                return {"status": "ok"}

            job_id = int(parts[1])

            # Check if job exists
            with get_cursor() as cursor:
                cursor.execute(
                    "SELECT id, position, country, salary "
                    "FROM jobs WHERE id = %s",
                    (job_id,)
                )
                job = cursor.fetchone()

            if not job:
                send_text(
                    sender,
                    f"❌ *Job #{job_id} not found!*\n\n"
                    "This job doesn't exist or has been removed.\n\n"
                    "Type *jobs* to see all available positions."
                )
                return {"status": "ok"}

            # Check if already applied
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
                    f"⚠️ *You already applied for this job!*\n\n"
                    f"Job: {job[1]} in {job[2]}\n\n"
                    "You can't apply twice for the same position.\n\n"
                    "Type *status* to check your application.\n"
                    "Type *jobs* to see other openings."
                )
                return {"status": "ok"}

            # Start application flow
            flag = get_flag(job[2])
            job_name = f"{job[1]} ({job[2]})"

            set_state(sender, {
                "step": "ask_age",
                "job_id": job[0],
                "job_name": job_name,
                "age": None,
                "experience": None
            })

            logging.info(f"Application started: {sender} for job {job_id}")

            reply = (
                f"📝 *Starting Application*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"You're applying for:\n\n"
                f"{flag} *{job[1]}*\n"
                f"📍 Country: {job[2]}\n"
                f"💰 Salary: {job[3]}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"I'll ask you 3 quick questions.\n\n"
                f"❓ *Question 1 of 3*\n\n"
                f"What is your age?\n"
                f"(Enter a number between 18-65)\n\n"
                f"💡 Type *cancel* anytime to stop."
            )

            send_text(sender, reply)
            return {"status": "ok"}

        # =================================
        # UNKNOWN MESSAGE
        # =================================

        send_text(
            sender,
            "🤔 *I didn't understand that.*\n\n"
            "Here's what you can type:\n\n"
            "📌 *hi* → Main menu\n"
            "📌 *jobs* → See available jobs\n"
            "📌 *apply 1* → Apply for Job #1\n"
            "📌 *visa* → Visa process info\n"
            "📌 *costs* → Cost details\n"
            "📌 *consultant* → Talk to someone\n"
            "📌 *status* → Check your application\n\n"
            "💡 Start by typing *jobs* to see openings!"
        )

    except KeyError as e:
        logging.error(f"KeyError: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")

    return {"status": "ok"}


# ====================================
# DASHBOARD ROUTES
# ====================================

@app.get("/", response_class=HTMLResponse)
def home():
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    with get_cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM jobs")
        total_jobs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM candidates")
        total_candidates = cursor.fetchone()[0]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_jobs": total_jobs,
        "total_candidates": total_candidates
    })


@app.post("/add-job")
def add_job(
    country: str = Form(...),
    position: str = Form(...),
    salary: str = Form(...),
    requirements: str = Form("")
):
    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO jobs (country, position, salary, requirements) "
            "VALUES (%s, %s, %s, %s)",
            (country.strip(), position.strip(),
             salary.strip(), requirements.strip())
        )
    logging.info(f"Job added: {position} in {country}")
    return RedirectResponse(url="/jobs", status_code=303)


@app.get("/jobs", response_class=HTMLResponse)
def view_jobs(request: Request):
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, requirements "
            "FROM jobs ORDER BY id"
        )
        rows = cursor.fetchall()

    return templates.TemplateResponse("jobs.html", {
        "request": request,
        "jobs": rows
    })
@app.get("/edit-job/{job_id}", response_class=HTMLResponse)
def edit_job_page(request: Request, job_id: int):
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, country, position, salary, requirements FROM jobs WHERE id = %s",
            (job_id,)
        )
        job = cursor.fetchone()

    if not job:
        return RedirectResponse(url="/jobs", status_code=303)

    return templates.TemplateResponse("edit_job.html", {
        "request": request,
        "job": job
    })
@app.post("/update-job/{job_id}")
def update_job(
    job_id: int,
    country: str = Form(...),
    position: str = Form(...),
    salary: str = Form(...),
    requirements: str = Form("")
):
    with get_cursor() as cursor:
        cursor.execute("""
            UPDATE jobs
            SET country = %s,
                position = %s,
                salary = %s,
                requirements = %s
            WHERE id = %s
        """, (
            country.strip(),
            position.strip(),
            salary.strip(),
            requirements.strip(),
            job_id
        ))

    return RedirectResponse(url="/jobs", status_code=303)

@app.get("/delete-job/{job_id}")
def delete_job(job_id: int):
    with get_cursor() as cursor:
        cursor.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
    return RedirectResponse(url="/jobs", status_code=303)


@app.get("/candidates", response_class=HTMLResponse)
def view_candidates(request: Request):
    with get_cursor() as cursor:
        cursor.execute("""
            SELECT
                c.id,
                c.phone,
                j.position,
                j.country,
                c.age,
                c.experience,
                c.english_level,
                c.status,
                c.created_at
            FROM candidates c
            JOIN jobs j ON c.job_id = j.id
            ORDER BY c.created_at DESC
        """)
        rows = cursor.fetchall()

    return templates.TemplateResponse("candidates.html", {
        "request": request,
        "candidates": rows
    })
@app.post("/update-candidate-status/{candidate_id}")
def update_candidate_status(candidate_id: int, status: str = Form(...)):
    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE candidates SET status = %s WHERE id = %s",
            (status, candidate_id)
        )
    return RedirectResponse(url="/candidates", status_code=303)


@app.get("/delete-candidate/{candidate_id}")
def delete_candidate(candidate_id: int):
    with get_cursor() as cursor:
        cursor.execute(
            "DELETE FROM candidates WHERE id = %s",
            (candidate_id,)
        )
    return RedirectResponse(url="/candidates", status_code=303)