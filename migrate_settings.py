import psycopg2
import os
from dotenv import load_dotenv

import psycopg2
import os
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    result = urllib.parse.urlparse(DATABASE_URL)
    conn = psycopg2.connect(
        host=result.hostname,
        port=result.port,
        database=result.path[1:],
        user=result.username,
        password=result.password
    )
else:
    conn = psycopg2.connect(
        host="localhost",
        database="overseas_bot3",
        user="postgres",
        password=os.getenv("DB_PASSWORD")
    )
cursor = conn.cursor()

print("🔧 Adding bot_settings table...")

# Check if table already exists
cursor.execute("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'bot_settings'
    )
""")
exists = cursor.fetchone()[0]

if exists:
    print("⚠️ bot_settings table already exists. Skipping creation.")
    print("   To rebuild, drop it first: DROP TABLE bot_settings;")
    cursor.close()
    conn.close()
    exit()

# Create table
cursor.execute("""
    CREATE TABLE bot_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        setting_type VARCHAR(20) DEFAULT 'text',
        category VARCHAR(50) NOT NULL,
        label VARCHAR(200) NOT NULL,
        description TEXT,
        display_order INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by INTEGER REFERENCES users(id)
    );
""")
print("✅ bot_settings table created")

# Also add is_deleted column to jobs if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'jobs' AND column_name = 'is_deleted'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE jobs ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE"
    )
    print("✅ Added is_deleted column to jobs table")

# Also add full_name to conversation_state if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'conversation_state'
    AND column_name = 'full_name'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE conversation_state "
        "ADD COLUMN full_name VARCHAR(200)"
    )
    print("✅ Added full_name column to conversation_state")

# Also add full_name to candidates if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'candidates'
    AND column_name = 'full_name'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE candidates ADD COLUMN full_name VARCHAR(200)"
    )
    print("✅ Added full_name column to candidates")

# ── INSERT ALL DEFAULT SETTINGS ──
# (paste the same default_settings list from above)

default_settings = [
    (
        "company_name",
        "Overseas Recruitment",
        "text", "company", "Company Name",
        "Your company/agency name shown in messages",
        1
    ),
    (
        "contact_phone",
        "+966 XX XXX XXXX",
        "text", "company", "Contact Phone Number",
        "Phone number shown to candidates",
        2
    ),
    (
        "contact_email",
        "info@overseasrecruitment.com",
        "text", "company", "Contact Email",
        "Email shown to candidates",
        3
    ),
    (
        "office_address",
        "Riyadh Office",
        "text", "company", "Office Address",
        "Office address for visit appointments",
        4
    ),
    (
        "working_days",
        "Sunday – Thursday",
        "text", "company", "Working Days",
        "Days your office is open",
        5
    ),
    (
        "working_hours",
        "11:00 AM – 5:00 PM",
        "text", "company", "Working Hours",
        "Office working hours",
        6
    ),
    (
        "welcome_greeting",
        "Welcome to Overseas Recruitment!",
        "text", "messages", "Welcome Greeting",
        "First line of the welcome message",
        10
    ),
    (
        "welcome_subtitle",
        "We help you find great jobs abroad 🌍",
        "text", "messages", "Welcome Subtitle",
        "Second line shown after greeting",
        11
    ),
    (
        "menu_option_1",
        "View available jobs",
        "text", "messages", "Menu Option 1 Text",
        "Label for 'jobs' option in menu",
        12
    ),
    (
        "menu_option_2",
        "Start application",
        "text", "messages", "Menu Option 2 Text",
        "Label for 'apply' option in menu",
        13
    ),
    (
        "menu_option_3",
        "Recruitment process",
        "text", "messages", "Menu Option 3 Text",
        "Label for 'process' option in menu",
        14
    ),
    (
        "menu_option_4",
        "Check application",
        "text", "messages", "Menu Option 4 Text",
        "Label for 'status' option in menu",
        15
    ),
    (
        "menu_option_5",
        "Talk to someone",
        "text", "messages", "Menu Option 5 Text",
        "Label for 'contact' option in menu",
        16
    ),
    (
        "question_1_text",
        "What is your *full name*?",
        "text", "questions", "Question 1: Name",
        "The question asking for candidate's name",
        20
    ),
    (
        "question_1_example",
        "Example: Ahmed Al-Rashid",
        "text", "questions", "Question 1: Example",
        "Example shown below the name question",
        21
    ),
    (
        "question_2_text",
        "What is your *current job/profession*?",
        "text", "questions", "Question 2: Profession",
        "The question asking for profession",
        22
    ),
    (
        "question_2_example",
        "For example: Electrician, Driver, Plumber, etc.",
        "text", "questions", "Question 2: Example",
        "Example shown below the profession question",
        23
    ),
    (
        "question_3_text",
        "What is your *nationality*?",
        "text", "questions", "Question 3: Nationality",
        "The question asking for nationality",
        24
    ),
    (
        "question_3_example",
        "For example: Indian, Pakistani, Filipino, etc.",
        "text", "questions", "Question 3: Example",
        "Example shown below the nationality question",
        25
    ),
    (
        "question_4_text",
        "What is your *current city/location*?",
        "text", "questions", "Question 4: City",
        "The question asking for current city",
        26
    ),
    (
        "question_5_text",
        "What is your *work preference*?",
        "text", "questions", "Question 5: Work Preference",
        "The question asking for work preference",
        27
    ),
    (
        "question_6_text",
        "How many *years of experience* do you have?",
        "text", "questions", "Question 6: Experience",
        "The question asking for experience",
        28
    ),
    (
        "question_7_text",
        "Which *documents* do you currently have?",
        "text", "questions", "Question 7: Documents",
        "The question asking for available documents",
        29
    ),
    (
        "question_7_example",
        "Passport, Iqama, Driving License, Experience Certificate, Educational Certificates",
        "text", "questions", "Question 7: Document Examples",
        "List of document examples shown to candidate",
        30
    ),
    (
        "question_8_text",
        "Are you ready to proceed and support this process financially?",
        "text", "questions", "Question 8: Process Ready",
        "The financial readiness question",
        31
    ),
    (
        "question_9_text",
        "How would you like to proceed?",
        "text", "questions", "Question 9: Next Step",
        "The question about next step preference",
        32
    ),
    (
        "work_pref_option_1",
        "Saudi Arabia 🇸🇦",
        "text", "preferences", "Work Preference Option 1",
        "First work preference choice",
        40
    ),
    (
        "work_pref_value_1",
        "Saudi Arabia",
        "text", "preferences", "Work Preference Value 1",
        "Stored value for first preference",
        41
    ),
    (
        "work_pref_option_2",
        "Poland / Europe 🇵🇱",
        "text", "preferences", "Work Preference Option 2",
        "Second work preference choice",
        42
    ),
    (
        "work_pref_value_2",
        "Poland / Europe",
        "text", "preferences", "Work Preference Value 2",
        "Stored value for second preference",
        43
    ),
    (
        "work_pref_option_3",
        "Any available opportunity",
        "text", "preferences", "Work Preference Option 3",
        "Third work preference choice",
        44
    ),
    (
        "work_pref_value_3",
        "Any Available",
        "text", "preferences", "Work Preference Value 3",
        "Stored value for third preference",
        45
    ),
    (
        "process_step_1",
        "Registration for the recruitment process",
        "text", "process", "Process Step 1",
        "First step in the recruitment process",
        50
    ),
    (
        "process_step_2",
        "Work permit application by employer",
        "text", "process", "Process Step 2",
        "Second step",
        51
    ),
    (
        "process_step_3",
        "Work permit approval by employer",
        "text", "process", "Process Step 3",
        "Third step",
        52
    ),
    (
        "process_step_4",
        "Embassy appointment registration (based on available slots / draw system)",
        "text", "process", "Process Step 4",
        "Fourth step",
        53
    ),
    (
        "process_step_5",
        "Document package preparation from employer",
        "text", "process", "Process Step 5",
        "Fifth step",
        54
    ),
    (
        "process_step_6",
        "Visa interview at the embassy",
        "text", "process", "Process Step 6",
        "Sixth step",
        55
    ),
    (
        "process_step_7",
        "Visa decision by embassy",
        "text", "process", "Process Step 7",
        "Seventh step",
        56
    ),
    (
        "process_step_8",
        "Travel to destination country after visa approval",
        "text", "process", "Process Step 8",
        "Eighth step",
        57
    ),
    (
        "process_disclaimer",
        "This process requires time, commitment, and financial readiness from the candidate. Visa approval is strictly subject to the embassy's final decision.",
        "textarea", "process", "Process Disclaimer",
        "Important disclaimer shown after process steps",
        58
    ),
    (
        "application_success_message",
        "Application Submitted Successfully!",
        "text", "confirmations", "Application Success Title",
        "Title shown when application is submitted",
        60
    ),
    (
        "not_ready_message",
        "No problem! Thank you for your interest. Come back when you're ready.",
        "text", "confirmations", "Not Ready Response",
        "Message when candidate says they're not ready",
        61
    ),
    (
        "already_applied_message",
        "You already applied for this job!",
        "text", "confirmations", "Already Applied Message",
        "Message when candidate applies for same job twice",
        62
    ),
    (
        "cost_info_text",
        "Exact costs depend on country & job type. Contact us for details.",
        "textarea", "costs", "Cost Information",
        "Cost information shown when candidate asks about fees",
        70
    ),
    (
        "hr_notification_enabled",
        "true",
        "boolean", "notifications",
        "Enable HR WhatsApp Notifications",
        "Send WhatsApp notification to HR when new application arrives",
        80
    ),
    (
        "hr_email_enabled",
        "true",
        "boolean", "notifications",
        "Enable HR Email Notifications",
        "Send email notification to HR when new application arrives",
        81
    ),
]

for setting in default_settings:
    cursor.execute("""
        INSERT INTO bot_settings
            (setting_key, setting_value, setting_type,
             category, label, description, display_order)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (setting_key) DO NOTHING
    """, setting)

print(f"✅ {len(default_settings)} default settings inserted")

conn.commit()
cursor.close()
conn.close()

print("")
print("=" * 50)
print("🎉 MIGRATION COMPLETE!")
print("=" * 50)
print("")
print("Now proceed to Step 2: Add settings")
print("routes and template to app.py")