import psycopg2
import bcrypt
import os
from dotenv import load_dotenv

import psycopg2
import bcrypt
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

print("🔧 Creating tables...")

# ====================================
# DROP OLD TABLES (if they exist)
# ====================================

cursor.execute("""
    DROP TABLE IF EXISTS candidate_notes CASCADE;
    DROP TABLE IF EXISTS candidates CASCADE;
    DROP TABLE IF EXISTS conversation_state CASCADE;
    DROP TABLE IF EXISTS jobs CASCADE;
    DROP TABLE IF EXISTS users CASCADE;
""")

print("✅ Old tables dropped")

# ====================================
# CREATE USERS TABLE
# ====================================

cursor.execute("""
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(200) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'staff',
        email VARCHAR(200),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id)
    );
""")

print("✅ users table created")

# ====================================
# CREATE JOBS TABLE
# ====================================

cursor.execute("""
    CREATE TABLE jobs (
        id SERIAL PRIMARY KEY,
        country VARCHAR(100) NOT NULL,
        position VARCHAR(200) NOT NULL,
        salary VARCHAR(100),
        requirements TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

print("✅ jobs table created")

# ====================================
# CREATE CANDIDATES TABLE
# ====================================

cursor.execute("""
    CREATE TABLE candidates (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(30) NOT NULL,
        current_profession VARCHAR(200),
        nationality VARCHAR(100),
        current_city VARCHAR(200),
        work_preference VARCHAR(100),
        years_experience VARCHAR(50),
        documents_available TEXT,
        process_ready BOOLEAN DEFAULT FALSE,
        next_step VARCHAR(50),
        preferred_time VARCHAR(100),
        preferred_day VARCHAR(50),
        job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        status VARCHAR(50) DEFAULT 'New',
        notes TEXT,
        assigned_to INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

print("✅ candidates table created")

# ====================================
# CREATE CONVERSATION STATE TABLE
# ====================================

cursor.execute("""
    CREATE TABLE conversation_state (
        phone VARCHAR(30) PRIMARY KEY,
        step VARCHAR(50),
        job_id INTEGER,
        job_name VARCHAR(300),
        current_profession VARCHAR(200),
        nationality VARCHAR(100),
        current_city VARCHAR(200),
        work_preference VARCHAR(100),
        years_experience VARCHAR(50),
        documents_available TEXT,
        process_ready BOOLEAN,
        next_step VARCHAR(50),
        preferred_day VARCHAR(50),
        preferred_time VARCHAR(100),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

print("✅ conversation_state table created")

# ====================================
# CREATE CANDIDATE NOTES TABLE
# ====================================

cursor.execute("""
    CREATE TABLE candidate_notes (
        id SERIAL PRIMARY KEY,
        candidate_id INTEGER REFERENCES candidates(id)
            ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

print("✅ candidate_notes table created")

# ====================================
# CREATE DEFAULT ADMIN USER
# ====================================

admin_password = "admin123"
hashed = bcrypt.hashpw(
    admin_password.encode("utf-8"),
    bcrypt.gensalt()
).decode("utf-8")

cursor.execute("""
    INSERT INTO users
        (username, password_hash, full_name, role, email)
    VALUES (%s, %s, %s, %s, %s)
""", (
    "admin",
    hashed,
    "System Administrator",
    "admin",
    "admin@recruitment.com"
))

print("✅ Admin user created")

# ====================================
# INSERT SAMPLE JOBS
# ====================================

sample_jobs = [
    (
        "Poland", "Construction Worker",
        "€1,200 - €1,800/month",
        "Physical fitness, basic tools knowledge"
    ),
    (
        "Poland", "Factory Worker",
        "€1,100 - €1,500/month",
        "Shift work flexibility"
    ),
    (
        "Poland", "Truck Driver",
        "€1,500 - €2,200/month",
        "Valid driving license, 2+ years experience"
    ),
    (
        "Saudi Arabia", "Electrician",
        "SAR 3,000 - 5,000/month",
        "Certified electrician, 3+ years"
    ),
    (
        "Saudi Arabia", "Plumber",
        "SAR 2,500 - 4,000/month",
        "2+ years experience"
    ),
    (
        "Germany", "Warehouse Worker",
        "€1,400 - €1,800/month",
        "Basic German preferred"
    ),
    (
        "Czech Republic", "Welder",
        "€1,300 - €1,700/month",
        "Welding certification required"
    ),
]

for job in sample_jobs:
    cursor.execute(
        "INSERT INTO jobs "
        "(country, position, salary, requirements) "
        "VALUES (%s, %s, %s, %s)",
        job
    )

print(f"✅ {len(sample_jobs)} sample jobs inserted")

# ====================================
# COMMIT AND CLOSE
# ====================================

conn.commit()
cursor.close()
conn.close()

print("")
print("=" * 50)
print("🎉 DATABASE SETUP COMPLETE!")
print("=" * 50)
print("")
print("📌 Login Credentials:")
print(f"   Username: admin")
print(f"   Password: {admin_password}")
print("")
print("📌 Change the password after first login!")
print("")
print("Now run: uvicorn app:app --reload")
print("Then go to: http://localhost:8000")