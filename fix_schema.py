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

# Add is_deleted to jobs if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'jobs' AND column_name = 'is_deleted'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE jobs ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE"
    )
    print("✅ Added is_deleted to jobs")
else:
    print("✅ is_deleted already exists")

# Add full_name to candidates if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'candidates' AND column_name = 'full_name'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE candidates ADD COLUMN full_name VARCHAR(200)"
    )
    print("✅ Added full_name to candidates")
else:
    print("✅ full_name already exists")

# Add full_name to conversation_state if missing
cursor.execute("""
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'conversation_state' AND column_name = 'full_name'
""")
if not cursor.fetchone():
    cursor.execute(
        "ALTER TABLE conversation_state ADD COLUMN full_name VARCHAR(200)"
    )
    print("✅ Added full_name to conversation_state")
else:
    print("✅ conversation_state full_name exists")

conn.commit()
cursor.close()
conn.close()
print("🎉 Schema fix complete!")