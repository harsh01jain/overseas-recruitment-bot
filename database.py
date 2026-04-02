import psycopg2

conn = psycopg2.connect(
    host="localhost",
    database="overseas_bot3",
    user="postgres",
    password="root"
)

cursor = conn.cursor()