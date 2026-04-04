#!/bin/bash
python setup_db.py
python migrate_settings.py
python fix_schema.py
uvicorn app:app --host 0.0.0.0 --port $PORT