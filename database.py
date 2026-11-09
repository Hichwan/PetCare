import os
import sqlite3
from contextlib import closing
from datetime import date, timedelta

# The database always lives in a "data" folder next to this file,
# no matter where you run the app from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "petcare.db")

CATEGORIES = ["Feeding", "Medication", "Vaccination", "Vet Visit",
              "Grooming", "Weight", "Other"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS cat (
    cat_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    breed    TEXT,
    birthday DATE,
    notes    TEXT
);

CREATE TABLE IF NOT EXISTS care_record (
    record_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    cat_id      INTEGER NOT NULL REFERENCES cat(cat_id) ON DELETE CASCADE,
    category    TEXT NOT NULL,
    task        TEXT NOT NULL,
    record_date DATE NOT NULL,
    next_due    DATE,
    notes       TEXT,
    status      TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'Completed'))
);
"""


# ---------- Connection and setup ----------
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row            # lets you use row["name"]
    conn.execute("PRAGMA foreign_keys = ON")  # must be set on every connection
    return conn


def init_db():
    """Create the data folder and tables (safe to run on every launch)."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(get_connection()) as conn:
        conn.executescript(SCHEMA)


def seed_sample_data():
    """Insert demo cats and records, but only if there are no cats yet."""
    with closing(get_connection()) as conn:
        if conn.execute("SELECT COUNT(*) FROM cat").fetchone()[0] > 0:
            return
        with conn:
            luna = conn.execute(
                "INSERT INTO cat (name, breed, birthday) VALUES (?, ?, ?)",
                ("Luna", "Tabby", "2024-09-03")).lastrowid
            milo = conn.execute(
                "INSERT INTO cat (name, breed, birthday) VALUES (?, ?, ?)",
                ("Milo", "Domestic Shorthair", "2025-05-12")).lastrowid

            today = date.today()

            def d(offset):
                return (today + timedelta(days=offset)).isoformat()

            records = [
                # cat, category, task, date, next due
                (luna, "Feeding", "Evening feeding", d(0), d(1)),
                (milo, "Feeding", "Morning feeding", d(0), d(1)),
                (milo, "Grooming", "Brush coat", d(-3), d(3)),
                (milo, "Weight", "Monthly weigh-in", d(-15), d(15)),
                (milo, "Medication", "Monthly flea prevention", d(-31), d(0)),
                (luna, "Vaccination", "Annual vaccination", d(-330), d(35)),
                (luna, "Vet Visit", "Wellness checkup", d(-365), d(-1)),
            ]
            conn.executemany(
                "INSERT INTO care_record "
                "(cat_id, category, task, record_date, next_due) "
                "VALUES (?, ?, ?, ?, ?)", records)


# ---------- Cats ----------
def list_cats():
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT * FROM cat ORDER BY name COLLATE NOCASE").fetchall()


def get_cat(cat_id):
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT * FROM cat WHERE cat_id = ?", (cat_id,)).fetchone()


def add_cat(name, breed, birthday, notes):
    with closing(get_connection()) as conn:
        with conn:
            return conn.execute(
                "INSERT INTO cat (name, breed, birthday, notes) VALUES (?, ?, ?, ?)",
                (name, breed, birthday, notes)).lastrowid


def update_cat(cat_id, name, breed, birthday, notes):
    with closing(get_connection()) as conn:
        with conn:
            conn.execute(
                "UPDATE cat SET name = ?, breed = ?, birthday = ?, notes = ? "
                "WHERE cat_id = ?",
                (name, breed, birthday, notes, cat_id))


def delete_cat(cat_id):
    """Also deletes the cat's care records (ON DELETE CASCADE)."""
    with closing(get_connection()) as conn:
        with conn:
            conn.execute("DELETE FROM cat WHERE cat_id = ?", (cat_id,))


# ---------- Care records ----------
def list_records():
    with closing(get_connection()) as conn:
        return conn.execute("""
            SELECT r.record_id, r.cat_id, c.name AS cat_name, r.category,
                   r.task, r.record_date, r.next_due, r.notes, r.status
            FROM care_record r
            JOIN cat c ON c.cat_id = r.cat_id
            ORDER BY r.record_date DESC, r.record_id
        """).fetchall()


def add_record(cat_id, category, task, record_date, next_due, notes):
    with closing(get_connection()) as conn:
        with conn:
            return conn.execute(
                "INSERT INTO care_record "
                "(cat_id, category, task, record_date, next_due, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (cat_id, category, task, record_date, next_due, notes)).lastrowid


def toggle_record_status(record_id):
    """Open -> Completed, Completed -> Open."""
    with closing(get_connection()) as conn:
        with conn:
            conn.execute(
                "UPDATE care_record SET status = "
                "CASE status WHEN 'Open' THEN 'Completed' ELSE 'Open' END "
                "WHERE record_id = ?", (record_id,))


def delete_record(record_id):
    with closing(get_connection()) as conn:
        with conn:
            conn.execute("DELETE FROM care_record WHERE record_id = ?", (record_id,))
