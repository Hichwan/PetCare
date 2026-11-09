import csv
import os
import sqlite3
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PETCARE_DB_PATH", BASE_DIR / "data" / "petcare.db"))

CATEGORIES = (
    "Feeding",
    "Medication",
    "Vaccination",
    "Vet Visit",
    "Grooming",
    "Weight",
    "Other",
)
STATUSES = ("Open", "Completed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cat (
    cat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    breed TEXT,
    birthday DATE,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS care_record (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cat_id INTEGER NOT NULL REFERENCES cat(cat_id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    task TEXT NOT NULL,
    record_date DATE NOT NULL,
    next_due DATE,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'Completed'))
);

CREATE INDEX IF NOT EXISTS idx_cat_name ON cat(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_care_record_cat_date
    ON care_record(cat_id, record_date DESC);
CREATE INDEX IF NOT EXISTS idx_care_record_due
    ON care_record(status, next_due);
"""

RECORD_SELECT = """
SELECT r.record_id, r.cat_id, c.name AS cat_name, r.category,
       r.task, r.record_date, r.next_due, r.notes, r.status
FROM care_record AS r
JOIN cat AS c ON c.cat_id = r.cat_id
"""


class ValidationError(ValueError):
    pass


class NotFoundError(LookupError):
    pass


def get_connection():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with closing(get_connection()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def _required_text(value, field, maximum):
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.")
    value = value.strip()
    if not value:
        raise ValidationError(f"{field} is required.")
    if len(value) > maximum:
        raise ValidationError(f"{field} must be {maximum} characters or fewer.")
    return value


def _optional_text(value, field, maximum):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.")
    value = value.strip()
    if len(value) > maximum:
        raise ValidationError(f"{field} must be {maximum} characters or fewer.")
    return value or None


def _date(value, field, required=False):
    if value is None or value == "":
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if not isinstance(value, str):
        raise ValidationError(f"{field} must use YYYY-MM-DD.")
    value = value.strip()
    if not value:
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValidationError(f"{field} must be a valid date in YYYY-MM-DD format.") from exc
    if parsed.isoformat() != value:
        raise ValidationError(f"{field} must use YYYY-MM-DD.")
    return value


def _id(value, field):
    if isinstance(value, bool):
        raise ValidationError(f"{field} must be a positive integer.")
    try:
        converted = int(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValidationError(f"{field} must be a positive integer.") from exc
    if converted <= 0 or str(value).strip() not in (str(converted),):
        raise ValidationError(f"{field} must be a positive integer.")
    return converted


def _cat_fields(name, breed, birthday, notes):
    cleaned_birthday = _date(birthday, "Birthday")
    if cleaned_birthday and cleaned_birthday > date.today().isoformat():
        raise ValidationError("Birthday cannot be in the future.")
    return (
        _required_text(name, "Name", 120),
        _optional_text(breed, "Breed", 120),
        cleaned_birthday,
        _optional_text(notes, "Notes", 5000),
    )


def _record_fields(cat_id, category, task, record_date, next_due, notes):
    cat_id = _id(cat_id, "Cat ID")
    category = _required_text(category, "Category", 40)
    if category not in CATEGORIES:
        raise ValidationError("Category must be one of the supported care categories.")
    task = _required_text(task, "Task", 250)
    record_date = _date(record_date, "Record date", required=True)
    next_due = _date(next_due, "Next due")
    if next_due is not None and next_due < record_date:
        raise ValidationError("Next due cannot be before the record date.")
    return cat_id, category, task, record_date, next_due, _optional_text(notes, "Notes", 5000)


def _ensure_exists(conn, table, id_field, item_id, title):
    row = conn.execute(
        f"SELECT 1 FROM {table} WHERE {id_field} = ?", (item_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"{title} was not found.")


def list_cats():
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT cat_id, name, breed, birthday, notes FROM cat "
            "ORDER BY name COLLATE NOCASE, cat_id"
        ).fetchall()


def get_cat(cat_id):
    cat_id = _id(cat_id, "Cat ID")
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT cat_id, name, breed, birthday, notes FROM cat WHERE cat_id = ?",
            (cat_id,),
        ).fetchone()


def add_cat(name, breed=None, birthday=None, notes=None):
    fields = _cat_fields(name, breed, birthday, notes)
    with closing(get_connection()) as conn:
        with conn:
            return conn.execute(
                "INSERT INTO cat (name, breed, birthday, notes) VALUES (?, ?, ?, ?)",
                fields,
            ).lastrowid


def update_cat(cat_id, name, breed=None, birthday=None, notes=None):
    cat_id = _id(cat_id, "Cat ID")
    fields = _cat_fields(name, breed, birthday, notes)
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE cat SET name = ?, breed = ?, birthday = ?, notes = ? "
                "WHERE cat_id = ?",
                (*fields, cat_id),
            )
            if not cursor.rowcount:
                raise NotFoundError("Cat was not found.")
    return cat_id


def delete_cat(cat_id):
    cat_id = _id(cat_id, "Cat ID")
    with closing(get_connection()) as conn:
        with conn:
            return bool(conn.execute(
                "DELETE FROM cat WHERE cat_id = ?", (cat_id,)
            ).rowcount)


def list_records(cat_id=None, category=None, status=None, due_before=None):
    filters = []
    params = []
    if cat_id is not None:
        filters.append("r.cat_id = ?")
        params.append(_id(cat_id, "Cat ID"))
    if category is not None:
        if category not in CATEGORIES:
            raise ValidationError("Category must be one of the supported care categories.")
        filters.append("r.category = ?")
        params.append(category)
    if status is not None:
        if status not in STATUSES:
            raise ValidationError("Status must be Open or Completed.")
        filters.append("r.status = ?")
        params.append(status)
    if due_before is not None:
        filters.append("r.next_due <= ?")
        params.append(_date(due_before, "Due before", required=True))
    where = " WHERE " + " AND ".join(filters) if filters else ""
    with closing(get_connection()) as conn:
        return conn.execute(
            RECORD_SELECT + where + " ORDER BY r.record_date DESC, r.record_id DESC",
            params,
        ).fetchall()


def get_record(record_id):
    record_id = _id(record_id, "Record ID")
    with closing(get_connection()) as conn:
        return conn.execute(
            RECORD_SELECT + " WHERE r.record_id = ?", (record_id,)
        ).fetchone()


def add_record(cat_id, category, task, record_date, next_due=None, notes=None):
    fields = _record_fields(cat_id, category, task, record_date, next_due, notes)
    with closing(get_connection()) as conn:
        with conn:
            _ensure_exists(conn, "cat", "cat_id", fields[0], "Cat")
            return conn.execute(
                "INSERT INTO care_record "
                "(cat_id, category, task, record_date, next_due, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                fields,
            ).lastrowid


def update_record(record_id, cat_id, category, task, record_date,
                  next_due=None, notes=None):
    record_id = _id(record_id, "Record ID")
    fields = _record_fields(cat_id, category, task, record_date, next_due, notes)
    with closing(get_connection()) as conn:
        with conn:
            _ensure_exists(conn, "cat", "cat_id", fields[0], "Cat")
            cursor = conn.execute(
                "UPDATE care_record SET cat_id = ?, category = ?, task = ?, "
                "record_date = ?, next_due = ?, notes = ? WHERE record_id = ?",
                (*fields, record_id),
            )
            if not cursor.rowcount:
                raise NotFoundError("Care record was not found.")
    return record_id


def set_record_status(record_id, status):
    record_id = _id(record_id, "Record ID")
    if status not in STATUSES:
        raise ValidationError("Status must be Open or Completed.")
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE care_record SET status = ? WHERE record_id = ?",
                (status, record_id),
            )
            if not cursor.rowcount:
                raise NotFoundError("Care record was not found.")
    return status


def toggle_record_status(record_id):
    record_id = _id(record_id, "Record ID")
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE care_record SET status = "
                "CASE status WHEN 'Open' THEN 'Completed' ELSE 'Open' END "
                "WHERE record_id = ?",
                (record_id,),
            )
            if not cursor.rowcount:
                raise NotFoundError("Care record was not found.")
            return conn.execute(
                "SELECT status FROM care_record WHERE record_id = ?",
                (record_id,),
            ).fetchone()["status"]


def delete_record(record_id):
    record_id = _id(record_id, "Record ID")
    with closing(get_connection()) as conn:
        with conn:
            return bool(conn.execute(
                "DELETE FROM care_record WHERE record_id = ?", (record_id,)
            ).rowcount)


def get_due_records(on_date=None):
    today = _date(on_date, "On date", required=True) if on_date is not None else date.today().isoformat()
    with closing(get_connection()) as conn:
        return conn.execute(
            RECORD_SELECT + " WHERE r.status = 'Open' AND r.next_due <= ? "
            "ORDER BY r.next_due ASC, r.record_id ASC",
            (today,),
        ).fetchall()


def get_upcoming_records(days=7, on_date=None):
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= 3650:
        raise ValidationError("Days must be a whole number from 0 to 3650.")
    start = _date(on_date, "On date", required=True) if on_date is not None else date.today().isoformat()
    end = (date.fromisoformat(start) + timedelta(days=days)).isoformat()
    with closing(get_connection()) as conn:
        return conn.execute(
            RECORD_SELECT + " WHERE r.status = 'Open' "
            "AND r.next_due BETWEEN ? AND ? "
            "ORDER BY r.next_due ASC, r.record_id ASC",
            (start, end),
        ).fetchall()


def get_dashboard_stats(on_date=None):
    today = _date(on_date, "On date", required=True) if on_date is not None else date.today().isoformat()
    with closing(get_connection()) as conn:
        cat_count = conn.execute("SELECT COUNT(*) FROM cat").fetchone()[0]
        record_count = conn.execute("SELECT COUNT(*) FROM care_record").fetchone()[0]
        due_count = conn.execute(
            "SELECT COUNT(*) FROM care_record "
            "WHERE status = 'Open' AND next_due <= ?",
            (today,),
        ).fetchone()[0]
    return {"profiles": cat_count, "records": record_count, "due": due_count}


def export_records_csv(destination):
    destination = Path(destination).expanduser().resolve()
    if destination == Path(DB_PATH).expanduser().resolve():
        raise ValidationError("Export destination must differ from the database path.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "record_id", "cat_id", "cat_name", "category", "task",
        "record_date", "next_due", "notes", "status",
    )
    rows = list_records()
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(row))
    return destination


def backup_database(destination):
    source = Path(DB_PATH).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if source == destination:
        raise ValidationError("Backup destination must differ from the database path.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(get_connection()) as original:
        with closing(sqlite3.connect(str(destination))) as backup:
            original.backup(backup)
    return destination


def seed_sample_data():
    with closing(get_connection()) as conn:
        if conn.execute("SELECT COUNT(*) FROM cat").fetchone()[0]:
            return
    luna = add_cat("Luna", "Tabby", "2024-09-03")
    milo = add_cat("Milo", "Domestic Shorthair", "2025-05-12")
    today = date.today()
    examples = (
        (luna, "Feeding", "Evening feeding", 0, 1),
        (milo, "Feeding", "Morning feeding", 0, 1),
        (milo, "Grooming", "Brush coat", -3, 3),
        (milo, "Weight", "Monthly weigh-in", -15, 15),
        (milo, "Medication", "Monthly flea prevention", -31, 0),
        (luna, "Vaccination", "Annual vaccination", -330, 35),
        (luna, "Vet Visit", "Wellness checkup", -365, -1),
    )
    for cat_id, category, task, record_offset, next_due_offset in examples:
        add_record(
            cat_id, category, task,
            today + timedelta(days=record_offset),
            today + timedelta(days=next_due_offset),
        )
