"""Cat Care / Health Tracker

Keep this file next to your existing database.py; do not delete data/petcare.db.
Run using the Python interpreter that displayed Tkinter successfully, e.g.:
    python3.14 PetManagementApp_Combined.py

Account data, cats and care records share data/petcare.db. This upgrade
adds an app_user table and a nullable owner_id column to cat on first run.
Accounts are local to this computer; the SQLite database is not encrypted.
"""

import csv
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import sys
import tkinter as tk
import calendar
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont
from types import SimpleNamespace

import database as db


# ---------- ACCOUNTS AND USER-SCOPED DATABASE OPERATIONS ----------
ITERATIONS = 420_000
USERNAME_PATTERN = re.compile(r"[a-zA-Z0-9_.-]{3,32}\Z")


class AccountError(ValueError):
    """Expected account/credential error displayed to the user."""


class OwnershipError(AccountError):
    """A resource cannot be found within the signed-in account."""


def _user_id(value):
    if type(value) is not int or value <= 0:
        raise AccountError("Please sign in again.")
    return value


def _positive_id(value, field):
    if type(value) is not int or value <= 0:
        raise AccountError(f"Invalid {field}.")
    return value


def _username(value):
    if not isinstance(value, str):
        raise AccountError("Enter a username.")
    value = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(value):
        raise AccountError("Username must be 3–32 characters: letters, numbers, _, . or -.")
    return value


def _password(value, *, registering=False):
    if not isinstance(value, str) or not value:
        raise AccountError("Enter your password.")
    if registering and not 8 <= len(value) <= 256:
        raise AccountError("Password must contain 8–256 characters.")
    return value


def _hash_password(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def init():
    """Initialize original tables, then add account ownership without erasing data."""
    db.init_db()
    with closing(db.get_connection()) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_user (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(cat)")}
            if "owner_id" not in columns:
                # Nullable by design, so legacy cats can be adopted explicitly.
                conn.execute("ALTER TABLE cat ADD COLUMN owner_id INTEGER "
                             "REFERENCES app_user(user_id) ON DELETE CASCADE")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cat_owner "
                         "ON cat(owner_id, name COLLATE NOCASE)")


def legacy_import_available():
    """Only before the first account exists, allow legacy cats to be adopted."""
    with closing(db.get_connection()) as conn:
        existing_users = conn.execute("SELECT COUNT(*) FROM app_user").fetchone()[0]
        old_cats = conn.execute(
            "SELECT COUNT(*) FROM cat WHERE owner_id IS NULL"
        ).fetchone()[0]
    return old_cats if existing_users == 0 else 0


def register(username, password, import_legacy=False):
    username = _username(username)
    password = _password(password, registering=True)
    salt = secrets.token_bytes(16)
    digest = _hash_password(password, salt, ITERATIONS)
    with closing(db.get_connection()) as conn:
        try:
            with conn:
                count = conn.execute("SELECT COUNT(*) FROM app_user").fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO app_user (username, password_hash, salt, iterations) "
                    "VALUES (?, ?, ?, ?)",
                    (username, digest.hex(), salt.hex(), ITERATIONS),
                )
                user_id = cur.lastrowid
                if import_legacy and count == 0:
                    conn.execute("UPDATE cat SET owner_id = ? WHERE owner_id IS NULL",
                                 (user_id,))
        except sqlite3.IntegrityError as exc:
            raise AccountError("That username is already taken.") from exc
    return {"user_id": user_id, "username": username}


def login(username, password):
    username = _username(username)
    password = _password(password)
    with closing(db.get_connection()) as conn:
        row = conn.execute(
            "SELECT user_id, username, password_hash, salt, iterations "
            "FROM app_user WHERE username = ?", (username,)
        ).fetchone()
    # Do not identify which part of the login was incorrect.
    if row is None:
        raise AccountError("Incorrect username or password.")
    actual = _hash_password(password, bytes.fromhex(row["salt"]), row["iterations"])
    if not hmac.compare_digest(actual, bytes.fromhex(row["password_hash"])):
        raise AccountError("Incorrect username or password.")
    return {"user_id": row["user_id"], "username": row["username"]}


def _verify_password(conn, user_id, password):
    password = _password(password)
    row = conn.execute(
        "SELECT password_hash, salt, iterations FROM app_user WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        raise AccountError("Account not found.")
    result = _hash_password(password, bytes.fromhex(row["salt"]), row["iterations"])
    if not hmac.compare_digest(result, bytes.fromhex(row["password_hash"])):
        raise AccountError("Incorrect password; account was not deleted.")


def delete_account(user_id, password):
    """Delete only this user and their cats/records, after password verification."""
    user_id = _user_id(user_id)
    with closing(db.get_connection()) as conn:
        with conn:
            _verify_password(conn, user_id, password)
            conn.execute("DELETE FROM care_record WHERE cat_id IN "
                         "(SELECT cat_id FROM cat WHERE owner_id = ?)", (user_id,))
            conn.execute("DELETE FROM cat WHERE owner_id = ?", (user_id,))
            conn.execute("DELETE FROM app_user WHERE user_id = ?", (user_id,))


def list_cats(user_id):
    user_id = _user_id(user_id)
    with closing(db.get_connection()) as conn:
        return conn.execute("""
            SELECT c.cat_id, c.name, c.breed, c.birthday, c.notes,
                   COUNT(r.record_id) AS record_count,
                   COALESCE(SUM(CASE WHEN r.status = 'Open' THEN 1 ELSE 0 END), 0) AS open_count,
                   COALESCE(SUM(CASE WHEN r.status = 'Open' AND r.next_due <= ?
                            THEN 1 ELSE 0 END), 0) AS due_count
            FROM cat c
            LEFT JOIN care_record r ON r.cat_id = c.cat_id
            WHERE c.owner_id = ?
            GROUP BY c.cat_id
            ORDER BY c.name COLLATE NOCASE, c.cat_id
        """, (date.today().isoformat(), user_id)).fetchall()


def get_cat(user_id, cat_id):
    user_id, cat_id = _user_id(user_id), _positive_id(cat_id, "cat ID")
    with closing(db.get_connection()) as conn:
        cat = conn.execute(
            "SELECT cat_id, name, breed, birthday, notes FROM cat "
            "WHERE cat_id = ? AND owner_id = ?", (cat_id, user_id)
        ).fetchone()
    if cat is None:
        raise OwnershipError("Cat not found in your account.")
    return cat


def _owned_cat(conn, user_id, cat_id):
    found = conn.execute("SELECT 1 FROM cat WHERE cat_id = ? AND owner_id = ?",
                         (cat_id, user_id)).fetchone()
    if found is None:
        raise OwnershipError("Cat not found in your account.")


def add_cat(user_id, name, breed=None, birthday=None, notes=None):
    user_id = _user_id(user_id)
    fields = db._cat_fields(name, breed, birthday, notes)
    with closing(db.get_connection()) as conn:
        with conn:
            return conn.execute(
                "INSERT INTO cat (name, breed, birthday, notes, owner_id) "
                "VALUES (?, ?, ?, ?, ?)", (*fields, user_id)
            ).lastrowid


def update_cat(user_id, cat_id, name, breed=None, birthday=None, notes=None):
    user_id, cat_id = _user_id(user_id), _positive_id(cat_id, "cat ID")
    fields = db._cat_fields(name, breed, birthday, notes)
    with closing(db.get_connection()) as conn:
        with conn:
            updated = conn.execute(
                "UPDATE cat SET name = ?, breed = ?, birthday = ?, notes = ? "
                "WHERE cat_id = ? AND owner_id = ?", (*fields, cat_id, user_id)
            ).rowcount
            if not updated:
                raise OwnershipError("Cat not found in your account.")
    return cat_id


def delete_cat(user_id, cat_id):
    user_id, cat_id = _user_id(user_id), _positive_id(cat_id, "cat ID")
    with closing(db.get_connection()) as conn:
        with conn:
            deleted = conn.execute(
                "DELETE FROM cat WHERE cat_id = ? AND owner_id = ?",
                (cat_id, user_id),
            ).rowcount
            if not deleted:
                raise OwnershipError("Cat not found in your account.")


def list_records(user_id, cat_id=None):
    user_id = _user_id(user_id)
    params = [user_id]
    filter_cat = ""
    if cat_id is not None:
        cat_id = _positive_id(cat_id, "cat ID")
        filter_cat = " AND r.cat_id = ?"
        params.append(cat_id)
    with closing(db.get_connection()) as conn:
        return conn.execute("""
            SELECT r.record_id, r.cat_id, c.name AS cat_name,
                   r.category, r.task, r.record_date, r.next_due,
                   r.notes, r.status
            FROM care_record r
            JOIN cat c ON c.cat_id = r.cat_id
            WHERE c.owner_id = ?
        """ + filter_cat + " ORDER BY r.record_date DESC, r.record_id DESC",
            params).fetchall()


def get_record(user_id, record_id):
    user_id, record_id = _user_id(user_id), _positive_id(record_id, "record ID")
    with closing(db.get_connection()) as conn:
        row = conn.execute("""
            SELECT r.record_id, r.cat_id, c.name AS cat_name, r.category,
                   r.task, r.record_date, r.next_due, r.notes, r.status
            FROM care_record r JOIN cat c ON c.cat_id = r.cat_id
            WHERE r.record_id = ? AND c.owner_id = ?
        """, (record_id, user_id)).fetchone()
    if row is None:
        raise OwnershipError("Care record not found in your account.")
    return row


def add_record(user_id, cat_id, category, task, record_date, next_due=None, notes=None):
    user_id = _user_id(user_id)
    fields = db._record_fields(cat_id, category, task, record_date, next_due, notes)
    with closing(db.get_connection()) as conn:
        with conn:
            _owned_cat(conn, user_id, fields[0])
            return conn.execute(
                "INSERT INTO care_record (cat_id, category, task, record_date, next_due, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)", fields
            ).lastrowid


def update_record(user_id, record_id, cat_id, category, task,
                  record_date, next_due=None, notes=None):
    user_id, record_id = _user_id(user_id), _positive_id(record_id, "record ID")
    fields = db._record_fields(cat_id, category, task, record_date, next_due, notes)
    with closing(db.get_connection()) as conn:
        with conn:
            _owned_cat(conn, user_id, fields[0])
            updated = conn.execute("""
                UPDATE care_record SET cat_id = ?, category = ?, task = ?,
                                       record_date = ?, next_due = ?, notes = ?
                WHERE record_id = ? AND cat_id IN
                      (SELECT cat_id FROM cat WHERE owner_id = ?)
            """, (*fields, record_id, user_id)).rowcount
            if not updated:
                raise OwnershipError("Care record not found in your account.")
    return record_id


def toggle_record_status(user_id, record_id):
    user_id, record_id = _user_id(user_id), _positive_id(record_id, "record ID")
    with closing(db.get_connection()) as conn:
        with conn:
            updated = conn.execute("""
                UPDATE care_record SET status =
                    CASE WHEN status = 'Open' THEN 'Completed' ELSE 'Open' END
                WHERE record_id = ? AND cat_id IN
                      (SELECT cat_id FROM cat WHERE owner_id = ?)
            """, (record_id, user_id)).rowcount
            if not updated:
                raise OwnershipError("Care record not found in your account.")


def delete_record(user_id, record_id):
    user_id, record_id = _user_id(user_id), _positive_id(record_id, "record ID")
    with closing(db.get_connection()) as conn:
        with conn:
            updated = conn.execute("""
                DELETE FROM care_record
                WHERE record_id = ? AND cat_id IN
                      (SELECT cat_id FROM cat WHERE owner_id = ?)
            """, (record_id, user_id)).rowcount
            if not updated:
                raise OwnershipError("Care record not found in your account.")


def dashboard_stats(user_id):
    user_id = _user_id(user_id)
    with closing(db.get_connection()) as conn:
        cats = conn.execute(
            "SELECT COUNT(*) FROM cat WHERE owner_id = ?", (user_id,)
        ).fetchone()[0]
        stats = conn.execute("""
            SELECT COUNT(*) AS all_records,
                   SUM(CASE WHEN r.status = 'Open' AND r.next_due <= ?
                            THEN 1 ELSE 0 END) AS due_count
            FROM care_record r JOIN cat c ON c.cat_id = r.cat_id
            WHERE c.owner_id = ?
        """, (date.today().isoformat(), user_id)).fetchone()
        return {"cats": cats, "records": stats["all_records"],
                "due": stats["due_count"] or 0}


def due_records(user_id):
    user_id = _user_id(user_id)
    with closing(db.get_connection()) as conn:
        return conn.execute("""
            SELECT r.record_id, r.cat_id, c.name AS cat_name, r.category,
                   r.task, r.record_date, r.next_due, r.notes, r.status
            FROM care_record r JOIN cat c ON c.cat_id = r.cat_id
            WHERE c.owner_id = ? AND r.status = 'Open' AND r.next_due <= ?
            ORDER BY r.next_due, r.record_id
        """, (user_id, date.today().isoformat())).fetchall()

def records_on_date(user_id, day):
    """All of this account's tasks that belong to one day (due date, else record date)."""
    user_id = _user_id(user_id)
    with closing(db.get_connection()) as conn:
        return conn.execute("""
            SELECT r.record_id, r.cat_id, c.name AS cat_name, r.category,
                   r.task, r.record_date, r.next_due, r.notes, r.status
            FROM care_record r JOIN cat c ON c.cat_id = r.cat_id
            WHERE c.owner_id = ?
              AND COALESCE(NULLIF(r.next_due, ''), r.record_date) = ?
            ORDER BY c.name COLLATE NOCASE, r.task COLLATE NOCASE
        """, (user_id, day.isoformat())).fetchall()


def task_counts(user_id, year, month):
    """{'YYYY-MM-DD': (total, open)} for one month, used by the popup calendar."""
    user_id = _user_id(user_id)
    start = date(year, month, 1)
    end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    with closing(db.get_connection()) as conn:
        rows = conn.execute("""
            SELECT COALESCE(NULLIF(r.next_due, ''), r.record_date) AS day,
                   COUNT(*) AS total,
                   SUM(CASE WHEN r.status = 'Open' THEN 1 ELSE 0 END) AS open_count
            FROM care_record r JOIN cat c ON c.cat_id = r.cat_id
            WHERE c.owner_id = ? AND day >= ? AND day < ?
            GROUP BY day
        """, (user_id, start.isoformat(), end.isoformat())).fetchall()
    return {row["day"]: (row["total"], row["open_count"] or 0) for row in rows}



def _check_export_destination(destination):
    destination = Path(destination).expanduser().resolve()
    if destination == Path(db.DB_PATH).expanduser().resolve():
        raise AccountError("Choose a destination other than the live petcare.db database.")
    return destination


def export_records_csv(user_id, destination):
    destination = _check_export_destination(destination)
    fields = ("cat_name", "category", "task", "record_date", "next_due",
              "notes", "status")
    rows = list_records(user_id)
    with open(destination, "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] or "" for key in fields})


def export_account_json(user_id, destination):
    """Personal data export; excludes every other account and passwords."""
    destination = _check_export_destination(destination)
    cats = list_cats(user_id)
    payload = {
        "format": "petcare-personal-export-v1",
        "exported_on": date.today().isoformat(),
        "cats": [{"name": c["name"], "breed": c["breed"],
                  "birthday": c["birthday"], "notes": c["notes"],
                  "records": [{key: r[key] for key in
                               ("category", "task", "record_date", "next_due", "notes", "status")}
                              for r in list_records(user_id, c["cat_id"])]}
                 for c in cats],
    }
    with open(destination, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False)

# Preserve a tidy interface between account/data functions and the UI.
# All account functions live in THIS file; account_store.py is not needed.
store = SimpleNamespace(
    AccountError=AccountError,
    OwnershipError=OwnershipError,
    init=init,
    legacy_import_available=legacy_import_available,
    register=register,
    login=login,
    delete_account=delete_account,
    list_cats=list_cats,
    get_cat=get_cat,
    add_cat=add_cat,
    update_cat=update_cat,
    delete_cat=delete_cat,
    list_records=list_records,
    get_record=get_record,
    add_record=add_record,
    update_record=update_record,
    toggle_record_status=toggle_record_status,
    delete_record=delete_record,
    dashboard_stats=dashboard_stats,
    due_records=due_records,
    records_on_date=records_on_date,
    task_counts=task_counts,
    export_records_csv=export_records_csv,
    export_account_json=export_account_json,
)


# ---------- TKINTER USER INTERFACE ----------
BLUE = "#4560d8"
BLUE_DARK = "#3449ad"
BG = "#f5f7fb"
WHITE = "#ffffff"
PALE_BLUE = "#e8edff"
TEXT = "#1e293b"
MUTED = "#64748b"
BORDER = "#dbe2ed"
RED = "#ba4055"
GREEN = "#1d806c"
ERRORS = (store.AccountError, db.ValidationError, db.NotFoundError, sqlite3.Error)

TASK_IDEAS = {
    "Feeding": ("Morning feeding", "Evening feeding", "Refill water", "Food portion check"),
    "Medication": ("Give medication", "Flea prevention", "Deworming"),
    "Vaccination": ("Schedule vaccination", "Vaccination appointment"),
    "Vet Visit": ("Schedule vet appointment", "Annual wellness exam"),
    "Grooming": ("Brush coat", "Trim nails", "Bath"),
    "Weight": ("Weigh cat", "Record weight"),
    "Other": ("Clean litter box", "Playtime", "Other care task"),
}


def task_attention_status(record, today=None):
    """User-facing status for a task; a completed task never counts as due."""
    today = today or date.today().isoformat()
    if record["status"] == "Completed":
        return "Completed"
    due = record["next_due"]
    if not due:
        return "No due date"
    if due < today:
        return "Overdue"
    if due == today:
        return "Due today"
    return "Upcoming"


def task_priority_key(record, today=None):
    """Order open tasks by urgency and put all completed tasks last.

    Priority: overdue, today, upcoming, no due date, completed.
    Due tasks sort oldest-first; completed tasks sort newest-first.
    """
    today = today or date.today().isoformat()
    bucket = task_attention_status(record, today)
    rank = {"Overdue": 0, "Due today": 1, "Upcoming": 2,
            "No due date": 3, "Completed": 4}[bucket]
    if bucket == "Completed":
        # Completed records go last, newest record first within that group.
        date_key = -date.fromisoformat(record["record_date"]).toordinal()
    else:
        # For open records, earlier due dates come first within each group.
        date_key = (date.fromisoformat(record["next_due"]).toordinal()
                    if record["next_due"] else 0)
    return (rank, date_key, record["task"].casefold(), record["record_id"])


def matches_status_filter(record, choice, today=None):
    """Match the filter chosen in a cat's task tab."""
    if choice in ("All", "All open"):
        return True
    if choice == "Open":
        return record["status"] == "Open"
    return task_attention_status(record, today) == choice


def button(parent, label, command, *, color=BLUE, text_color=WHITE, width=None):
    """Colored, rounded Canvas button with no native macOS text-overlay artifacts.

    The label is drawn directly onto the same Canvas as its background, avoiding
    the strikethrough-looking line seen on some older Aqua Tk combinations.
    Buttons keep their original colors and work by mouse, Return, and Space.
    """
    hover_colors = {
        BLUE: BLUE_DARK,
        GREEN: "#126250",
        PALE_BLUE: "#d3ddff",
        WHITE: "#e8edff",
        "#f8e2e6": "#efd0d7",
        "#f5e2e7": "#efd0d7",
        RED: "#983046",
    }
    hover_bg = hover_colors.get(color, color)
    button_font = tkfont.Font(root=parent, family="Arial", size=10, weight="bold")
    text_width = button_font.measure(label)
    if width is not None:
        text_width = max(text_width, button_font.measure("M") * width)
    pixel_width = max(70, text_width + 34)
    pixel_height = max(38, button_font.metrics("linespace") + 20)

    # Match the parent background to create genuinely rounded corners.
    try:
        parent_bg = parent.cget("background")
    except tk.TclError:
        parent_bg = BG
    control = tk.Canvas(
        parent, width=pixel_width, height=pixel_height,
        bg=parent_bg, bd=0, relief="flat", highlightthickness=0,
        cursor="hand2", takefocus=1,
    )

    def rounded_rect(x0, y0, x1, y1, radius, **kwargs):
        return control.create_polygon(
            x0 + radius, y0, x1 - radius, y0,
            x1, y0, x1, y0 + radius,
            x1, y1 - radius, x1, y1,
            x1 - radius, y1, x0 + radius, y1,
            x0, y1, x0, y1 - radius,
            x0, y0 + radius, x0, y0,
            smooth=True, splinesteps=20, **kwargs,
        )

    radius = 9
    base = rounded_rect(1, 1, pixel_width - 1, pixel_height - 1,
                        radius, fill=color, outline="")
    control.create_text(pixel_width / 2, pixel_height / 2,
                        text=label, fill=text_color, font=button_font,
                        anchor="center")
    focus_outline = rounded_rect(
        2, 2, pixel_width - 2, pixel_height - 2,
        radius, fill="", outline=BLUE_DARK, width=2, state="hidden",
    )
    # Tk keeps named fonts alive only when Python retains their Font instances.
    control._button_font = button_font

    def activate(event=None):
        control.focus_set()
        command()
        return "break"

    control.bind("<Button-1>", activate)
    control.bind("<Return>", activate)
    control.bind("<space>", activate)
    control.bind("<Enter>", lambda event: control.itemconfigure(base, fill=hover_bg))
    control.bind("<Leave>", lambda event: control.itemconfigure(base, fill=color))
    control.bind("<FocusIn>", lambda event: control.itemconfigure(focus_outline, state="normal"))
    control.bind("<FocusOut>", lambda event: control.itemconfigure(focus_outline, state="hidden"))
    return control


def label(parent, text, *, size=10, bold=False, fg=TEXT, bg=WHITE, **kwargs):
    return tk.Label(parent, text=text, fg=fg, bg=bg,
                    font=("Arial", size, "bold" if bold else "normal"),
                    **kwargs)


def entry(parent, *, show=None, width=30):
    return tk.Entry(parent, bg=WHITE, fg=TEXT, insertbackground=TEXT,
                    relief="solid", bd=1, highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=BLUE,
                    width=width, show=show, font=("Arial", 11))


def field(parent, title, row, *, value="", show=None):
    label(parent, title, bold=True).grid(row=row, column=0, sticky="w", pady=8, padx=(0, 12))
    box = entry(parent, show=show)
    box.grid(row=row, column=1, sticky="ew", pady=8, ipady=5)
    box.insert(0, "" if value is None else str(value))
    return box


def text_value(widget):
    return widget.get("1.0", "end-1c").strip()


def require_date(value, title, optional=False):
    value = value.strip()
    if not value and optional:
        return None
    if not value:
        raise ValueError(f"{title} is required.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{title} must be a valid YYYY-MM-DD date.") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{title} must use YYYY-MM-DD.")
    return value


def section(parent, heading, subtitle=None):
    label(parent, heading, size=18, bold=True, bg=BG).pack(anchor="w", pady=(6, 2))
    if subtitle:
        label(parent, subtitle, fg=MUTED, bg=BG).pack(anchor="w", pady=(0, 12))


def make_tree(parent, cols, widths):
    outer = tk.Frame(parent, bg=WHITE, highlightbackground=BORDER, highlightthickness=1)
    outer.rowconfigure(0, weight=1)
    outer.columnconfigure(0, weight=1)
    tree = ttk.Treeview(outer, columns=tuple(key for key, _ in cols),
                        show="headings", selectmode="browse")
    for (key, title), width in zip(cols, widths):
        tree.heading(key, text=title, anchor="w")
        tree.column(key, width=width, anchor="w", minwidth=70, stretch=True)
    vertical = ttk.Scrollbar(outer, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(outer, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    tree.tag_configure("done", foreground=GREEN)
    tree.tag_configure("overdue", foreground=RED)
    tree.tag_configure("today", foreground="#a35b0d")
    tree.tag_configure("upcoming", foreground=BLUE_DARK)
    tree.tag_configure("no_due", foreground=MUTED)
    return outer, tree


def mac_light_appearance(window):
    """Ask macOS Tk to render this window in light mode.

    Tk 9 uses Tcl's ``wm attributes -appearance aqua``.  This is deliberately
    called through Tcl rather than ``window.attributes(appearance=...)``, which
    older Python/Tkinter bindings (including some macOS builds) reject.
    """
    if sys.platform != "darwin":
        return
    try:
        window.tk.call("wm", "attributes", window._w, "-appearance", "aqua")
    except tk.TclError:
        # Tk 8.6 macOS fallback.  Do not fail startup if unavailable.
        try:
            window.tk.call("tk::unsupported::MacWindowStyle",
                           "appearance", window._w, "aqua")
        except tk.TclError:
            pass


class LightTabs(tk.Frame):
    """Light-themed tabbed pages without macOS's dark native notebook frame.

    Tk Labels draw the tab buttons and Tk Frames draw the content area. This
    keeps backgrounds the same pale color as the main window, even if macOS
    uses Dark Mode for native ttk.Notebook widgets.
    """

    def __init__(self, parent, *, surface=BG, tab_padding=14, font_size=10):
        super().__init__(parent, bg=surface, bd=0, highlightthickness=0)
        self.surface = surface
        self.tab_padding = tab_padding
        self.font_size = font_size
        self.tab_strip = tk.Frame(self, bg=surface)
        self.tab_strip.pack(fill="x", pady=(0, 8))
        self.content = tk.Frame(self, bg=surface, bd=0, highlightthickness=0)
        self.content.pack(fill="both", expand=True)
        self._tabs = {}
        self._selected = None

    def add(self, page, *, text):
        if page.master is not self.content:
            raise ValueError("Create tab pages inside LightTabs.content")
        tab = tk.Label(
            self.tab_strip, text=text, bg=WHITE, fg=BLUE_DARK,
            font=("Arial", self.font_size, "bold"),
            padx=self.tab_padding, pady=10,
            relief="flat", highlightthickness=1, highlightbackground=BORDER,
            cursor="hand2", takefocus=1,
        )
        tab.pack(side="left", padx=(0, 7))
        tab.bind("<Button-1>", lambda event, target=page: self.select(target))
        tab.bind("<Return>", lambda event, target=page: self.select(target))
        tab.bind("<space>", lambda event, target=page: self.select(target))
        tab.bind("<Enter>", lambda event, target=page: self._hover(target, True))
        tab.bind("<Leave>", lambda event, target=page: self._hover(target, False))
        self._tabs[page] = tab
        page.place(relx=0, rely=0, relwidth=1, relheight=1)
        # Newly placed pages appear above previous pages. Restore selection.
        self.select(self._selected if self._selected is not None else page)

    def _hover(self, page, entering):
        if page is not self._selected:
            self._tabs[page].configure(bg=PALE_BLUE if entering else WHITE)

    def select(self, page=None):
        """Switch tabs, or return the selected page when called without args."""
        if page is None:
            return self._selected
        if page not in self._tabs:
            raise ValueError("Unknown tab page")
        self._selected = page
        page.tkraise()
        for current, tab in self._tabs.items():
            active = current is page
            tab.configure(bg=BLUE if active else WHITE,
                          fg=WHITE if active else BLUE_DARK)
        return page


class PetCareApp:
    def __init__(self):
        store.init()  # Adds account tables/ownership without removing original petcare.db data.
        self.root = tk.Tk()
        self.root.title("Cat Care | Health Tracker")
        self.root.geometry("1100x760")
        self.root.minsize(820, 580)
        self.root.configure(bg=BG)
        mac_light_appearance(self.root)
        # Consistent light backgrounds, including with system Dark Mode.
        self.user = None
        self.shell = None
        self.cat_windows = {}
        self.dialogs = set()
        self.daily_window = None  # Separate, reopenable daily-task window
        self.calendar_window = None  # Independent, reopenable calendar popup
        self.day_windows = {}

        style = ttk.Style(self.root)
        # The native Aqua theme is the most reliable choice on macOS.
        # Other platforms keep the cross-platform Clam theme.
        if sys.platform == "darwin" and "aqua" in style.theme_names():
            style.theme_use("aqua")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 9),
                        font=("Arial", 10, "bold"))
        style.map("TNotebook.Tab", foreground=[("selected", BLUE)])
        style.configure("Treeview", font=("Arial", 10), rowheight=28,
                        background=WHITE, fieldbackground=WHITE, foreground=TEXT)
        style.map("Treeview", background=[("selected", BLUE)],
                  foreground=[("selected", WHITE)])
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"),
                        background=PALE_BLUE, foreground=TEXT, padding=6)
        style.configure("TCombobox", padding=5)
        print("Cat Care version: 2.6 (auto calendar + light tabs + search)", flush=True)
        print("Running Python:", sys.version.split()[0], sys.executable, flush=True)
        print("Running Tcl/Tk:", self.root.tk.call("info", "patchlevel"), flush=True)
        self.show_auth()

    @property
    def uid(self):
        return self.user["user_id"]

    def new_shell(self):
        if self.shell is not None:
            self.shell.destroy()
        self.shell = tk.Frame(self.root, bg=BG)
        self.shell.pack(fill="both", expand=True)
        return self.shell

    def track_dialog(self, window):
        self.dialogs.add(window)
        window.bind("<Destroy>",
                    lambda event: self.dialogs.discard(window)
                    if event.widget is window else None, add="+")

    def show_auth(self, register=False):
        """Render the account form using native ttk controls.

        On macOS, mixing explicitly colored classic Tk inputs with native
        Aqua controls can result in invisible fields or stale button drawings.
        The entire authentication screen uses one ttk-managed form.
        """
        self.user = None
        self.root.config(menu="")
        if self.shell is not None:
            self.shell.destroy()

        self.shell = ttk.Frame(self.root, padding=20)
        self.shell.pack(fill="both", expand=True)
        self.shell.columnconfigure(0, weight=1)
        self.shell.rowconfigure(0, weight=1)

        card = ttk.Frame(self.shell, padding=(35, 25))
        card.grid(row=0, column=0, padx=20, pady=20)
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="CAT CARE | HEALTH TRACKER",
                  font=("Arial", 20, "bold")).grid(
                      row=0, column=0, sticky="w", pady=(0, 9))
        ttk.Label(card, text="Your cats, routines and reminders in one place.",
                  font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=(0, 25))

        title = ttk.Label(card, text="Welcome back", font=("Arial", 16, "bold"))
        title.grid(row=2, column=0, sticky="w", pady=(0, 16))

        ttk.Label(card, text="Username").grid(row=3, column=0, sticky="w")
        username_box = ttk.Entry(card, width=36, font=("Arial", 12))
        username_box.grid(row=4, column=0, sticky="ew", pady=(4, 15), ipady=5)

        ttk.Label(card, text="Password").grid(row=5, column=0, sticky="w")
        password_box = ttk.Entry(card, width=36, show="*", font=("Arial", 12))
        password_box.grid(row=6, column=0, sticky="ew", pady=(4, 15), ipady=5)

        confirm_label = ttk.Label(card, text="Confirm password")
        confirm_label.grid(row=7, column=0, sticky="w")
        confirm_box = ttk.Entry(card, width=36, show="*", font=("Arial", 12))
        confirm_box.grid(row=8, column=0, sticky="ew", pady=(4, 15), ipady=5)

        hint = ttk.Label(card, text="", wraplength=350, font=("Arial", 10))
        hint.grid(row=9, column=0, sticky="w", pady=(0, 13))

        error_text = tk.StringVar(value="")
        error_label = ttk.Label(card, textvariable=error_text, wraplength=350)
        error_label.grid(row=10, column=0, sticky="w", pady=(0, 8))
        mode = tk.BooleanVar(value=bool(register))

        def submit():
            print("Account button clicked:", "register" if mode.get() else "login", flush=True)
            try:
                name = username_box.get().strip()
                password = password_box.get()
                if mode.get():
                    if password != confirm_box.get():
                        raise store.AccountError("Passwords do not match.")
                    older = store.legacy_import_available()
                    take_old = False
                    if older:
                        take_old = messagebox.askyesno(
                            "Keep existing cats?",
                            f"Found {older} cat profile(s) from before accounts existed.\n\n"
                            "Import them into this first account?",
                            parent=self.root,
                        )
                    authenticated = store.register(name, password, import_legacy=take_old)
                else:
                    authenticated = store.login(name, password)
            except (store.AccountError, sqlite3.Error) as exc:
                error_text.set(str(exc))
                messagebox.showerror("Account problem", str(exc), parent=self.root)
                return
            self.user = authenticated
            self.show_home()
            # Preserve the due-task reminder on sign-in and automatically open
            # the independent calendar afterwards, keeping the calendar on top.
            self.root.after_idle(self.open_daily_if_needed)
            self.root.after_idle(self.open_calendar)

        primary = ttk.Button(card, text="Log in", command=submit)
        primary.grid(row=11, column=0, sticky="ew", pady=(6, 12), ipady=6)

        def toggle_mode():
            mode.set(not mode.get())
            print("Switched account form to:", "register" if mode.get() else "login", flush=True)
            update_mode()

        secondary = ttk.Button(card, text="New here? Create an account",
                               command=toggle_mode)
        secondary.grid(row=12, column=0, sticky="ew", ipady=5)

        def update_mode():
            registering = mode.get()
            title.configure(text="Create an account" if registering else "Welcome back")
            primary.configure(text="Create account" if registering else "Log in")
            secondary.configure(text=("Already have an account? Log in" if registering
                                      else "New here? Create an account"))
            hint.configure(text=("Username: 3–32 letters, numbers, _, . or -; "
                                 "password: at least 8 characters."
                                 if registering else "Enter your username and password."))
            if registering:
                confirm_label.grid()
                confirm_box.grid()
            else:
                confirm_label.grid_remove()
                confirm_box.grid_remove()
                confirm_box.delete(0, tk.END)
            error_text.set("")

        update_mode()
        username_box.bind("<Return>", lambda event: submit())
        password_box.bind("<Return>", lambda event: submit())
        confirm_box.bind("<Return>", lambda event: submit())
        username_box.focus_set()

    def install_menu(self):
        menu = tk.Menu(self.root)
        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard_tab)
        view_menu.add_command(label="Cat profiles", command=self.show_profiles_tab)
        view_menu.add_separator()
        view_menu.add_command(label="Open calendar...", command=self.open_calendar)
        view_menu.add_command(label="Open daily task list", command=self.open_daily_tasks)
        menu.add_cascade(label="View", menu=view_menu)
        data_menu = tk.Menu(menu, tearoff=False)
        data_menu.add_command(label="Export my care records (CSV)...",
                              command=self.export_csv)
        data_menu.add_command(label="Export my account data (JSON)...",
                              command=self.export_json)
        menu.add_cascade(label="Data", menu=data_menu)
        self.root.config(menu=menu)

    def show_dashboard_tab(self):
        self.notebook.select(self.dashboard_tab)

    def show_profiles_tab(self):
        self.notebook.select(self.profiles_tab)

    def show_home(self):
        """Dashboard and searchable cat profiles occupy separate main-window tabs.

        The task calendar is *not* embedded here. It has its own popup window.
        """
        base = self.new_shell()
        header = tk.Frame(base, bg=BLUE)
        header.pack(fill="x")
        header_inner = tk.Frame(header, bg=BLUE)
        header_inner.pack(fill="x", padx=24, pady=15)
        label(header_inner, "CAT CARE  /  HEALTH TRACKER", size=17,
              bold=True, fg=WHITE, bg=BLUE).pack(side="left")
        button(header_inner, "Log out", self.logout,
               color=WHITE, text_color=RED).pack(side="right", padx=(8, 0))
        button(header_inner, "Delete account", self.delete_my_account,
               color="#f5e2e7", text_color=RED).pack(side="right", padx=(8, 0))
        button(header_inner, "Open calendar", self.open_calendar,
               color=PALE_BLUE, text_color=BLUE).pack(side="right", padx=(8, 0))
        label(base, f"Signed in as {self.user['username']}",
              bg=BG, fg=MUTED).pack(anchor="w", padx=26, pady=(10, 4))

        # Plain Tk tabs avoid the large black background rendered by Aqua's
        # native ttk.Notebook on some macOS / Tk versions.
        self.notebook = LightTabs(base, surface=BG, tab_padding=18)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(8, 18))
        self.dashboard_tab = tk.Frame(self.notebook.content, bg=BG)
        self.profiles_tab = tk.Frame(self.notebook.content, bg=BG)
        self.notebook.add(self.dashboard_tab, text="Dashboard / Tasks")
        self.notebook.add(self.profiles_tab, text="Cat Profiles / Search")

        # Dashboard: summary counters plus overdue/today tasks only.
        dash_top = tk.Frame(self.dashboard_tab, bg=BG)
        dash_top.pack(fill="x", pady=(13, 12))
        label(dash_top, "Overview", bold=True, size=20, bg=BG).pack(side="left")
        button(dash_top, "Open calendar popup", self.open_calendar,
               color=BLUE).pack(side="right")
        button(dash_top, "+ Quick task", self.quick_task, color=GREEN).pack(
            side="right", padx=9)

        stats_frame = tk.Frame(self.dashboard_tab, bg=BG)
        stats_frame.pack(fill="x", pady=(0, 14))
        self.stats_widgets = {}
        for col, (key, title) in enumerate((("cats", "CAT PROFILES"),
                                            ("records", "CARE RECORDS"),
                                            ("due", "DUE / OVERDUE"))):
            stats_frame.columnconfigure(col, weight=1, uniform="stats")
            tile = tk.Frame(stats_frame, bg=PALE_BLUE, highlightbackground=BORDER,
                            highlightthickness=1)
            tile.grid(row=0, column=col, padx=5, sticky="ew")
            label(tile, title, bg=PALE_BLUE, fg=MUTED, size=9,
                  bold=True).pack(pady=(9, 0))
            value = label(tile, "0", bg=PALE_BLUE, fg=BLUE,
                          size=22, bold=True)
            value.pack(pady=(0, 8))
            self.stats_widgets[key] = value

        attention = tk.Frame(self.dashboard_tab, bg=BG)
        attention.pack(fill="both", expand=True, pady=(0, 12))
        attention_bar = tk.Frame(attention, bg=BG)
        attention_bar.pack(fill="x", pady=(0, 5))
        label(attention_bar, "Today's tasks & overdue", bold=True,
              size=14, bg=BG).pack(side="left")
        button(attention_bar, "Refresh", self.refresh_views,
               color=PALE_BLUE, text_color=BLUE).pack(side="right")
        button(attention_bar, "Mark selected complete", self.complete_due_selected,
               color=GREEN).pack(side="right", padx=(0, 8))
        button(attention_bar, "Open daily task list", self.open_daily_tasks,
               color=BLUE, text_color=WHITE).pack(side="right", padx=(0, 8))
        self.due_summary = label(attention, "", bg=BG, fg=MUTED)
        self.due_summary.pack(anchor="w", pady=(0, 6))
        frame, self.due_tree = make_tree(
            attention,
            (("cat", "Cat"), ("task", "Task"), ("category", "Category"),
             ("due", "Due"), ("status", "Status")),
            (140, 260, 140, 110, 110),
        )
        frame.pack(fill="both", expand=True)
        self.due_tree.bind("<Double-1>", self.open_due_selected)
        self.due_tree.bind("<Return>", self.open_due_selected)
        self.due_hint = label(attention, "Double-click a task to open its cat.",
                              bg=BG, fg=MUTED, size=9)
        self.due_hint.pack(anchor="w", pady=(5, 0))

        # Cat Profiles: original live search and cards on their own tab.
        profiles_top = tk.Frame(self.profiles_tab, bg=BG)
        profiles_top.pack(fill="x", pady=(13, 10))
        label(profiles_top, "My cat profiles", size=20,
              bold=True, bg=BG).pack(side="left")
        button(profiles_top, "+ Add cat", self.add_cat).pack(side="right")
        button(profiles_top, "+ Quick task", self.quick_task, color=GREEN).pack(
            side="right", padx=(0, 9))
        label(self.profiles_tab, "Search by name, then open a profile to see its care history.",
              fg=MUTED, bg=BG).pack(anchor="w", pady=(0, 10))
        search_row = tk.Frame(self.profiles_tab, bg=BG)
        search_row.pack(fill="x", pady=(0, 10))
        label(search_row, "Search cats:", bg=BG).pack(side="left")
        self.cat_search = tk.StringVar()
        search_box = entry(search_row, width=32)
        search_box.configure(textvariable=self.cat_search)
        search_box.pack(side="left", padx=8, ipady=4)
        self.cat_search.trace_add("write", lambda *_: self.refresh_views())
        button(search_row, "Clear", self.clear_cat_search,
               color=PALE_BLUE, text_color=BLUE).pack(side="left")

        card_region = tk.Frame(self.profiles_tab, bg=BG)
        card_region.pack(fill="both", expand=True)
        canvas = tk.Canvas(card_region, bg=BG, highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(card_region, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.cards_frame = tk.Frame(canvas, bg=BG)
        window_id = canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        self.cards_frame.bind("<Configure>",
                              lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda event: canvas.itemconfigure(window_id, width=event.width))
        self.install_menu()
        self.refresh_views()

    def clear_cat_search(self):
        self.cat_search.set("")

    def refresh_views(self):
        if self.user is None:
            return
        try:
            cats = store.list_cats(self.uid)
            stats = store.dashboard_stats(self.uid)
            due = store.due_records(self.uid)
        except ERRORS as exc:
            messagebox.showerror("Couldn't load your cats", str(exc), parent=self.root)
            return
        for key, value in stats.items():
            self.stats_widgets[key].configure(text=str(value))
        for child in self.cards_frame.winfo_children():
            child.destroy()

        query = self.cat_search.get().strip().casefold()
        visible_cats = [cat for cat in cats if query in cat["name"].casefold()]
        if not visible_cats:
            empty = tk.Frame(self.cards_frame, bg=WHITE, padx=30, pady=25,
                             highlightbackground=BORDER, highlightthickness=1)
            empty.pack(fill="x", pady=5)
            label(empty, "No cats found" if query else "No cats yet",
                  size=15, bold=True).pack(anchor="w")
            label(empty, "Try a different name or press Clear." if query else
                  "Choose '+ Add cat' to create your first profile.",
                  fg=MUTED).pack(anchor="w", pady=(4, 0))
        for cat in visible_cats:
            row = tk.Frame(self.cards_frame, bg=WHITE,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=4, padx=2)
            info = tk.Frame(row, bg=WHITE)
            info.pack(side="left", fill="x", expand=True, padx=16, pady=12)
            label(info, cat["name"], size=15, bold=True).pack(anchor="w")
            subtitle = (cat["breed"] or "Breed not specified")
            if cat["birthday"]:
                subtitle += f"  •  Born {cat['birthday']}"
            label(info, subtitle, fg=MUTED).pack(anchor="w", pady=2)
            count = f"{cat['open_count']} open task(s)  •  {cat['due_count']} due/overdue"
            label(info, count, fg=RED if cat["due_count"] else MUTED).pack(anchor="w")
            actions = tk.Frame(row, bg=WHITE)
            actions.pack(side="right", padx=14, pady=12)
            cat_id = cat["cat_id"]
            button(actions, "Open cat", lambda cid=cat_id: self.open_cat(cid)).pack(
                side="left", padx=(0, 8))
            button(actions, "+ Task",
                   lambda cid=cat_id: self.quick_task(cid), color=GREEN).pack(side="left")

        self.due_tree.delete(*self.due_tree.get_children())
        today = date.today().isoformat()
        overdue_count = sum(r["next_due"] < today for r in due)
        today_count = len(due) - overdue_count
        self.due_summary.configure(
            text=f"{today_count} due today  •  {overdue_count} overdue  •  "
                 "All cats in your account")
        self.due_hint.configure(text=(
            "Double-click a task to open its cat, or select it and mark complete."
            if due else "All caught up! No tasks due today or overdue."))
        for record in due:
            status = task_attention_status(record, today)
            self.due_tree.insert("", "end", iid=str(record["record_id"]),
                                 values=(record["cat_name"], record["task"],
                                         record["category"], record["next_due"],
                                         status),
                                 tags=("overdue",) if status == "Overdue" else ("today",))
        if self.daily_window is not None:
            if self.daily_window.top.winfo_exists():
                self.daily_window.refresh()
            else:
                self.daily_window = None
        if self.calendar_window is not None:
            if self.calendar_window.top.winfo_exists():
                self.calendar_window.calendar.refresh()
            else:
                self.calendar_window = None
        for key, window in list(self.day_windows.items()):
            if window.top.winfo_exists():
                window.refresh()
            else:
                self.day_windows.pop(key, None)
            
            
        for cat_id, window in list(self.cat_windows.items()):
            if window.top.winfo_exists():
                try:
                    window.refresh()
                except store.OwnershipError:
                    window.close()
            else:
                self.cat_windows.pop(cat_id, None)

    def open_daily_if_needed(self):
        """Show a daily checklist after sign-in if there are overdue/today tasks."""
        if self.user is None or self.daily_window is not None:
            return
        try:
            if store.due_records(self.uid):
                print("Opening today's task list automatically.", flush=True)
                self.open_daily_tasks()
        except ERRORS as exc:
            messagebox.showerror("Couldn't open today's tasks", str(exc),
                                 parent=self.root)

    def open_daily_tasks(self):
        """Open or raise the separate daily checklist from the home screen."""
        if self.user is None:
            return
        if self.daily_window is not None and self.daily_window.top.winfo_exists():
            self.daily_window.refresh()
            self.daily_window.top.deiconify()
            self.daily_window.top.lift()
            self.daily_window.top.focus_set()
            return
        self.daily_window = DailyTaskWindow(self)

    def open_calendar(self):
        """Open a standalone calendar window, independent of both tabs."""
        if self.user is None:
            return
        if self.calendar_window is not None and self.calendar_window.top.winfo_exists():
            self.calendar_window.calendar.refresh()
            self.calendar_window.top.deiconify()
            self.calendar_window.top.lift()
            self.calendar_window.top.focus_set()
            return
        self.calendar_window = CalendarWindow(self)

    def open_due_selected(self, event=None):
        selection = self.due_tree.selection()
        if not selection:
            return
        record_id = int(selection[0])
        try:
            record = store.get_record(self.uid, record_id)
        except ERRORS as exc:
            messagebox.showerror("Record unavailable", str(exc), parent=self.root)
            return
        self.open_cat(record["cat_id"])

    def complete_due_selected(self):
        """Quickly complete an overdue/today task without opening the cat window."""
        selection = self.due_tree.selection()
        if not selection:
            messagebox.showinfo("Select a task", "Select a task in Today's tasks first.",
                                parent=self.root)
            return
        try:
            record_id = int(selection[0])
            record = store.get_record(self.uid, record_id)
            if record["status"] == "Open":
                store.toggle_record_status(self.uid, record_id)
        except ERRORS as exc:
            messagebox.showerror("Couldn't complete task", str(exc), parent=self.root)
            return
        self.refresh_views()

    def open_cat(self, cat_id):
        if cat_id in self.cat_windows and self.cat_windows[cat_id].top.winfo_exists():
            window = self.cat_windows[cat_id]
            window.top.lift()
            window.top.focus_force()
            return
        try:
            cat = store.get_cat(self.uid, cat_id)
        except ERRORS as exc:
            messagebox.showerror("Cat unavailable", str(exc), parent=self.root)
            return
        self.cat_windows[cat_id] = CatWindow(self, cat)
    def open_day(self, day):
        key = day.isoformat()
        window = self.day_windows.get(key)
        if window is not None and window.top.winfo_exists():
            window.refresh()
            window.top.lift()
            window.top.focus_force()
            return
        self.day_windows[key] = DayTasksWindow(self, day)

    def add_cat(self):
        CatDialog(self)

    def quick_task(self, cat_id=None):
        cats = store.list_cats(self.uid)
        if not cats:
            messagebox.showinfo("Add a cat first", "Create a cat profile before adding a task.",
                                parent=self.root)
            self.add_cat()
            return
        TaskDialog(self, cat_id=cat_id)

    def logout(self):
        if self.calendar_window is not None:
            self.calendar_window.close()
        if self.daily_window is not None:
            self.daily_window.close()
        for dialog in list(self.dialogs):
            if dialog.winfo_exists():
                dialog.destroy()
        self.dialogs.clear()
        for window in list(self.cat_windows.values()):
            window.close()
        self.cat_windows.clear()
        for window in list(self.day_windows.values()):
            window.close()
        self.day_windows.clear()
        self.show_auth()

    def delete_my_account(self):
        name = self.user["username"]
        answer = simpledialog.askstring(
            "Delete my account", "This permanently deletes your account, its cats, "
            "and all their care records.\n\nType your username to continue:",
            parent=self.root,
        )
        if answer is None or answer.strip().lower() != name:
            if answer is not None:
                messagebox.showerror("Not deleted", "Username did not match.",
                                     parent=self.root)
            return
        password = simpledialog.askstring("Confirm deletion", "Enter your account password:",
                                          show="*", parent=self.root)
        if password is None:
            return
        if not messagebox.askyesno(
                "Permanently delete?",
                "Permanently delete this account and all of its cats and records?\n"
                "This cannot be undone.", icon="warning", parent=self.root):
            return
        try:
            store.delete_account(self.uid, password)
        except ERRORS as exc:
            messagebox.showerror("Account not deleted", str(exc), parent=self.root)
            return
        self.logout()
        messagebox.showinfo("Account deleted", "Your account and its records were deleted.",
                            parent=self.root)

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Export my care records", defaultextension=".csv",
            initialfile=f"{self.user['username']}_care_records.csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if path:
            try:
                store.export_records_csv(self.uid, path)
            except (OSError, *ERRORS) as exc:
                messagebox.showerror("Export failed", str(exc), parent=self.root)
            else:
                messagebox.showinfo("Export complete", "Your records were exported.",
                                    parent=self.root)

    def export_json(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Export my account data", defaultextension=".json",
            initialfile=f"{self.user['username']}_petcare_export.json",
            filetypes=[("JSON files", "*.json")],
        )
        if path:
            try:
                store.export_account_json(self.uid, path)
            except (OSError, *ERRORS) as exc:
                messagebox.showerror("Export failed", str(exc), parent=self.root)
            else:
                messagebox.showinfo("Export complete", "Your cats and records were exported.\n"
                                    "Keep this file somewhere safe.", parent=self.root)

    def run(self):
        self.root.mainloop()



class DailyTaskWindow:
    """Reopenable checklist for tasks due today or overdue across all cats."""

    def __init__(self, app):
        self.app = app
        self.top = tk.Toplevel(app.root)
        self.top.title("Daily task list | Cat Care")
        self.top.geometry("860x510")
        self.top.minsize(670, 360)
        self.top.configure(bg=BG)
        self.top.transient(app.root)
        self.top.protocol("WM_DELETE_WINDOW", self.close)

        header = tk.Frame(self.top, bg=WHITE)
        header.pack(fill="x", padx=18, pady=(16, 8))
        label(header, "Today's tasks & overdue", size=18, bold=True).pack(
            side="left", padx=14, pady=12)
        button(header, "+ Quick task", self.add_task, color=GREEN).pack(
            side="right", padx=12, pady=9)

        label(self.top, "All cats in your account • open tasks due today or earlier",
              bg=BG, fg=MUTED).pack(anchor="w", padx=28, pady=(2, 5))
        self.summary = label(self.top, "", bg=BG, fg=TEXT, bold=True)
        self.summary.pack(anchor="w", padx=28, pady=(0, 10))
        table_frame, self.tree = make_tree(
            self.top,
            (("cat", "Cat"), ("task", "Task"), ("category", "Category"),
             ("due", "Due date"), ("status", "Status")),
            (140, 270, 140, 120, 110),
        )
        table_frame.pack(fill="both", expand=True, padx=22, pady=(0, 8))
        self.tree.bind("<Double-1>", self.open_cat)
        self.tree.bind("<Return>", self.open_cat)

        self.hint = label(self.top, "", bg=BG, fg=MUTED, size=9)
        self.hint.pack(anchor="w", padx=27, pady=(0, 8))

        actions = tk.Frame(self.top, bg=BG)
        actions.pack(fill="x", padx=22, pady=(0, 18))
        button(actions, "Mark selected complete", self.complete_selected,
               color=GREEN).pack(side="left")
        button(actions, "Open selected cat", self.open_cat).pack(
            side="left", padx=8)
        button(actions, "Refresh", self.refresh,
               color=PALE_BLUE, text_color=BLUE_DARK).pack(side="left")
        # Native ttk for pale/gray buttons to avoid macOS text streaks.
        ttk.Button(actions, text="Close", command=self.close,
                   style="HeaderAction.TButton").pack(side="right")
        self.refresh()
        # Raise this modeless checklist over the home window on macOS.
        self.top.after_idle(self.top.lift)

    def refresh(self):
        if self.app.user is None or not self.top.winfo_exists():
            return
        try:
            due = store.due_records(self.app.uid)
        except ERRORS as exc:
            messagebox.showerror("Couldn't load today's tasks", str(exc),
                                 parent=self.top)
            return
        old_selection = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        today = date.today().isoformat()
        overdue = sum(record["next_due"] < today for record in due)
        self.summary.configure(text=f"{len(due) - overdue} due today  •  "
                                    f"{overdue} overdue")
        self.hint.configure(text=(
            "Double-click a task to open its cat, or select a task to mark complete."
            if due else "You're all caught up! No tasks are due today or overdue."))
        for record in due:
            status = task_attention_status(record, today)
            self.tree.insert("", "end", iid=str(record["record_id"]),
                             values=(record["cat_name"], record["task"],
                                     record["category"], record["next_due"], status),
                             tags=("overdue",) if status == "Overdue" else ("today",))
        if old_selection and self.tree.exists(old_selection[0]):
            self.tree.selection_set(old_selection[0])

    def selected_record(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Select a task", "Select a task first.", parent=self.top)
            return None
        try:
            return store.get_record(self.app.uid, int(selection[0]))
        except ERRORS as exc:
            messagebox.showerror("Task unavailable", str(exc), parent=self.top)
            self.refresh()
            return None

    def open_cat(self, event=None):
        record = self.selected_record()
        if record is not None:
            self.app.open_cat(record["cat_id"])

    def complete_selected(self):
        record = self.selected_record()
        if record is None:
            return
        try:
            if record["status"] == "Open":
                store.toggle_record_status(self.app.uid, record["record_id"])
        except ERRORS as exc:
            messagebox.showerror("Couldn't complete task", str(exc), parent=self.top)
            return
        self.app.refresh_views()  # Updates BOTH the main dashboard and this window.

    def add_task(self):
        self.app.quick_task()

    def close(self):
        self.app.daily_window = None
        if self.top.winfo_exists():
            self.top.destroy()


class CatDialog:
    """Add a new cat; profiles can also be edited from their individual window."""
    def __init__(self, app):
        self.app = app
        self.top = tk.Toplevel(app.root)
        # Use the same native appearance as the parent.
        app.track_dialog(self.top)
        self.top.title("Add a cat")
        self.top.geometry("490x460")
        self.top.configure(bg=WHITE)
        self.top.transient(app.root)
        area = tk.Frame(self.top, bg=WHITE, padx=24, pady=22)
        area.pack(fill="both", expand=True)
        area.columnconfigure(1, weight=1)
        label(area, "Create a cat profile", size=17, bold=True).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 14))
        self.name = field(area, "Name *", 1)
        self.breed = field(area, "Breed", 2)
        self.birthday = field(area, "Birthday", 3)
        label(area, "Birthday format: YYYY-MM-DD (or leave blank)",
              fg=MUTED, size=9).grid(row=4, column=1, sticky="w")
        label(area, "Notes", bold=True).grid(row=5, column=0, sticky="nw", pady=10)
        self.notes = tk.Text(area, height=4, width=30, bg=WHITE, fg=TEXT,
                             relief="solid", bd=1, wrap="word", font=("Arial", 10))
        self.notes.grid(row=5, column=1, sticky="ew", pady=10)
        controls = tk.Frame(area, bg=WHITE)
        controls.grid(row=6, column=0, columnspan=2, sticky="e", pady=(10, 0))
        button(controls, "Cancel", self.top.destroy, color=PALE_BLUE,
               text_color=BLUE).pack(side="left", padx=8)
        button(controls, "Save cat", self.save).pack(side="left")
        self.name.focus_set()

    def save(self):
        try:
            birthday = require_date(self.birthday.get(), "Birthday", optional=True)
            cat_id = store.add_cat(self.app.uid, self.name.get(), self.breed.get(),
                                   birthday, text_value(self.notes))
        except (ValueError, *ERRORS) as exc:
            messagebox.showerror("Could not add cat", str(exc), parent=self.top)
            return
        self.top.destroy()
        self.app.refresh_views()
        self.app.open_cat(cat_id)


class CatWindow:
    """A separate window with organized task tabs for one selected cat."""
    TAB_GROUPS = (
        ("To do", None),
        ("Feeding", ("Feeding",)),
        ("Medication", ("Medication",)),
        ("Health", ("Vaccination", "Vet Visit", "Weight")),
        ("Grooming / Other", ("Grooming", "Other")),
        ("All records", "all"),
    )

    def __init__(self, app, cat):
        self.app = app
        self.cat_id = cat["cat_id"]
        self.top = tk.Toplevel(app.root)
        # Use the same native appearance as the parent.
        self.top.title(f"{cat['name']} | Cat Care")
        self.top.geometry("1040x670")
        self.top.minsize(760, 500)
        self.top.configure(bg=BG)
        mac_light_appearance(self.top)
        self.top.protocol("WM_DELETE_WINDOW", self.close)
        header = tk.Frame(self.top, bg=WHITE)
        header.pack(fill="x", padx=18, pady=(16, 8))
        self.name_label = label(header, cat["name"], size=21, bold=True)
        self.name_label.pack(side="left", padx=12, pady=10)
        button(header, "+ Add task", self.add_task, color=GREEN).pack(
            side="right", padx=12, pady=9)
        self.subtitle = label(self.top, "", bg=BG, fg=MUTED)
        self.subtitle.pack(anchor="w", padx=27, pady=(0, 9))

        self.notebook = LightTabs(self.top, surface=BG, tab_padding=10, font_size=9)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.trees = {}
        self.group_keys = {}
        self.status_filters = {}
        for title, categories in self.TAB_GROUPS:
            page = tk.Frame(self.notebook.content, bg=WHITE)
            self.notebook.add(page, text=title)
            heading_row = tk.Frame(page, bg=WHITE)
            heading_row.pack(fill="x", padx=14, pady=(12, 4))
            label(heading_row, title + " tasks", size=14, bold=True).pack(side="left")
            options = (("All open", "Overdue", "Due today", "Upcoming", "No due date")
                       if categories is None else
                       ("All", "Open", "Overdue", "Due today", "Upcoming",
                        "No due date", "Completed"))
            status_filter = ttk.Combobox(heading_row, state="readonly", width=16,
                                         values=options)
            status_filter.set(options[0])
            status_filter.pack(side="right")
            label(heading_row, "Show:", size=10).pack(side="right", padx=(0, 8))
            status_filter.bind("<<ComboboxSelected>>",
                               lambda event: self.refresh())
            self.status_filters[title] = status_filter
            label(page, "Sorted: Overdue → Due today → Upcoming → No due date → Completed",
                  fg=MUTED, size=9).pack(anchor="w", padx=14, pady=(0, 7))
            outer, tree = make_tree(
                page,
                (("task", "Task"), ("category", "Category"),
                 ("record_date", "Recorded"), ("next_due", "Next due"),
                 ("status", "Status")),
                (250, 140, 110, 110, 110),
            )
            outer.pack(fill="both", expand=True, padx=12, pady=(0, 8))
            row = tk.Frame(page, bg=WHITE)
            row.pack(fill="x", padx=12, pady=(0, 12))
            button(row, "+ New task", self.add_task).pack(side="left")
            button(row, "Edit selected", lambda t=tree: self.edit_selected(t),
                   color=PALE_BLUE, text_color=BLUE).pack(side="left", padx=7)
            button(row, "Complete / reopen", lambda t=tree: self.toggle_selected(t),
                   color=GREEN).pack(side="left", padx=7)
            button(row, "Delete", lambda t=tree: self.delete_selected(t),
                   color="#f8e2e6", text_color=RED).pack(side="left", padx=7)
            tree.bind("<Double-1>", lambda event, t=tree: self.edit_selected(t))
            self.trees[title] = tree
            self.group_keys[title] = categories

        profile = tk.Frame(self.notebook.content, bg=WHITE, padx=22, pady=20)
        self.notebook.add(profile, text="Profile")
        profile.columnconfigure(1, weight=1)
        label(profile, "Cat profile", size=15, bold=True).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        self.profile_name = field(profile, "Name *", 1, value=cat["name"])
        self.profile_breed = field(profile, "Breed", 2, value=cat["breed"])
        self.profile_birthday = field(profile, "Birthday", 3, value=cat["birthday"])
        label(profile, "Use YYYY-MM-DD or leave blank", fg=MUTED, size=9).grid(
            row=4, column=1, sticky="w")
        label(profile, "Notes", bold=True).grid(row=5, column=0,
                                                 sticky="nw", pady=10)
        self.profile_notes = tk.Text(profile, height=5, width=35, font=("Arial", 10),
                                     relief="solid", bd=1, wrap="word")
        self.profile_notes.grid(row=5, column=1, sticky="ew", pady=10)
        self.profile_notes.insert("1.0", cat["notes"] or "")
        buttons = tk.Frame(profile, bg=WHITE)
        buttons.grid(row=6, column=0, columnspan=2, sticky="w", pady=(16, 0))
        button(buttons, "Save profile", self.save_profile).pack(side="left")
        button(buttons, "Delete cat", self.delete_cat, color="#f8e2e6",
               text_color=RED).pack(side="left", padx=12)
        self.refresh()

    def close(self):
        self.app.cat_windows.pop(self.cat_id, None)
        if self.top.winfo_exists():
            self.top.destroy()

    def refresh(self):
        cat = store.get_cat(self.app.uid, self.cat_id)
        self.top.title(f"{cat['name']} | Cat Care")
        self.name_label.configure(text=cat["name"])
        self.subtitle.configure(text=(cat["breed"] or "Breed not specified") +
                                (f"   •   Born {cat['birthday']}" if cat["birthday"] else ""))
        records = store.list_records(self.app.uid, self.cat_id)
        today = date.today().isoformat()
        for title, tree in self.trees.items():
            tree.delete(*tree.get_children())
            group = self.group_keys[title]
            if group is None:  # To do: only unfinished tasks.
                selected = [r for r in records if r["status"] == "Open"]
            elif group == "all":
                selected = list(records)
            else:
                selected = [r for r in records if r["category"] in group]
            chosen_filter = self.status_filters[title].get()
            selected = [r for r in selected
                        if matches_status_filter(r, chosen_filter, today)]
            selected.sort(key=lambda r: task_priority_key(r, today))
            for record in selected:
                display_status = task_attention_status(record, today)
                tag = {"Overdue": "overdue", "Due today": "today",
                       "Upcoming": "upcoming", "No due date": "no_due",
                       "Completed": "done"}[display_status]
                tree.insert("", "end", iid=str(record["record_id"]),
                            values=(record["task"], record["category"],
                                    record["record_date"], record["next_due"] or "",
                                    display_status), tags=(tag,))

    def _selected_record(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Select a task", "Click a task in the table first.",
                                parent=self.top)
            return None
        return int(selected[0])

    def add_task(self):
        TaskDialog(self.app, cat_id=self.cat_id, parent=self.top)

    def edit_selected(self, tree):
        record_id = self._selected_record(tree)
        if record_id is not None:
            TaskDialog(self.app, cat_id=self.cat_id,
                       record_id=record_id, parent=self.top)

    def toggle_selected(self, tree):
        record_id = self._selected_record(tree)
        if record_id is None:
            return
        try:
            store.toggle_record_status(self.app.uid, record_id)
        except ERRORS as exc:
            messagebox.showerror("Could not change task", str(exc), parent=self.top)
            return
        self.app.refresh_views()

    def delete_selected(self, tree):
        record_id = self._selected_record(tree)
        if record_id is None:
            return
        if not messagebox.askyesno("Delete task", "Delete the selected task?",
                                   parent=self.top, icon="warning"):
            return
        try:
            store.delete_record(self.app.uid, record_id)
        except ERRORS as exc:
            messagebox.showerror("Could not delete task", str(exc), parent=self.top)
            return
        self.app.refresh_views()

    def save_profile(self):
        try:
            birthday = require_date(self.profile_birthday.get(), "Birthday", optional=True)
            store.update_cat(self.app.uid, self.cat_id, self.profile_name.get(),
                             self.profile_breed.get(), birthday,
                             text_value(self.profile_notes))
        except (ValueError, *ERRORS) as exc:
            messagebox.showerror("Could not save profile", str(exc), parent=self.top)
            return
        self.app.refresh_views()
        messagebox.showinfo("Saved", "Profile updated.", parent=self.top)

    def delete_cat(self):
        cat = store.get_cat(self.app.uid, self.cat_id)
        if not messagebox.askyesno(
                "Delete cat", f"Delete {cat['name']} and all their care records?\n"
                "This cannot be undone.", icon="warning", parent=self.top):
            return
        try:
            store.delete_cat(self.app.uid, self.cat_id)
        except ERRORS as exc:
            messagebox.showerror("Could not delete cat", str(exc), parent=self.top)
            return
        self.close()
        self.app.refresh_views()

class DatePicker:
    """Popup month calendar that writes a YYYY-MM-DD date into an Entry."""

    def __init__(self, parent, target, allow_clear=False):
        self.target = target
        self.allow_clear = allow_clear
        try:
            self.selected = datetime.strptime(target.get().strip(), "%Y-%m-%d").date()
        except ValueError:
            self.selected = None
        base = self.selected or date.today()
        self.year, self.month = base.year, base.month

        self.top = tk.Toplevel(parent)
        self.top.title("Choose a date")
        self.top.configure(bg=WHITE)
        self.top.transient(parent)
        self.top.resizable(False, False)
        self.top.geometry(f"+{target.winfo_rootx()}"
                          f"+{target.winfo_rooty() + target.winfo_height() + 4}")
        self.top.bind("<Escape>", lambda event: self.top.destroy())
        self.body = tk.Frame(self.top, bg=WHITE, padx=12, pady=12)
        self.body.pack()
        self.draw()
        self.top.after_idle(self._grab)

    def _grab(self):
        try:
            self.top.lift()
            self.top.grab_set()
            self.top.focus_set()
        except tk.TclError:
            pass

    def shift(self, months):
        total = self.year * 12 + (self.month - 1) + months
        year, month = divmod(total, 12)
        if 1 <= year <= 9999:
            self.year, self.month = year, month + 1
            self.draw()

    def pick(self, chosen):
        self.target.delete(0, "end")
        self.target.insert(0, chosen.isoformat())
        self.top.destroy()

    def clear(self):
        self.target.delete(0, "end")
        self.top.destroy()

    def draw(self):
        for child in self.body.winfo_children():
            child.destroy()

        nav = tk.Frame(self.body, bg=WHITE)
        nav.pack(fill="x", pady=(0, 8))

        def nav_label(text, months):
            lbl = tk.Label(nav, text=text, bg=PALE_BLUE, fg=BLUE, width=3,
                           font=("Arial", 12, "bold"), cursor="hand2")
            lbl.bind("<Button-1>", lambda event: self.shift(months))
            return lbl

        nav_label("«", -12).pack(side="left")
        nav_label("‹", -1).pack(side="left", padx=(4, 0))
        nav_label("»", 12).pack(side="right")
        nav_label("›", 1).pack(side="right", padx=(0, 4))
        tk.Label(nav, text=f"{calendar.month_name[self.month]} {self.year}",
                 bg=WHITE, fg=TEXT, font=("Arial", 12, "bold")).pack(expand=True)

        grid = tk.Frame(self.body, bg=WHITE)
        grid.pack()
        for col, name in enumerate(("Su", "Mo", "Tu", "We", "Th", "Fr", "Sa")):
            tk.Label(grid, text=name, bg=WHITE, fg=MUTED, width=4,
                     font=("Arial", 9, "bold")).grid(row=0, column=col)

        today = date.today()
        weeks = calendar.Calendar(firstweekday=6).monthdayscalendar(self.year, self.month)
        for row, week in enumerate(weeks, start=1):
            for col, day in enumerate(week):
                if not day:
                    continue
                current = date(self.year, self.month, day)
                bg, fg = WHITE, TEXT
                if current == today:
                    bg, fg = PALE_BLUE, BLUE
                if current == self.selected:
                    bg, fg = BLUE, WHITE
                cell = tk.Label(grid, text=str(day), bg=bg, fg=fg, width=4, height=2,
                                font=("Arial", 10), cursor="hand2")
                cell.grid(row=row, column=col, padx=1, pady=1)
                cell.bind("<Button-1>", lambda event, d=current: self.pick(d))

        footer = tk.Frame(self.body, bg=WHITE)
        footer.pack(fill="x", pady=(10, 0))
        button(footer, "Today", lambda: self.pick(date.today()),
               color=PALE_BLUE, text_color=BLUE).pack(side="left")
        if self.allow_clear:
            button(footer, "Clear", self.clear, color="#f8e2e6",
                   text_color=RED).pack(side="left", padx=8)
        button(footer, "Cancel", self.top.destroy, color=PALE_BLUE,
               text_color=BLUE).pack(side="right")


class CalendarWindow:
    """Independent popup with a full-month overview of the signed-in account."""

    def __init__(self, app):
        self.app = app
        self.top = tk.Toplevel(app.root)
        self.top.title("Care Calendar | Cat Care")
        self.top.geometry("800x640")
        self.top.minsize(610, 500)
        self.top.configure(bg=BG)
        mac_light_appearance(self.top)
        self.top.transient(app.root)
        self.top.protocol("WM_DELETE_WINDOW", self.close)

        header = tk.Frame(self.top, bg=BG)
        header.pack(fill="x", padx=20, pady=(17, 8))
        label(header, "Care calendar", size=20, bold=True,
              bg=BG).pack(side="left")
        button(header, "Close", self.close, color=PALE_BLUE,
               text_color=BLUE).pack(side="right")
        label(self.top, "Select any date to see its care tasks. Colored task counts show activity.",
              bg=BG, fg=MUTED).pack(anchor="w", padx=20, pady=(0, 12))
        self.calendar = HomeCalendar(self.top, app)
        self.calendar.frame.pack(fill="both", expand=True, padx=20, pady=(0, 14))
        label(self.top, "Past open tasks: red   •   Today's open tasks: amber   •   "
              "Future open tasks: blue   •   All completed: green",
              bg=BG, fg=MUTED, size=9).pack(anchor="w", padx=20, pady=(0, 16))
        # The calendar appears as the foremost, independently closeable window.
        self.top.after_idle(self.top.lift)
        self.top.after_idle(self.top.focus_set)

    def close(self):
        self.app.calendar_window = None
        if self.top.winfo_exists():
            self.top.destroy()


class HomeCalendar:
    """Month calendar rendered in the separate calendar popup."""

    def __init__(self, parent, app):
        self.app = app
        today = date.today()
        self.year, self.month = today.year, today.month
        self.frame = tk.Frame(parent, bg=WHITE,
                              highlightbackground=BORDER, highlightthickness=1)
        self.refresh()

    def shift(self, months):
        total = self.year * 12 + (self.month - 1) + months
        year, month = divmod(total, 12)
        if 1 <= year <= 9999:
            self.year, self.month = year, month + 1
            self.refresh()

    def go_today(self):
        today = date.today()
        self.year, self.month = today.year, today.month
        self.refresh()

    def refresh(self):
        if self.app.user is None or not self.frame.winfo_exists():
            return
        try:
            counts = store.task_counts(self.app.uid, self.year, self.month)
        except ERRORS:
            counts = {}
        for child in self.frame.winfo_children():
            child.destroy()

        bar = tk.Frame(self.frame, bg=WHITE)
        bar.pack(fill="x", padx=12, pady=(10, 6))
        label(bar, f"{calendar.month_name[self.month]} {self.year}",
              size=14, bold=True).pack(side="left")

        def nav_label(text, months):
            lbl = tk.Label(bar, text=text, bg=PALE_BLUE, fg=BLUE, width=3,
                           font=("Arial", 12, "bold"), cursor="hand2")
            lbl.bind("<Button-1>", lambda event: self.shift(months))
            return lbl

        button(bar, "Today", self.go_today, color=PALE_BLUE,
               text_color=BLUE).pack(side="right", padx=(8, 0))
        nav_label("›", 1).pack(side="right", padx=(4, 0))
        nav_label("‹", -1).pack(side="right")

        grid = tk.Frame(self.frame, bg=WHITE)
        grid.pack(fill="x", padx=12, pady=(0, 12))
        for col, name in enumerate(("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")):
            grid.columnconfigure(col, weight=1, uniform="cal")
            tk.Label(grid, text=name, bg=WHITE, fg=MUTED,
                     font=("Arial", 9, "bold")).grid(row=0, column=col, pady=(0, 4))

        today = date.today()
        weeks = calendar.Calendar(firstweekday=6).monthdayscalendar(self.year, self.month)
        for row, week in enumerate(weeks, start=1):
            for col, day_number in enumerate(week):
                if not day_number:
                    continue
                current = date(self.year, self.month, day_number)
                total, open_count = counts.get(current.isoformat(), (0, 0))
                text, fg = str(day_number), TEXT
                if total:
                    text += f"\n{total} task" + ("" if total == 1 else "s")
                    if open_count == 0:
                        fg = GREEN
                    elif current < today:
                        fg = RED
                    elif current == today:
                        fg = "#a35b0d"
                    else:
                        fg = BLUE_DARK
                cell = tk.Label(grid, text=text, bg=PALE_BLUE if current == today else WHITE,
                                fg=fg, height=2, cursor="hand2",
                                font=("Arial", 10, "bold" if total else "normal"),
                                highlightbackground=BORDER, highlightthickness=1)
                cell.grid(row=row, column=col, sticky="nsew", padx=1, pady=1)
                cell.bind("<Button-1>", lambda event, d=current: self.app.open_day(d))


class DayTasksWindow:
    """Popup listing every task for one calendar day."""

    def __init__(self, app, day):
        self.app = app
        self.day = day
        self.top = tk.Toplevel(app.root)
        self.top.title(f"Tasks for {day.isoformat()} | Cat Care")
        self.top.geometry("780x440")
        self.top.minsize(620, 320)
        self.top.configure(bg=BG)
        self.top.transient(app.root)
        self.top.protocol("WM_DELETE_WINDOW", self.close)

        header = tk.Frame(self.top, bg=WHITE)
        header.pack(fill="x", padx=18, pady=(16, 8))
        label(header, day.strftime("%A, %B %d, %Y").replace(" 0", " "),
              size=17, bold=True).pack(side="left", padx=14, pady=12)
        self.summary = label(self.top, "", bg=BG, fg=MUTED)
        self.summary.pack(anchor="w", padx=28, pady=(2, 8))

        table, self.tree = make_tree(
            self.top,
            (("cat", "Cat"), ("task", "Task"), ("category", "Category"),
             ("recorded", "Recorded"), ("status", "Status")),
            (140, 260, 130, 110, 110),
        )
        table.pack(fill="both", expand=True, padx=22, pady=(0, 8))
        self.tree.bind("<Double-1>", self.open_cat)

        actions = tk.Frame(self.top, bg=BG)
        actions.pack(fill="x", padx=22, pady=(0, 18))
        button(actions, "Complete / reopen", self.toggle, color=GREEN).pack(side="left")
        button(actions, "Open selected cat", self.open_cat).pack(side="left", padx=8)
        button(actions, "Close", self.close, color=PALE_BLUE,
               text_color=BLUE).pack(side="right")
        self.refresh()
        self.top.after_idle(self.top.lift)

    def refresh(self):
        if self.app.user is None or not self.top.winfo_exists():
            return
        try:
            rows = store.records_on_date(self.app.uid, self.day)
        except ERRORS as exc:
            messagebox.showerror("Couldn't load tasks", str(exc), parent=self.top)
            return
        today = date.today().isoformat()
        rows = sorted(rows, key=lambda r: task_priority_key(r, today))
        old = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        tags = {"Overdue": "overdue", "Due today": "today", "Upcoming": "upcoming",
                "No due date": "no_due", "Completed": "done"}
        for record in rows:
            status = task_attention_status(record, today)
            self.tree.insert("", "end", iid=str(record["record_id"]),
                             values=(record["cat_name"], record["task"],
                                     record["category"], record["record_date"], status),
                             tags=(tags[status],))
        open_count = sum(r["status"] == "Open" for r in rows)
        self.summary.configure(
            text=(f"{open_count} open  •  {len(rows) - open_count} completed"
                  if rows else "No tasks on this day."))
        if old and self.tree.exists(old[0]):
            self.tree.selection_set(old[0])

    def selected_record(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Select a task", "Select a task first.", parent=self.top)
            return None
        try:
            return store.get_record(self.app.uid, int(selection[0]))
        except ERRORS as exc:
            messagebox.showerror("Task unavailable", str(exc), parent=self.top)
            self.refresh()
            return None

    def open_cat(self, event=None):
        record = self.selected_record()
        if record is not None:
            self.app.open_cat(record["cat_id"])

    def toggle(self):
        record = self.selected_record()
        if record is None:
            return
        try:
            store.toggle_record_status(self.app.uid, record["record_id"])
        except ERRORS as exc:
            messagebox.showerror("Couldn't change task", str(exc), parent=self.top)
            return
        self.app.refresh_views()

    def close(self):
        self.app.day_windows.pop(self.day.isoformat(), None)
        if self.top.winfo_exists():
            self.top.destroy()




class TaskDialog:
    """Quick add/edit: choose a cat, preset task, and a due-date shortcut."""
    def __init__(self, app, cat_id=None, record_id=None, parent=None):
        self.app = app
        self.record_id = record_id
        self.parent = parent if parent is not None else app.root
        self.top = tk.Toplevel(self.parent)
        # Use the same native appearance as the parent.
        app.track_dialog(self.top)
        self.top.title("Edit care record" if record_id else "Quick add a task")
        self.top.geometry("560x600")
        self.top.minsize(470, 510)
        self.top.configure(bg=WHITE)
        self.top.transient(self.parent)
        container = tk.Frame(self.top, bg=WHITE, padx=25, pady=20)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)
        label(container, "Edit care record" if record_id else "Quick add a task",
              size=17, bold=True).grid(row=0, column=0, columnspan=2,
                                       sticky="w", pady=(0, 4))
        label(container, "Choose a common task or type your own.",
              fg=MUTED).grid(row=1, column=0, columnspan=2,
                              sticky="w", pady=(0, 14))

        cats = store.list_cats(app.uid)
        self.cat_ids = {f"{cat['name']} (#{cat['cat_id']})": cat["cat_id"] for cat in cats}
        label(container, "Cat *", bold=True).grid(row=2, column=0,
                                                   sticky="w", pady=8)
        self.cat_choice = ttk.Combobox(container, state="readonly",
                                       values=list(self.cat_ids), width=30)
        self.cat_choice.grid(row=2, column=1, sticky="ew", pady=8)
        if cat_id is not None:
            for title, cid in self.cat_ids.items():
                if cid == cat_id:
                    self.cat_choice.set(title)
                    break
        elif self.cat_ids:
            self.cat_choice.current(0)
        if cat_id is not None:
            self.cat_choice.configure(state="disabled")

        label(container, "Category *", bold=True).grid(row=3, column=0,
                                                        sticky="w", pady=8)
        self.category = ttk.Combobox(container, values=db.CATEGORIES,
                                     state="readonly", width=30)
        self.category.grid(row=3, column=1, sticky="ew", pady=8)
        self.category.set("Feeding")

        label(container, "Task *", bold=True).grid(row=4, column=0, sticky="w", pady=8)
        self.task = ttk.Combobox(container, values=TASK_IDEAS["Feeding"], width=30)
        self.task.grid(row=4, column=1, sticky="ew", pady=8)
        self.category.bind("<<ComboboxSelected>>", self.category_changed)

        self.record_date = field(container, "Record date *", 5,
                                 value=date.today().isoformat())
        self.due_date = field(container, "Next due", 6,
                              value=date.today().isoformat())
        self.picker = None
        for box, clearable in ((self.record_date, False), (self.due_date, True)):
            box.bind("<Button-1>",
                     lambda event, b=box, c=clearable: self.show_picker(b, c), add="+")
        
        shortcuts = tk.Frame(container, bg=WHITE)
        shortcuts.grid(row=7, column=1, sticky="w", pady=(0, 6))
        for caption, delta in (("Today", 0), ("Tomorrow", 1),
                               ("+7 days", 7), ("+30 days", 30)):
            button(shortcuts, caption, lambda d=delta: self.set_due(d),
                   color=PALE_BLUE, text_color=BLUE).pack(
                       side="left", padx=(0, 5))
        label(container, "Dates: YYYY-MM-DD. Next due may be left blank.",
              fg=MUTED, size=9).grid(row=8, column=1, sticky="w", pady=(0, 8))
        label(container, "Notes", bold=True).grid(row=9, column=0, sticky="nw", pady=8)
        self.notes = tk.Text(container, height=4, bg=WHITE, fg=TEXT,
                             relief="solid", bd=1, wrap="word",
                             font=("Arial", 10))
        self.notes.grid(row=9, column=1, sticky="nsew", pady=8)
        controls = tk.Frame(container, bg=WHITE)
        controls.grid(row=10, column=0, columnspan=2, sticky="e", pady=(15, 0))
        button(controls, "Cancel", self.top.destroy, color=PALE_BLUE,
               text_color=BLUE).pack(side="left", padx=8)
        button(controls, "Save changes" if record_id else "Add task",
               self.save).pack(side="left")

        if record_id is not None:
            record = store.get_record(app.uid, record_id)
            for title, cid in self.cat_ids.items():
                if cid == record["cat_id"]:
                    self.cat_choice.configure(state="readonly")
                    self.cat_choice.set(title)
                    # In a cat-specific window, do not accidentally move records.
                    if cat_id is not None:
                        self.cat_choice.configure(state="disabled")
                    break
            self.category.set(record["category"])
            self.category_changed(clear_task=False)
            self.task.set(record["task"])
            self.record_date.delete(0, "end")
            self.record_date.insert(0, record["record_date"])
            self.due_date.delete(0, "end")
            self.due_date.insert(0, record["next_due"] or "")
            self.notes.insert("1.0", record["notes"] or "")
        self.task.focus_set()

    def category_changed(self, event=None, clear_task=True):
        self.task.configure(values=TASK_IDEAS.get(self.category.get(), ()))
        if clear_task:
            self.task.set("")

    def set_due(self, days):
        value = (date.today() + timedelta(days=days)).isoformat()
        self.due_date.delete(0, "end")
        self.due_date.insert(0, value)

    def show_picker(self, box, clearable):
        if self.picker is not None and self.picker.top.winfo_exists():
            self.picker.top.destroy()
        self.picker = DatePicker(self.top, box, allow_clear=clearable)

    def save(self):
        chosen = self.cat_ids.get(self.cat_choice.get())
        if chosen is None:
            messagebox.showerror("Select a cat", "Please select a cat.", parent=self.top)
            return
        try:
            fields = (chosen, self.category.get(), self.task.get().strip(),
                      require_date(self.record_date.get(), "Record date"),
                      require_date(self.due_date.get(), "Next due", optional=True),
                      text_value(self.notes))
            if self.record_id is None:
                store.add_record(self.app.uid, *fields)
            else:
                store.update_record(self.app.uid, self.record_id, *fields)
        except (ValueError, *ERRORS) as exc:
            messagebox.showerror("Could not save task", str(exc), parent=self.top)
            return
        self.top.destroy()
        self.app.refresh_views()


if __name__ == "__main__":
    try:
        PetCareApp().run()
    except (sqlite3.Error, OSError) as error:
        print("Unable to start Cat Care:", error, file=sys.stderr)
        raise
