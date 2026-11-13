"""Cat Care / Health Tracker — single-file application with local user accounts.

Keep this file next to your existing database.py; do not delete data/petcare.db.
Run using the Python interpreter that displayed Tkinter successfully, e.g.:
    python3.14 PetManagementApp.py

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
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
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


def button(parent, label, command, *, color=BLUE, text_color=WHITE, width=None):
    return tk.Button(
        parent, text=label, command=command, bg=color, fg=text_color,
        activebackground=BLUE_DARK if color == BLUE else color,
        activeforeground=text_color, relief="flat", bd=0,
        padx=14, pady=8, cursor="hand2", font=("Arial", 10, "bold"),
        width=width, highlightthickness=0,
    )


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
    tree.tag_configure("done", foreground=MUTED)
    tree.tag_configure("overdue", foreground=RED)
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


class PetCareApp:
    def __init__(self):
        store.init()  # Adds account tables/ownership without removing original petcare.db data.
        self.root = tk.Tk()
        self.root.title("Cat Care | Health Tracker")
        self.root.geometry("1100x760")
        self.root.minsize(820, 580)
        self.root.configure(bg=BG)
        mac_light_appearance(self.root)
        self.user = None
        self.shell = None
        self.cat_windows = {}
        self.dialogs = set()

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
        """Build ONE reusable auth form; toggling modes does not stack forms.

        Previously, switching between two independently created screens could
        leave stale-looking native button drawings on some macOS/Tk builds.
        A single card with a single pair of buttons avoids that path.
        """
        self.user = None
        self.root.config(menu="")
        base = self.new_shell()
        base.columnconfigure(0, weight=1)
        base.rowconfigure(0, weight=1)

        card = tk.Frame(base, bg=WHITE, highlightbackground=BORDER,
                        highlightthickness=1)
        card.grid(row=0, column=0, sticky="", padx=24, pady=26)
        inner = tk.Frame(card, bg=WHITE, padx=42, pady=38)
        inner.pack(fill="both")
        inner.columnconfigure(0, minsize=140)
        inner.columnconfigure(1, minsize=275, weight=1)

        label(inner, "CAT CARE", size=24, bold=True, fg=BLUE).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        label(inner, "Your cats, care routines, and reminders in one place.",
              fg=MUTED, wraplength=410, justify="left").grid(
                  row=1, column=0, columnspan=2, sticky="w", pady=(0, 24))

        title = label(inner, "Welcome back", bold=True, size=16)
        title.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 14))
        username_box = field(inner, "Username", 3)
        password_box = field(inner, "Password", 4, show="*")

        # The confirm-password widgets are created only once, then hidden
        # when the form is in login mode.
        confirm_label = label(inner, "Confirm password", bold=True)
        confirm_label.grid(row=5, column=0, sticky="w", pady=8, padx=(0, 12))
        confirm_box = entry(inner, show="*")
        confirm_box.grid(row=5, column=1, sticky="ew", pady=8, ipady=5)

        hint = label(inner, "", fg=MUTED, size=9, wraplength=410,
                     justify="left")
        hint.grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 10))
        error_text = tk.StringVar(value="")
        error_label = label(inner, "", textvariable=error_text, fg=RED,
                            wraplength=410, justify="left")
        error_label.grid(row=7, column=0, columnspan=2, sticky="w", pady=(0, 8))

        mode = tk.BooleanVar(value=bool(register))

        def submit():
            try:
                name = username_box.get()
                password = password_box.get()
                if mode.get():
                    if password != confirm_box.get():
                        raise store.AccountError("Passwords do not match.")
                    older = store.legacy_import_available()
                    take_old = False
                    if older:
                        take_old = messagebox.askyesno(
                            "Keep your existing cats?",
                            f"Found {older} cat profile(s) from before accounts existed.\n\n"
                            "Import them into this first account?\n\n"
                            "Yes = Keep these cats and their care records in your new account.\n"
                            "No = Leave the old data untouched and unassigned.",
                            parent=self.root,
                        )
                    self.user = store.register(name, password, import_legacy=take_old)
                else:
                    self.user = store.login(name, password)
            except (store.AccountError, sqlite3.Error) as exc:
                error_text.set(str(exc))
                return
            self.show_home()

        primary = button(inner, "Log in", submit)
        primary.grid(row=8, column=0, columnspan=2,
                     sticky="ew", pady=(8, 12), ipady=5)

        def toggle_mode():
            mode.set(not mode.get())
            update_mode()

        secondary = button(inner, "New here? Create an account", toggle_mode,
                           color=PALE_BLUE, text_color=BLUE)
        secondary.grid(row=9, column=0, columnspan=2, sticky="ew", ipady=4)

        def update_mode():
            is_register = mode.get()
            title.configure(text="Create an account" if is_register else "Welcome back")
            hint.configure(text=(
                "Username: 3–32 letters, numbers, _, . or -  •  Password: 8+ characters"
                if is_register else "Sign in to see only your own cats and care records."
            ))
            primary.configure(text="Create account" if is_register else "Log in")
            secondary.configure(text=("Already have an account? Log in"
                                      if is_register else "New here? Create an account"))
            if is_register:
                confirm_label.grid()
                confirm_box.grid()
            else:
                confirm_label.grid_remove()
                confirm_box.grid_remove()
                confirm_box.delete(0, "end")
            error_text.set("")

        update_mode()
        password_box.bind("<Return>", lambda event: submit())
        confirm_box.bind("<Return>", lambda event: submit())
        username_box.focus_set()

    def install_menu(self):
        menu = tk.Menu(self.root)
        data_menu = tk.Menu(menu, tearoff=False)
        data_menu.add_command(label="Export my care records (CSV)...",
                              command=self.export_csv)
        data_menu.add_command(label="Export my account data (JSON)...",
                              command=self.export_json)
        menu.add_cascade(label="Data", menu=data_menu)
        self.root.config(menu=menu)

    def show_home(self):
        self.install_menu()
        base = self.new_shell()
        header = tk.Frame(base, bg=BLUE)
        header.pack(fill="x")
        header_inner = tk.Frame(header, bg=BLUE)
        header_inner.pack(fill="x", padx=24, pady=15)
        label(header_inner, "CAT CARE  /  HEALTH TRACKER", size=17,
              bold=True, fg=WHITE, bg=BLUE).pack(side="left")
        button(header_inner, "Log out", self.logout, color=WHITE,
               text_color=BLUE).pack(side="right", padx=(8, 0))
        button(header_inner, "Delete account", self.delete_my_account,
               color="#f5e2e7", text_color=RED).pack(side="right")
        label(base, f"Signed in as {self.user['username']}",
              bg=BG, fg=MUTED).pack(anchor="w", padx=26, pady=(10, 0))

        body = tk.Frame(base, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        top = tk.Frame(body, bg=BG)
        top.pack(fill="x", pady=(5, 9))
        label(top, "My cats", bold=True, size=20, bg=BG).pack(side="left")
        button(top, "+ Add cat", self.add_cat).pack(side="right")
        button(top, "+ Quick task", self.quick_task, color=GREEN).pack(
            side="right", padx=9)

        stats_frame = tk.Frame(body, bg=BG)
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

        label(body, "Select a cat to open their tasks and health history.",
              bg=BG, fg=MUTED).pack(anchor="w", pady=(0, 7))
        card_region = tk.Frame(body, bg=BG)
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

        attention = tk.Frame(body, bg=BG)
        attention.pack(fill="both", pady=(12, 0))
        bar = tk.Frame(attention, bg=BG)
        bar.pack(fill="x", pady=(0, 7))
        label(bar, "Needs attention", bold=True, size=12, bg=BG).pack(side="left")
        button(bar, "Refresh", self.refresh_views, color=PALE_BLUE,
               text_color=BLUE).pack(side="right")
        frame, self.due_tree = make_tree(
            attention,
            (("cat", "Cat"), ("task", "Task"), ("category", "Category"),
             ("due", "Due"), ("status", "Status")),
            (140, 260, 140, 110, 110),
        )
        frame.pack(fill="both", expand=True)
        frame.configure(height=150)
        self.due_tree.bind("<Double-1>", self.open_due_selected)
        self.refresh_views()

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

        if not cats:
            empty = tk.Frame(self.cards_frame, bg=WHITE, padx=30, pady=25,
                             highlightbackground=BORDER, highlightthickness=1)
            empty.pack(fill="x", pady=5)
            label(empty, "No cats yet", size=15, bold=True).pack(anchor="w")
            label(empty, "Choose '+ Add cat' to create your first profile.",
                  fg=MUTED).pack(anchor="w", pady=(4, 0))
        for cat in cats:
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
        for record in due:
            status = "Overdue" if record["next_due"] < today else "Due today"
            self.due_tree.insert("", "end", iid=str(record["record_id"]),
                                 values=(record["cat_name"], record["task"],
                                         record["category"], record["next_due"],
                                         status),
                                 tags=("overdue",) if status == "Overdue" else ())
        for cat_id, window in list(self.cat_windows.items()):
            if window.top.winfo_exists():
                try:
                    window.refresh()
                except store.OwnershipError:
                    window.close()
            else:
                self.cat_windows.pop(cat_id, None)

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
        for dialog in list(self.dialogs):
            if dialog.winfo_exists():
                dialog.destroy()
        self.dialogs.clear()
        for window in list(self.cat_windows.values()):
            window.close()
        self.cat_windows.clear()
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


class CatDialog:
    """Add a new cat; profiles can also be edited from their individual window."""
    def __init__(self, app):
        self.app = app
        self.top = tk.Toplevel(app.root)
        mac_light_appearance(self.top)
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
        mac_light_appearance(self.top)
        self.top.title(f"{cat['name']} | Cat Care")
        self.top.geometry("1040x670")
        self.top.minsize(760, 500)
        self.top.configure(bg=BG)
        self.top.protocol("WM_DELETE_WINDOW", self.close)
        header = tk.Frame(self.top, bg=WHITE)
        header.pack(fill="x", padx=18, pady=(16, 8))
        self.name_label = label(header, cat["name"], size=21, bold=True)
        self.name_label.pack(side="left", padx=12, pady=10)
        button(header, "+ Add task", self.add_task, color=GREEN).pack(
            side="right", padx=12, pady=9)
        self.subtitle = label(self.top, "", bg=BG, fg=MUTED)
        self.subtitle.pack(anchor="w", padx=27, pady=(0, 9))

        self.notebook = ttk.Notebook(self.top)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.trees = {}
        self.group_keys = {}
        for title, categories in self.TAB_GROUPS:
            page = tk.Frame(self.notebook, bg=WHITE)
            self.notebook.add(page, text=title)
            label(page, title + " tasks", size=14, bold=True).pack(
                anchor="w", padx=14, pady=(12, 8))
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

        profile = tk.Frame(self.notebook, bg=WHITE, padx=22, pady=20)
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
            if group is None:  # To do (only open records)
                selected = [record for record in records if record["status"] == "Open"]
                selected.sort(key=lambda r: (r["next_due"] is None,
                                             r["next_due"] or "9999-12-31",
                                             r["task"].casefold()))
            elif group == "all":
                selected = records
            else:
                selected = [r for r in records if r["category"] in group]
            for record in selected:
                tags = ()
                if record["status"] == "Completed":
                    tags = ("done",)
                elif record["next_due"] and record["next_due"] < today:
                    tags = ("overdue",)
                tree.insert("", "end", iid=str(record["record_id"]),
                            values=(record["task"], record["category"],
                                    record["record_date"], record["next_due"] or "",
                                    record["status"]), tags=tags)

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


class TaskDialog:
    """Quick add/edit: choose a cat, preset task, and a due-date shortcut."""
    def __init__(self, app, cat_id=None, record_id=None, parent=None):
        self.app = app
        self.record_id = record_id
        self.parent = parent if parent is not None else app.root
        self.top = tk.Toplevel(self.parent)
        mac_light_appearance(self.top)
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
