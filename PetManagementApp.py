import tkinter as tk
from tkinter import ttk, messagebox
from datetime import date, datetime

import database as db

# ---------- Colors ----------
BLUE = "#4560d8"
PAGE_BG = "#f5f7fb"
CARD_BG = "#e8edff"
TEXT = "#1e293b"
MUTED = "#64748b"
WHITE = "#ffffff"
GRAY = "#64748b"
RED = "#c0485f"

# ---------- Database setup ----------
db.init_db()
db.seed_sample_data()  # delete this line once you've entered your own cats


# ---------- Small helpers ----------
def parse_date(text, field, required=False):
    """Return an ISO date string, None if blank, or raise ValueError."""
    text = text.strip()
    if not text:
        if required:
            raise ValueError(f"{field} is required.")
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date().isoformat()
    except ValueError:
        raise ValueError(f"{field} must look like YYYY-MM-DD (for example 2026-10-17).")


def make_button(parent, text, command, bg):
    # A Label is used instead of tk.Button because buttons ignore colors on macOS.
    btn = tk.Label(parent, text=text, bg=bg, fg=WHITE, font=("Arial", 10, "bold"),
                   padx=14, pady=8, cursor="hand2")
    btn.bind("<Button-1>", lambda event: command())
    return btn


def make_entry(parent, width=22):
    return tk.Entry(parent, width=width, bg=WHITE, fg=TEXT, insertbackground=TEXT,
                    relief="flat", font=("Arial", 10),
                    highlightthickness=1, highlightbackground="#334155",
                    highlightcolor=BLUE)


def set_entry(entry, value):
    entry.delete(0, tk.END)
    entry.insert(0, value or "")


def make_table(parent, columns, headings, widths):
    """Return (frame, tree). Grid or pack the frame, use the tree for data."""
    frame = tk.Frame(parent, bg=WHITE, highlightbackground="#9aa5b8",
                     highlightthickness=1)
    tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
    scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scroll.set)
    for col, head, width in zip(columns, headings, widths):
        tree.heading(col, text=head, anchor="center")
        tree.column(col, width=width, anchor="w")
    tree.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    return frame, tree


def add_field(parent, row, text):
    tk.Label(parent, text=text, bg=WHITE, fg=TEXT,
             font=("Arial", 10)).grid(row=row, column=0, sticky="w", pady=6, padx=(0, 14))
    entry = make_entry(parent)
    entry.grid(row=row, column=1, sticky="w", pady=6, ipady=4)
    return entry


def add_combo(parent, row, text, values):
    tk.Label(parent, text=text, bg=WHITE, fg=TEXT,
             font=("Arial", 10)).grid(row=row, column=0, sticky="w", pady=6, padx=(0, 14))
    combo = ttk.Combobox(parent, values=values, state="readonly", width=21)
    combo.grid(row=row, column=1, sticky="w", pady=6)
    return combo


def add_hint(parent, row, text):
    tk.Label(parent, text=text, bg=WHITE, fg=MUTED,
             font=("Arial", 8)).grid(row=row, column=1, sticky="w")


def add_form_title(parent, text):
    tk.Label(parent, text=text, bg=WHITE, fg=BLUE,
             font=("Arial", 10, "bold")).grid(row=0, column=0, columnspan=2,
                                              sticky="w", pady=(4, 10))


def add_page_title(parent, title, subtitle):
    tk.Label(parent, text=title, bg=WHITE, fg=TEXT,
             font=("Arial", 16, "bold")).pack(anchor="w", padx=20, pady=(16, 0))
    tk.Label(parent, text=subtitle, bg=WHITE, fg=MUTED,
             font=("Arial", 10)).pack(anchor="w", padx=20, pady=(2, 10))


def attention_status(record, today):
    """'Overdue' / 'Due today' for open records that need attention, else None."""
    if record["status"] != "Open" or not record["next_due"]:
        return None
    due = date.fromisoformat(record["next_due"])
    if due < today:
        return "Overdue"
    if due == today:
        return "Due today"
    return None


# ---------- Window ----------
root = tk.Tk()
root.geometry("860x600")
root.minsize(780, 540)
root.title("Pet Management APP")
root.configure(bg=PAGE_BG)
root.eval("tk::PlaceWindow . center")

# ---------- Styles ----------
style = ttk.Style()
style.theme_use("clam")  # "clam" respects colors on macOS
style.configure("TNotebook", background=PAGE_BG, borderwidth=0)
style.configure("TNotebook.Tab", background="#e8edf5", foreground=TEXT,
                font=("Arial", 10, "bold"), padding=(14, 6))
style.map("TNotebook.Tab",
          background=[("selected", WHITE)],
          foreground=[("selected", BLUE)])
style.configure("Treeview", background=WHITE, fieldbackground=WHITE,
                foreground=TEXT, rowheight=26, font=("Arial", 10))
style.map("Treeview", background=[("selected", BLUE)],
          foreground=[("selected", WHITE)])
style.configure("Treeview.Heading", background=CARD_BG, foreground=TEXT,
                font=("Arial", 10, "bold"), relief="solid", padding=5)
style.map("Treeview.Heading", background=[("active", CARD_BG)])
style.configure("TCombobox", fieldbackground=WHITE, background=CARD_BG,
                foreground=TEXT, arrowcolor=TEXT, padding=4)
style.map("TCombobox",
          fieldbackground=[("readonly", WHITE)],
          foreground=[("readonly", TEXT)],
          selectbackground=[("readonly", WHITE)],
          selectforeground=[("readonly", TEXT)])
root.option_add("*TCombobox*Listbox.background", WHITE)
root.option_add("*TCombobox*Listbox.foreground", TEXT)
root.option_add("*TCombobox*Listbox.selectBackground", BLUE)
root.option_add("*TCombobox*Listbox.selectForeground", WHITE)

# ---------- Header ----------
header = tk.Frame(root, bg=BLUE)
header.pack(fill="x")
tk.Label(header, text="CAT CARE  /  HEALTH TRACKER", bg=BLUE, fg=WHITE,
         font=("Arial", 18, "bold")).pack(anchor="w", padx=28, pady=(14, 0))
tk.Label(header, text="Keep your cat's records, routines, and reminders in one place.",
         bg=BLUE, fg="#dbe3ff", font=("Arial", 10)).pack(anchor="w", padx=28, pady=(0, 10))

# ---------- Tabs ----------
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=18, pady=(14, 14))

dashboard_tab = tk.Frame(notebook, bg=WHITE)
profiles_tab = tk.Frame(notebook, bg=WHITE)
records_tab = tk.Frame(notebook, bg=WHITE)
notebook.add(dashboard_tab, text="Dashboard")
notebook.add(profiles_tab, text="Cat Profiles")
notebook.add(records_tab, text="Care Records")

# =====================================================================
# DASHBOARD TAB
# =====================================================================
add_page_title(dashboard_tab, "Your care overview",
               "Tasks due today or overdue appear below.")

cards = tk.Frame(dashboard_tab, bg=WHITE)
cards.pack(fill="x", padx=20)
for col in range(3):
    cards.columnconfigure(col, weight=1, uniform="card")

stat_values = {}  # kept so refresh_all() can update the numbers
for col, (key, title) in enumerate([("profiles", "CAT PROFILES"),
                                    ("records", "TOTAL RECORDS"),
                                    ("due", "DUE OR OVERDUE")]):
    card = tk.Frame(cards, bg=CARD_BG, highlightbackground="#d5dcf7",
                    highlightthickness=1)
    card.grid(row=0, column=col, sticky="ew", padx=6)
    tk.Label(card, text=title, bg=CARD_BG, fg=MUTED,
             font=("Arial", 9, "bold")).pack(pady=(12, 0))
    value_label = tk.Label(card, text="0", bg=CARD_BG, fg=BLUE,
                           font=("Arial", 28, "bold"))
    value_label.pack(pady=(0, 10))
    stat_values[key] = value_label

tk.Label(dashboard_tab, text="Needs attention", bg=WHITE, fg=TEXT,
         font=("Arial", 11, "bold")).pack(anchor="w", padx=20, pady=(18, 6))

attention_frame, attention_table = make_table(
    dashboard_tab,
    ("cat", "task", "category", "due", "status"),
    ("Cat", "Task", "Category", "Due date", "Status"),
    (80, 230, 110, 100, 90))
attention_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

# =====================================================================
# CAT PROFILES TAB
# =====================================================================
add_page_title(profiles_tab, "Cat profiles",
               "Add or select a cat to edit its information.")

profiles_body = tk.Frame(profiles_tab, bg=WHITE)
profiles_body.pack(fill="both", expand=True, padx=20, pady=(0, 20))
profiles_body.columnconfigure(0, weight=3)
profiles_body.columnconfigure(1, weight=2)
profiles_body.rowconfigure(0, weight=1)

cat_frame, cat_table = make_table(
    profiles_body,
    ("name", "breed", "birthday"),
    ("Name", "Breed", "Birthday"),
    (120, 160, 110))
cat_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 28))

profile_form = tk.Frame(profiles_body, bg=WHITE)
profile_form.grid(row=0, column=1, sticky="n")
add_form_title(profile_form, "PROFILE DETAILS")
name_entry = add_field(profile_form, 1, "Name *")
breed_entry = add_field(profile_form, 2, "Breed")
birthday_entry = add_field(profile_form, 3, "Birthday")
add_hint(profile_form, 4, "YYYY-MM-DD or blank")
cat_notes_entry = add_field(profile_form, 5, "Notes")

profile_buttons = tk.Frame(profile_form, bg=WHITE)
profile_buttons.grid(row=6, column=0, columnspan=2, sticky="w", pady=(14, 0))

cat_state = {"cat_id": None}  # which cat is currently loaded in the form


def clear_cat_form():
    cat_state["cat_id"] = None
    for entry in (name_entry, breed_entry, birthday_entry, cat_notes_entry):
        set_entry(entry, "")
    cat_table.selection_remove(cat_table.selection())
    name_entry.focus_set()


def on_cat_select(event=None):
    selection = cat_table.selection()
    if not selection:
        return
    cat = db.get_cat(int(selection[0]))
    if cat is None:
        return
    cat_state["cat_id"] = cat["cat_id"]
    set_entry(name_entry, cat["name"])
    set_entry(breed_entry, cat["breed"])
    set_entry(birthday_entry, cat["birthday"])
    set_entry(cat_notes_entry, cat["notes"])


def save_cat():
    name = name_entry.get().strip()
    if not name:
        messagebox.showerror("Missing name", "Name is required.")
        return
    try:
        birthday = parse_date(birthday_entry.get(), "Birthday")
    except ValueError as error:
        messagebox.showerror("Invalid date", str(error))
        return
    breed = breed_entry.get().strip() or None
    notes = cat_notes_entry.get().strip() or None

    if cat_state["cat_id"] is None:
        cat_id = db.add_cat(name, breed, birthday, notes)
    else:
        cat_id = cat_state["cat_id"]
        db.update_cat(cat_id, name, breed, birthday, notes)

    refresh_all()
    cat_table.selection_set(str(cat_id))  # also reloads the form via on_cat_select
    cat_table.see(str(cat_id))


def delete_cat():
    if cat_state["cat_id"] is None:
        messagebox.showinfo("Select a cat", "Click a cat in the list first.")
        return
    name = name_entry.get().strip() or "this cat"
    if not messagebox.askyesno(
            "Delete profile",
            f"Delete {name} and all of their care records?\nThis can't be undone."):
        return
    db.delete_cat(cat_state["cat_id"])
    clear_cat_form()
    refresh_all()


make_button(profile_buttons, "Save profile", save_cat, BLUE).pack(side="left")
make_button(profile_buttons, "New", clear_cat_form, GRAY).pack(side="left", padx=6)
make_button(profile_buttons, "Delete", delete_cat, RED).pack(side="left")
cat_table.bind("<<TreeviewSelect>>", on_cat_select)

# =====================================================================
# CARE RECORDS TAB
# =====================================================================
add_page_title(records_tab, "Care records & reminders",
               "Save feeding, medication, vet visits, and other care activities.")

records_body = tk.Frame(records_tab, bg=WHITE)
records_body.pack(fill="both", expand=True, padx=20, pady=(0, 20))
records_body.columnconfigure(0, weight=3)
records_body.columnconfigure(1, weight=2)
records_body.rowconfigure(0, weight=1)

records_left = tk.Frame(records_body, bg=WHITE)
records_left.grid(row=0, column=0, sticky="nsew", padx=(0, 24))

records_frame, records_table = make_table(
    records_left,
    ("cat", "type", "task", "date", "next_due", "status"),
    ("Cat", "Type", "Task / Record", "Date", "Next due", "Status"),
    (55, 85, 150, 85, 85, 75))
records_frame.pack(fill="both", expand=True)
records_table.tag_configure("done", foreground=MUTED)

records_buttons = tk.Frame(records_left, bg=WHITE)
records_buttons.pack(anchor="w", pady=(12, 0))

record_form = tk.Frame(records_body, bg=WHITE)
record_form.grid(row=0, column=1, sticky="n")
add_form_title(record_form, "NEW CARE RECORD")
cat_combo = add_combo(record_form, 1, "Cat *", [])
category_combo = add_combo(record_form, 2, "Category *", db.CATEGORIES)
category_combo.set(db.CATEGORIES[0])
task_entry = add_field(record_form, 3, "Task *")
date_entry = add_field(record_form, 4, "Date *")
next_due_entry = add_field(record_form, 5, "Next due")
add_hint(record_form, 6, "Dates: YYYY-MM-DD")
record_notes_entry = add_field(record_form, 7, "Notes")
set_entry(date_entry, date.today().isoformat())

cat_choices = {}  # dropdown text such as "Luna (#2)" -> cat_id


def add_record():
    label = cat_combo.get()
    if label not in cat_choices:
        messagebox.showerror("No cat selected",
                             "Add a cat on the Cat Profiles tab first.")
        return
    task = task_entry.get().strip()
    if not task:
        messagebox.showerror("Missing task", "Task is required.")
        return
    try:
        record_date = parse_date(date_entry.get(), "Date", required=True)
        next_due = parse_date(next_due_entry.get(), "Next due")
    except ValueError as error:
        messagebox.showerror("Invalid date", str(error))
        return

    db.add_record(cat_choices[label], category_combo.get(), task, record_date,
                  next_due, record_notes_entry.get().strip() or None)

    for entry in (task_entry, next_due_entry, record_notes_entry):
        set_entry(entry, "")
    set_entry(date_entry, date.today().isoformat())
    refresh_all()


def toggle_selected_record():
    selection = records_table.selection()
    if not selection:
        messagebox.showinfo("Select a record", "Click a record in the list first.")
        return
    record_id = selection[0]
    db.toggle_record_status(int(record_id))
    refresh_all()
    records_table.selection_set(record_id)


def delete_selected_record():
    selection = records_table.selection()
    if not selection:
        messagebox.showinfo("Select a record", "Click a record in the list first.")
        return
    if not messagebox.askyesno("Delete record",
                               "Delete the selected record?\nThis can't be undone."):
        return
    db.delete_record(int(selection[0]))
    refresh_all()


make_button(records_buttons, "Mark complete / reopen",
            toggle_selected_record, BLUE).pack(side="left")
make_button(records_buttons, "Delete selected",
            delete_selected_record, RED).pack(side="left", padx=8)
make_button(record_form, "Add care record", add_record, BLUE).grid(
    row=8, column=0, columnspan=2, sticky="w", pady=(14, 0))


# =====================================================================
# LOAD DATA FROM SQLITE INTO THE WINDOW
# =====================================================================
def refresh_all():
    """Re-read the database and redraw every list, dropdown, and number."""
    today = date.today()
    cats = db.list_cats()
    records = db.list_records()

    # Cat Profiles table
    cat_table.delete(*cat_table.get_children())
    for cat in cats:
        cat_table.insert("", "end", iid=str(cat["cat_id"]),
                         values=(cat["name"], cat["breed"] or "", cat["birthday"] or ""))

    # Cat dropdown on the Care Records form
    cat_choices.clear()
    for cat in cats:
        cat_choices[f"{cat['name']} (#{cat['cat_id']})"] = cat["cat_id"]
    labels = list(cat_choices)
    cat_combo["values"] = labels
    if cat_combo.get() not in cat_choices:
        cat_combo.set(labels[0] if labels else "")

    # Care Records table
    records_table.delete(*records_table.get_children())
    for r in records:
        records_table.insert(
            "", "end", iid=str(r["record_id"]),
            values=(r["cat_name"], r["category"], r["task"], r["record_date"],
                    r["next_due"] or "", r["status"]),
            tags=("done",) if r["status"] == "Completed" else ())

    # Dashboard: open records that are due today or overdue
    due_rows = []
    for r in records:
        status = attention_status(r, today)
        if status:
            due_rows.append((r["next_due"], r, status))
    due_rows.sort(key=lambda item: item[0])

    attention_table.delete(*attention_table.get_children())
    for _, r, status in due_rows:
        attention_table.insert("", "end", values=(
            r["cat_name"], r["task"], r["category"], r["next_due"], status))

    stat_values["profiles"].config(text=str(len(cats)))
    stat_values["records"].config(text=str(len(records)))
    stat_values["due"].config(text=str(len(due_rows)))


refresh_all()
root.mainloop()
