"""Headless automated regression tests. No email is ever sent over the network."""

import csv
import json
import os
import subprocess
import sys
import sqlite3
import tempfile
import unittest
from datetime import date
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import database as db
import PetManagementApp as app


class PetCareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db_patch = patch.object(db, "DB_PATH", Path(self.tmp.name) / "petcare_test.db")
        db_patch.start()
        self.addCleanup(db_patch.stop)
        fast_passwords = patch.object(app, "ITERATIONS", 1000)
        fast_passwords.start()
        self.addCleanup(fast_passwords.stop)
        app.init()
        self.alice = app.register("alice", "password123")["user_id"]
        self.bob = app.register("bob", "password234")["user_id"]
        self.cat = app.add_cat(self.alice, "Luna", "Tabby")
        self.bobcat = app.add_cat(self.bob, "Milo")

    def add_task(self, due="2026-11-20", repeat="Never", cat=None, uid=None,
                 task="Medication"):
        record_date = min("2026-11-19", due) if due else "2026-11-19"
        return app.add_record(uid or self.alice, cat or self.cat, "Medication", task,
                              record_date, due, "once with food", repeat)

    def test_registration_login_hash_and_user_isolation(self):
        self.assertEqual(app.login("ALICE", "password123")["user_id"], self.alice)
        with self.assertRaises(app.AccountError):
            app.login("alice", "incorrect")
        with self.assertRaises(app.AccountError):
            app.register("alice", "password123")
        self.assertEqual(len(app.list_cats(self.bob)), 1)
        with self.assertRaises(app.OwnershipError):
            app.get_cat(self.bob, self.cat)
        with self.assertRaises(app.OwnershipError):
            app.add_record(self.bob, self.cat, "Feeding", "Feed", "2026-11-20")
        self.assertEqual(app.list_records(self.bob), [])

    def test_repeat_date_calculation_all_intervals(self):
        cases = [
            ("2026-11-20", "Daily", "2026-11-21"),
            ("2026-11-20", "Weekly", "2026-11-27"),
            ("2026-01-31", "Monthly", "2026-02-28"),
            ("2024-01-31", "Monthly", "2024-02-29"),
            ("2026-11-30", "Every 3 months", "2027-02-28"),
            ("2024-02-29", "Yearly", "2025-02-28"),
            ("2026-12-31", "Daily", "2027-01-01"),
        ]
        for starting, interval, result in cases:
            with self.subTest(starting=starting, interval=interval):
                self.assertEqual(app.next_recurrence(starting, interval), result)
        with self.assertRaises(app.AccountError):
            app.next_recurrence("2026-11-20", "Never")

    def test_repeat_requires_due_date_and_valid_rule(self):
        with self.assertRaises(app.AccountError):
            self.add_task(None, "Daily")
        with self.assertRaises(app.AccountError):
            self.add_task("2026-11-20", "Every 15 minutes")
        self.assertEqual(app.get_record(self.alice, self.add_task(None))["next_due"], None)

    def test_completing_repeat_generates_child_and_keeps_history(self):
        initial = self.add_task(repeat="Weekly")
        app.toggle_record_status(self.alice, initial)
        tasks = app.list_records(self.alice)
        self.assertEqual(len(tasks), 2)
        old = app.get_record(self.alice, initial)
        self.assertEqual(old["status"], "Completed")
        next_task = next(r for r in tasks if r["record_id"] != initial)
        self.assertEqual(next_task["next_due"], "2026-11-27")
        self.assertEqual(next_task["record_date"], "2026-11-27")
        self.assertEqual(next_task["repeat_interval"], "Weekly")
        self.assertEqual(next_task["status"], "Open")
        with closing(db.get_connection()) as conn:
            self.assertEqual(conn.execute(
                "SELECT recurrence_parent_id FROM care_record WHERE record_id = ?",
                (next_task["record_id"],)).fetchone()[0], initial)
        app.toggle_record_status(self.alice, next_task["record_id"])
        self.assertEqual(len(app.list_records(self.alice)), 3)

    def test_reopen_repeat_removes_untouched_child_then_can_repeat(self):
        initial = self.add_task(repeat="Daily")
        app.toggle_record_status(self.alice, initial)
        self.assertEqual(len(app.list_records(self.alice)), 2)
        app.toggle_record_status(self.alice, initial)
        self.assertEqual(len(app.list_records(self.alice)), 1)
        self.assertEqual(app.get_record(self.alice, initial)["status"], "Open")
        app.toggle_record_status(self.alice, initial)
        self.assertEqual(len(app.list_records(self.alice)), 2)

    def test_cannot_reopen_completed_chain_and_edited_child(self):
        initial = self.add_task(repeat="Monthly")
        app.toggle_record_status(self.alice, initial)
        child = next(r for r in app.list_records(self.alice)
                     if r["record_id"] != initial)
        app.update_record(self.alice, child["record_id"], self.cat,
                          child["category"], "Changed", child["record_date"],
                          child["next_due"], child["notes"], "Monthly")
        with self.assertRaises(app.AccountError):
            app.toggle_record_status(self.alice, initial)
        self.assertEqual(app.get_record(self.alice, initial)["status"], "Completed")

    def test_recurring_completion_atomic_when_scheduling_fails(self):
        initial = self.add_task(repeat="Daily")
        with patch.object(app, "next_recurrence", side_effect=ValueError("bad")):
            with self.assertRaises(ValueError):
                app.toggle_record_status(self.alice, initial)
        self.assertEqual(app.get_record(self.alice, initial)["status"], "Open")
        self.assertEqual(len(app.list_records(self.alice)), 1)

    def test_nonrepeat_toggle_does_not_spawn_tasks(self):
        rec = self.add_task()
        app.toggle_record_status(self.alice, rec)
        app.toggle_record_status(self.alice, rec)
        self.assertEqual(len(app.list_records(self.alice)), 1)
        self.assertEqual(app.get_record(self.alice, rec)["status"], "Open")

    def test_recurring_record_owner_isolation(self):
        rec = self.add_task(repeat="Yearly")
        with self.assertRaises(app.OwnershipError):
            app.toggle_record_status(self.bob, rec)
        with self.assertRaises(app.OwnershipError):
            app.update_record(self.bob, rec, self.bobcat, "Feeding", "Feed",
                              "2026-11-20", "2026-11-20", "", "Daily")
        self.assertEqual(len(app.list_records(self.alice)), 1)

    def test_edit_repeat_and_exports(self):
        rec = self.add_task()
        app.update_record(self.alice, rec, self.cat, "Medication", "Medication",
                          "2026-11-19", "2026-11-20", "once with food", "Daily")
        self.assertEqual(app.get_record(self.alice, rec)["repeat_interval"], "Daily")
        path = Path(self.tmp.name) / "care.csv"
        app.export_records_csv(self.alice, path)
        with path.open(newline="", encoding="utf-8") as fh:
            exported = list(csv.DictReader(fh))
        self.assertEqual(exported[0]["repeat_interval"], "Daily")
        path = Path(self.tmp.name) / "care.json"
        app.export_account_json(self.alice, path)
        data = json.loads(path.read_text())
        self.assertEqual(data["cats"][0]["records"][0]["repeat_interval"], "Daily")
        self.assertEqual(len(data["cats"]), 1)

    def test_email_preferences_validation_and_owner_scoping(self):
        self.assertEqual(app.get_email_preferences(self.alice)["enabled"], False)
        app.set_email_preferences(self.alice, "alice@example.com", True, 3)
        self.assertEqual(app.get_email_preferences(self.alice),
                         {"email": "alice@example.com", "enabled": True,
                          "lead_days": 3})
        self.assertEqual(app.get_email_preferences(self.bob)["email"], "")
        with self.assertRaises(app.AccountError):
            app.set_email_preferences(self.alice, "evil@example.com\nBcc: foo", True, 1)
        with self.assertRaises(app.AccountError):
            app.set_email_preferences(self.alice, "", True, 1)
        with self.assertRaises(app.AccountError):
            app.set_email_preferences(self.alice, "alice@example.com", True, 4)

    def test_notification_digest_lead_time_and_deduplication(self):
        self.add_task("2026-11-21", "Daily")
        future = self.add_task("2026-12-05", task="Future medication")
        self.add_task("2026-11-17", task="Overdue medication")
        self.add_task("2026-11-20", cat=self.bobcat, uid=self.bob, task="Bob medication")
        app.set_email_preferences(self.alice, "alice@example.com", True, 1)
        seen = []
        sender = lambda to, subject, body: seen.append((to, subject, body))
        first = app.send_due_notifications(today="2026-11-20", smtp_sender=sender)
        self.assertEqual(first, {"users_sent": 1, "tasks_notified": 2, "errors": []})
        self.assertEqual(len(seen), 1)
        self.assertIn("Luna", seen[0][2])
        self.assertNotIn("Future medication", seen[0][2])
        self.assertNotIn("Bob medication", seen[0][2])
        second = app.send_due_notifications(date(2026, 11, 20), sender)
        self.assertEqual(second["tasks_notified"], 0)
        self.assertEqual(len(seen), 1)
        # If a due date changes after a delivery, the new due date can be notified.
        app.update_record(self.alice, future, self.cat, "Medication", "Future medication",
                          "2026-11-19", "2026-11-21", "", "Never")
        again = app.send_due_notifications(date(2026, 11, 20), sender)
        self.assertEqual(again["tasks_notified"], 1)

    def test_notification_send_failure_retries_and_does_not_log(self):
        rec = self.add_task()
        app.set_email_preferences(self.alice, "alice@example.com", True, 0)
        def fail(*args):
            raise OSError("simulated SMTP outage")
        outcome = app.send_due_notifications(date(2026, 11, 20), fail)
        self.assertEqual(outcome["tasks_notified"], 0)
        self.assertEqual(len(outcome["errors"]), 1)
        delivery = []
        outcome = app.send_due_notifications(date(2026, 11, 20),
                                             lambda *args: delivery.append(args))
        self.assertEqual(outcome["tasks_notified"], 1)
        self.assertEqual(len(delivery), 1)
        app.delete_record(self.alice, rec)
        with closing(db.get_connection()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM notification_delivery")
                             .fetchone()[0], 0)

    def test_email_disable_reminders_and_future_reminders(self):
        self.add_task()
        app.set_email_preferences(self.alice, "alice@example.com", False, 1)
        seen = []
        result = app.send_due_notifications(date(2026, 11, 20),
                                            lambda *args: seen.append(args))
        self.assertEqual(result["users_sent"], 0)
        self.assertFalse(seen)

    def test_delete_account_removes_email_preferences_and_records(self):
        rec = self.add_task(repeat="Daily")
        app.set_email_preferences(self.alice, "alice@example.com", True, 1)
        app.send_due_notifications(date(2026, 11, 20), lambda *args: None)
        app.delete_account(self.alice, "password123")
        with closing(db.get_connection()) as conn:
            self.assertIsNone(conn.execute(
                "SELECT * FROM email_preference WHERE user_id = ?", (self.alice,)
            ).fetchone())
            self.assertIsNone(conn.execute(
                "SELECT * FROM notification_delivery WHERE record_id = ?", (rec,)
            ).fetchone())
        self.assertEqual(len(app.list_cats(self.bob)), 1)

    def test_month_end_anchor_survives_multiple_completions(self):
        rec = self.add_task("2026-01-31", "Monthly")
        app.toggle_record_status(self.alice, rec)
        feb = max(app.list_records(self.alice), key=lambda r: r["record_id"])
        self.assertEqual(feb["next_due"], "2026-02-28")
        app.toggle_record_status(self.alice, feb["record_id"])
        march = max(app.list_records(self.alice), key=lambda r: r["record_id"])
        self.assertEqual(march["next_due"], "2026-03-31")
        self.assertEqual(march["repeat_interval"], "Monthly")

    def test_scheduled_cli_headless_without_smtp_does_not_fake_delivery(self):
        self.add_task("2020-01-01")
        app.set_email_preferences(self.alice, "alice@example.com", True, 1)
        env = os.environ.copy()
        for key in ("PETCARE_SMTP_HOST", "PETCARE_SMTP_USERNAME",
                    "PETCARE_SMTP_PASSWORD", "PETCARE_SMTP_FROM"):
            env.pop(key, None)
        env["PETCARE_DB_PATH"] = str(db.DB_PATH)
        finished = subprocess.run(
            [sys.executable, str(Path(app.__file__)), "--send-reminders"],
            capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(finished.returncode, 1)
        self.assertIn("SMTP is not configured", finished.stderr)
        with closing(db.get_connection()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM notification_delivery")
                             .fetchone()[0], 0)

    def test_smtp_transport_tls_mocked(self):
        creds = {
            "PETCARE_SMTP_HOST": "mail.example.com",
            "PETCARE_SMTP_USERNAME": "sender",
            "PETCARE_SMTP_PASSWORD": "secret",
            "PETCARE_SMTP_FROM": "sender@example.com",
            "PETCARE_SMTP_PORT": "587",
        }
        with patch.dict(app.os.environ, creds):
            with patch.object(app.smtplib, "SMTP") as smtp:
                app.send_email("recipient@example.com", "Hello", "Body")
                smtp.assert_called_once_with("mail.example.com", 587, timeout=12)
                channel = smtp.return_value.__enter__.return_value
                channel.starttls.assert_called_once()
                channel.login.assert_called_once_with("sender", "secret")
                message = channel.send_message.call_args.args[0]
                self.assertEqual(message["To"], "recipient@example.com")
        creds["PETCARE_SMTP_PORT"] = "465"
        with patch.dict(app.os.environ, creds):
            with patch.object(app.smtplib, "SMTP_SSL") as smtp_ssl:
                app.send_email("recipient@example.com", "Hello", "Body")
                smtp_ssl.assert_called_once()

    def test_migration_preserves_existing_records(self):
        with closing(db.get_connection()) as conn:
            with conn:
                conn.execute("INSERT INTO cat (name) VALUES ('Old cat')")
                old_cat = conn.execute("SELECT MAX(cat_id) FROM cat").fetchone()[0]
                conn.execute("INSERT INTO care_record (cat_id, category, task, "
                             "record_date, next_due) VALUES (?, 'Feeding', 'Dinner', "
                             "'2026-11-19', '2026-11-20')", (old_cat,))
        app.init()
        with closing(db.get_connection()) as conn:
            self.assertEqual(conn.execute(
                "SELECT repeat_interval FROM care_record WHERE cat_id = ?",
                (old_cat,)).fetchone()[0], "Never")
            self.assertIsNotNone(conn.execute(
                "SELECT name FROM cat WHERE cat_id = ?", (old_cat,)).fetchone())


class LegacyMigrationTests(unittest.TestCase):
    def test_existing_database_is_migrated_without_losing_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "existing_database.db"
            # Simulate the original app database, predating accounts/recurrence.
            with closing(sqlite3.connect(path)) as conn:
                with conn:
                    conn.execute("""CREATE TABLE cat (
                        cat_id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                        breed TEXT, birthday TEXT, notes TEXT)""")
                    conn.execute("""CREATE TABLE care_record (
                        record_id INTEGER PRIMARY KEY, cat_id INTEGER NOT NULL,
                        category TEXT NOT NULL, task TEXT NOT NULL,
                        record_date TEXT NOT NULL, next_due TEXT, notes TEXT,
                        status TEXT DEFAULT 'Open')""")
                    conn.execute("INSERT INTO cat (cat_id, name) VALUES (99, 'Legacy Luna')")
                    conn.execute("""INSERT INTO care_record
                        (record_id, cat_id, category, task, record_date, next_due)
                        VALUES (123, 99, 'Feeding', 'Dinner', '2026-11-01', '2026-11-20')""")
            with patch.object(db, "DB_PATH", path), patch.object(app, "ITERATIONS", 1000):
                app.init()
                self.assertEqual(app.legacy_import_available(), 1)
                user = app.register("legacy", "password123", import_legacy=True)
                cats = app.list_cats(user["user_id"])
                self.assertEqual(cats[0]["cat_id"], 99)
                tasks = app.list_records(user["user_id"])
                self.assertEqual(tasks[0]["record_id"], 123)
                self.assertEqual(tasks[0]["repeat_interval"], "Never")
                app.init()  # Multiple launches must be idempotent.
                self.assertEqual(len(app.list_records(user["user_id"])), 1)


if __name__ == "__main__":
    unittest.main()
