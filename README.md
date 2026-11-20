# PetCare

Desktop cat-care management app built with **Python, Tkinter and SQLite**

## Files

- `PetManagementApp.py` — main application, database operations, GUI and email-reminder command.
- `database.py` — SQLite connection helpers, schema, basic data validation.
- `tests/test_petcare.py` — automated tests; **never sends a real email**.
- `.github/workflows/tests.yml` — runs tests automatically on GitHub pushes and pull requests.

No third-party Python packages are needed. Use **Python 3.11+** with Tkinter installed. Some Linux installations require an OS package such as `python3-tk`.

## Start the app

1. **Back up your existing project and especially `data/petcare.db`** before replacing files or trying a migration. If you already have a `database.py`, back it up too: the copy in this package was reconstructed from the interface used by your uploaded main file.
2. Keep `PetManagementApp.py` next to `database.py`.
3. In this folder, run:

   ```bash
   python PetManagementApp.py
   ```

4. Register or sign in. The app creates `data/petcare.db` on first launch if it doesn't already exist. If you already have a compatible database, `init()` adds new columns/tables **without intentionally deleting existing records**.

For testing with a separate database, set `PETCARE_DB_PATH` to a temporary SQLite file before running the app. Never run unfamiliar upgrades on your only copy of real data.

## 1. Recurring tasks

Open a cat profile or **Quick task**. Set its **Next due** date and choose **Repeat**:

- Never
- Daily
- Weekly
- Monthly
- Every 3 months
- Yearly

When you mark an open recurring task **Completed**, the original stays in the history and the app creates the **next open occurrence** automatically. The next date is calculated from the **scheduled due date**, not the date you clicked Completed. Monthly/yearly tasks maintain their original day when possible (January 31 → February 28 → March 31). A task must have a due date in order to repeat.

If you reopen a completed recurring task, the app removes its generated next occurrence **only if it's still unchanged and open**. If the next occurrence was edited or completed, reopening the old record is blocked to protect the established schedule. Edit the current occurrence instead.

Future occurrences aren't all generated in advance: the next one is created when you complete the current one.

## 2. Optional email reminders

Email is **off by default**. After signing in, choose **Notifications → Email settings…** or the **Email settings** button. Enter your email address, enable notifications, and select **0, 1, 3 or 7 days** of advance notice. You can click **Send test email** to verify SMTP settings.

The app sends a **single digest email** for all matching, still-open tasks in your account. It includes overdue tasks and tasks due within your selected advance-notice window. Each task is normally emailed **once per due date**, not every day. If you edit its due date, it can be notified again for the new date. An unsuccessful email send is *not* recorded as delivered and can be retried.

### Configure SMTP securely

**You must supply an SMTP provider and credentials.** Never paste secrets into `PetManagementApp.py`, the SQLite database, tests, or GitHub. Some email providers require a separate app password or token.

On **macOS/Linux** in a terminal (replace placeholders with details from your email provider):

```bash
export PETCARE_SMTP_HOST="smtp.example.com"
export PETCARE_SMTP_PORT="587"
export PETCARE_SMTP_USERNAME="you@example.com"
export PETCARE_SMTP_PASSWORD="YOUR_SMTP_APP_PASSWORD"
export PETCARE_SMTP_FROM="you@example.com"
python PetManagementApp.py
```

On **Windows PowerShell**, set the equivalent environment variables before launching Python:

```powershell
$env:PETCARE_SMTP_HOST="smtp.example.com"
$env:PETCARE_SMTP_PORT="587"
$env:PETCARE_SMTP_USERNAME="you@example.com"
$env:PETCARE_SMTP_PASSWORD="YOUR_SMTP_APP_PASSWORD"
$env:PETCARE_SMTP_FROM="you@example.com"
python PetManagementApp.py
```

**Port 587** uses SMTP + STARTTLS. **Port 465** uses SMTP over SSL. TLS certificate verification is enabled. SMTP sending has a 12-second timeout. Email preferences are saved per user, but **SMTP passwords are read from environment variables only**. Email addresses in local SQLite are not encrypted.

### When are emails sent?

- **While the app is running:** it checks after ~10 seconds, then every 30 minutes, using a background thread so Tkinter stays responsive.
- **When the app is closed:** nothing runs on its own. Schedule the following command using Windows Task Scheduler, macOS `launchd`, or Linux `cron`:

  ```bash
  python /full/path/to/PetManagementApp.py --send-reminders
  ```

  Configure the scheduler to supply the five `PETCARE_SMTP_*` environment variables. The command uses the same database file as the app; it runs **without opening a GUI**. Running it daily (e.g. morning) provides daily checks, while reminders still send **only once per task and due date**. It exits with a nonzero status if sending failed.

  For cron, an example schedule is `0 8 * * * /full/path/to/python /full/path/to/PetManagementApp.py --send-reminders` **provided SMTP variables are securely available to that process**. Choose a full interpreter path and don't put passwords in your crontab or repository.

### Email troubleshooting

- No email: confirm you enabled notifications and saved a valid address. Try **Send test email**.
- Provider rejects login: use the provider's supported SMTP authentication method and (if supported) an app password rather than your normal account password.
- Your app is closed: schedule `--send-reminders`; a Tkinter desktop app can't send by itself while closed.
- Duplicate alerts on the same date shouldn't happen for a sent notification: delivery is tracked in SQLite. If due dates change, a new notice is allowed.

## 3. Automated testing

From the project folder:

```bash
python -m unittest discover -s tests -v
```

The tests create **temporary databases**, replace expensive hashing parameters *only for tests*, and mock the SMTP sender so **no messages are sent and your real `data/petcare.db` is not touched**. They cover account isolation, legacy-data migration, repeating schedules, month-end dates, task completion/reopening, editing/exports, notification timing, opt-in privacy, deduplication, failed-email retries, deletion cleanup, SMTP TLS configuration and headless CLI error handling.

When you upload this folder's contents to the root of a GitHub repository, GitHub Actions can run the tests on every push and pull request using `.github/workflows/tests.yml`.

## Important notes

- The uploaded main file referenced a `database.py` that was **not provided**. The package therefore includes a **compatible replacement**. Its migration was tested on a simulated earlier schema, but compatibility with your specific original `database.py` and existing data was **not** verified. Back up the database before using this version on real data.
- Automated tests were executed locally. The GUI was also smoke-tested in a virtual X display. **Live SMTP delivery was not tested** because no account credentials were supplied.
- No GUI window is needed to run automated tests or the `--send-reminders` command.
- Accounts and cat-care records are stored locally in SQLite; the database itself is **not encrypted**. Protect your computer and backups accordingly.
