# PetCare

PetCare is a desktop app we created using Python, Tkinter, and SQLite. Our goal was to make it easier to keep track of our cats' information and things like feeding, medication, vaccinations, and vet appointments.

## What the app can do

- Create an account and log in.
- Add, edit, and manage cat profiles.
- Add tasks with due dates and mark them as completed.
- Set tasks to repeat daily, weekly, monthly, every three months, or yearly.
- View upcoming and overdue tasks.
- Export records to CSV or JSON.

## Project files

- PetManagementApp.py – The main program, including the Tkinter interface and reminder features.
- database.py – Handles the SQLite database and checks that saved data is valid.
- test_petcare.py – Automated tests that we run on our computer.
- data/petcare.db – The local database that stores user and cat information.

The project uses Python 3.11 or newer. It doesn't need any extra Python packages, but Tkinter needs to be installed.

## How to run it

We open the project folder in VS Code and make sure the terminal is in the folder containing PetManagementApp.py.

Then we run:

bash python3 PetManagementApp.py 

Once the application opens, we can create an account or log in with an existing one.

The application saves all information in a local SQLite database.

Important: If we update an older version, we make sure to back up data/petcare.db and database.py first so we don't accidentally lose any information.

## 1. Recurring Tasks

We added recurring tasks because some cat-care activities need to be done regularly, such as giving medication or scheduling vaccinations.

When creating or editing a task, we can choose how often it repeats.

The available options are:

- Never
- Daily
- Weekly
- Monthly
- Every 3 months
- Yearly

For example, if we create a medication task that repeats daily, the application automatically creates the next task when we mark the current one as completed.

The completed task stays in the history so we can still see which tasks have already been finished.

We also made sure that monthly tasks handle dates correctly. For example, a task scheduled for January 31 would repeat on February 28 and then March 31.

The application only creates the next task after the current one is completed instead of creating every future task at once.

## 2. Automated Testing

We also added automated testing to help make sure the main features of our application work correctly.

For this, we used Python's built-in unittest library.

This allows us to test different parts of the program without having to manually go through every feature each time we make changes.

### How We Run the Tests

We run the tests directly from the terminal in VS Code.

First, we open the folder containing test_petcare.py.

Then we enter:

bash python3 -m unittest discover -s . -p "test_*.py" -v 

Python automatically finds the test file and runs the tests.

The results appear in the terminal.

If a test passes, it shows:

text test_example ... ok 

If something goes wrong, it displays FAIL or ERROR along with information about the problem.

When all the tests pass, the terminal displays something similar to:

text Ran 20 tests  OK 

This lets us check whether our changes are working correctly.

### What We Test

Our automated tests cover several important parts of the application, including:

- Creating user accounts and logging in.
- Checking that users can only access their own data.
- Creating and completing recurring tasks.
- Calculating the next date for recurring tasks.
- Editing and exporting records.
- Making sure database changes work correctly.
- Checking email notification settings.
- Preventing duplicate email reminders.
- Handling unsuccessful email attempts.

The tests use temporary databases, so they don't affect the actual information saved in our application.

Email sending is also simulated during automated testing, which means the tests don't send real emails.

### Manual Testing

Besides automated testing, we also test the application ourselves by using its interface.

For example, we can:

1. Create a test account and log in.
2. Add a cat profile.
3. Create a medication task that repeats daily.
4. Mark the task as completed.
5. Check that the next task is automatically created.
6. Open the calendar and check the upcoming tasks.
7. Configure email notifications and send a test email.

This helps us check that the application works correctly from a user's perspective and not just through the automated tests.

## Additional Notes

The application stores its information locally using SQLite.

The database itself is not encrypted, so it's important to keep backups and protect the computer where the application is installed.

SMTP passwords are provided through environment variables rather than being stored in the program.

The automated tests don't send real emails, so actual email delivery needs to be checked separately using the test email feature.

Overall, our main goal with this project was to create an application that makes it easier to organize cat-care information and keep track of important tasks.

By adding recurring tasks and email notifications, we made the application more useful because users don't have to remember or manually recreate every task themselves.
