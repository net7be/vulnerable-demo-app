# Project overview

`cmd/tasks-server` is a JSON API with endpoints allowing users to:

- Create new tasks
- Mark a task as done
- Delete tasks (admin only)
- Assign a task to another user (admin only)
- Authenticate as a certain user using a password
- Create a new user (admin only) - Provides a randomly generated password in the response

Tasks have the following data:
- name
- status (done or in progress)
- date when it was created (automatically added on creation)
- assigned user (defaults to user who created the task)

We need to save **tasks** and **users** in a **sqlite** database to be created as `db/tasks.db`.

The program has a routine to create the database if it does not exist and applies migrations according to a DB version tracking system.

Create an "initial" migration with the basic database structure and a default "admin" user and a random password written in the console the first time the migration is done.

The API itself uses the `net/http` package.
