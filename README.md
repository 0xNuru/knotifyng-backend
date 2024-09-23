# Knotifyng (Backend)

## Project Overview

The **Knotifyng Platform** is a robust and scalable application that aims to streamline the business operations of professionals in the wedding and event industry, e.g photographers, videographers, event planners, venue owners, and cake vendors.
The platform is designed to automate administrative tasks, simplify client interactions Built with modern web technologies, this backend ensures the secure and efficient handling of all business processes.

## Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) in this project. This leads to more readable messages that are easy to follow when looking through the project history. Also, we can use the git commit messages to generate the project change log.

### Commit Message Format

Each commit message consists of a **header** and an optional **body** and a **footer**. The header has a special format that includes a **type**, a **scope** and a **subject**:

```
<type>: <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The **header** is mandatory and the **scope** of the header is optional.

Any line of the commit message cannot be longer than 100 characters! This allows the message to be easier to read on GitHub as well as in various git tools.

### Type

Must be one of the following:

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools and libraries such as documentation generation

### Subject

The subject contains a succinct description of the change:

- use the imperative, present tense: "change" not "changed" nor "changes"
- don't capitalize the first letter
- no dot (.) at the end

### Body

Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Footer

The footer should contain any information about **Breaking Changes** and is also the place to
reference GitHub issues that this commit **Closes**.

**Breaking Changes** should start with the word `BREAKING CHANGE:` with a space or two newlines. The rest of the commit message is then used for this.

### Examples

```
feat: add 'reload' method to refresh the page
```

```
chore: remove environment variables
```

```

fix(compile): couple of unit tests for IE9

Older IEs serialize html uppercased, but IE9 does not...
Would be better to expect case insensitive, unfortunately jasmine does
not allow to user regexps for throw expectations.

Closes #392
Breaks foo.bar api, foo.baz should be used instead

```

## Technologies Used

- **Python**: The main programming language used for backend development.
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python 3.7+.
- **SQLAlchemy**: SQL toolkit and Object-Relational Mapping (ORM) library for Python, used for database interactions.
- **PostgreSQL**: A powerful, open-source object-relational database system.
- **Pydantic**: Data validation and settings management using Python type annotations.
- **Paystack**: Payment gateway used for processing transactions.
- **Boto3**: AWS SDK for Python, used for interacting with AWS services like S3.
- **Jinja2**: Templating engine for rendering HTML templates.
- **Gunicorn**: Python WSGI HTTP Server for Unix, used to serve the FastAPI application.
- **Requests**: A simple, yet elegant, HTTP library for Python, used for making API calls to external services.
- **Itsdangerous**: Used for generating random secure tokens.
- **Passlib**: Password hashing library used for secure user authentication.
- **FastAPI-Mail**: For sending emails through SMTP.
- **Pydantic Settings**: For managing environment configuration settings.

## Installation and Setup

### Prerequisites

- Python 3.7 or higher
- PostgreSQL database
- AWS account (for S3 bucket setup)
- Paystack account for payment integration

### Environment Variables Configuration

To run the backend application, you need to set up a `.env` file in the root directory of your project. This file contains critical configuration settings for connecting to services like your database, AWS, and Paystack. Below is the format for the `.env` file:

```env
# Example Database Configuration
DB_USER="postgres"
DB_PASSWORD="knotifypassword!"
DB_NAME="knotifyng"
DB_HOST="host"
DB_PORT=5432
DB_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"


# Token Settings
JWT_SECRET_KEY=""
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30000
REFRESH_TOKEN_EXPIRE_MINUTES=300

# Email Server Settings
EMAIL_HOST=
EMAIL_PORT=587
EMAIL_USERNAME=
EMAIL_PASSWORD=""
EMAIL_FROM=@.tech

# AWS S3 Configuration
S3_BUCKET_NAME="knotify"
S3_REGION="eu-north-1"
S3_ACCESS_KEY=""
S3_SECRET_KEY=""

# Paystack Configuration
PAYSTACK_SECRET_KEY=""
```

### Artchitecture

![Application Architecture](https://knotifyng.s3.eu-north-1.amazonaws.com/knotify-architecture.png)
