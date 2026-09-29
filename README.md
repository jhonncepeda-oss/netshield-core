# NetShield Core

Network Security Auditing Engine built with Python (FastAPI), Supabase, and Clean Architecture principles.

## Features
* Automated auditing of Cisco IOS configuration files.
* Identification of security vulnerabilities (Telnet enabled, plaintext passwords, missing timeouts).
* Automatic redaction of sensitive data (Passwords, SNMP strings).
* Centralized reporting via Supabase.
* Rich CLI and REST API.

## Setup
1. Clone the repository.
2. Run `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and configure your Supabase keys.
4. Run the API: `python main.py api` or run the CLI: `python main.py --config path/to/config.cfg ...`
