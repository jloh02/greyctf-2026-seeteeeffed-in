<!--
Copy this README.md when starting a new challenge.

Required sections are Name, Description, Author, and Flag.

Read the Whale section below if the challenge needs per-team/per-user instances.
-->

# Name
Profile Sync

# Description

CTFs are the best chance to connect with others. Find out who else is in this CTF! But make sure to make your connections fast - the DB resets every 5 mins.

# Author
jloh02

# Flag
`flag{refint_cascade_update_sql_injection}`

# Challenge

A web challenge for CVE-2026-6637.

# Local Verification

Run the stack and then execute:

```bash
python solve/exploit_refint.py --base-url http://127.0.0.1:8080
```

The exploit registers a fresh player, uses the automatically created anchor username, triggers the vulnerable cascade update, and surfaces the flag in the visible `profile_cache` field on that player's own session mirror.

# Automatic Reset

The default compose stack reapplies `db/init.sql` every 5 minutes so shared deployments recover automatically from persistent state corruption and session spam:

```bash
docker compose up --build
```

Change the cadence by overriding `RESET_INTERVAL_SECONDS` on the `db-reset` service.
