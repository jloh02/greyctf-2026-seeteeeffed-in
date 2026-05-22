<!--
Copy this README.md when starting a new challenge.

Required sections are Name, Description, Author, and Flag.

Read the Whale section below if the challenge needs per-team/per-user instances.
-->

# Name
SeeTeeEffedIn

# Description

CTFs are the best chance to connect with others. Network with others in this Grey Cat the Flag! But make sure to connect fast - the world resets every 5 mins.

# Author
jloh02

# Flag
`grey{refint_c4Scad3_Upd4t3_sq1_lnject10n}`

# Challenge

A web challenge for [CVE-2026-6637](https://www.postgresql.org/support/security/CVE-2026-6637/) running on Postgres 18.3. ([patch](https://github.com/postgres/postgres/commit/260e97733bf09acc448faea24fc6210411892b1a))

# Local Verification

Run the stack and then execute:

```bash
python solve/exploit_refint.py --base-url http://127.0.0.1:8080
```

The exploit registers a fresh player with separate public-facing and private-facing usernames, updates the private-facing username through the vulnerable cascade path, and surfaces the flag in the visible `session_note` field on that player's own session mirror. Public feed handles stay clean, so other users do not see the exploit payload in normal network activity.

# Automatic Reset

The default compose stack reapplies `db/init.sql` every 5 minutes so shared deployments recover automatically from persistent state corruption and session spam:

```bash
docker compose up --build
```

Change the cadence by overriding `RESET_INTERVAL_SECONDS` on the `db-reset` service.
