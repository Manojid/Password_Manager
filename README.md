# Secure Password Manager

A local password manager with both a command-line and a Tkinter GUI interface,
built to explore secure key derivation and symmetric encryption in Python.

## Features

- **Master-password protected** — a single master password unlocks your vault.
- **PBKDF2-HMAC-SHA256** key derivation (390,000 iterations) from the master
  password, so the encryption key is never stored directly.
- **Fernet (AES-128-CBC + HMAC)** symmetric encryption for every stored entry.
- **Startup verification** — a canary value is encrypted and checked on login,
  so a wrong master password is caught immediately instead of failing later
  on individual entries.
- **Cryptographically secure password generator** (`secrets` module, not `random`).
- Add / view / delete individual entries, or clear the whole vault.
- CLI (`Password_manager.py`) and GUI (`Password_manager_gui.py`) share the
  same encrypted data files, so either interface can be used interchangeably.

## Threat model

This protects data **at rest** — someone who steals `passwords.txt`, `key.key`,
and `check.key` without your master password cannot recover the stored
passwords (short of brute-forcing the master password itself). It does
**not** protect against keyloggers, memory scraping, or a compromised
machine while the vault is unlocked. It's a learning project, not a
production-grade password manager — for real-world use, prefer an
established tool (Bitwarden, 1Password, KeePass).

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### CLI

```bash
python Password_manager.py
```

Menu options: View, Add, Delete entry, Clear all, Quit.

### GUI

```bash
python Password_manager_gui.py
```

Enter your master password in the dialog, then use the Add / View / Copy /
Delete / Clear All buttons.

## How it works

1. On first run, a random 16-byte salt is generated and stored in `key.key`.
2. Your master password + salt are run through PBKDF2-HMAC-SHA256
   (390,000 iterations) to derive a 256-bit key, base64-encoded for Fernet.
3. A canary value is encrypted with that key and stored in `check.key` to
   verify future logins use the correct master password.
4. Each entry's password is encrypted individually with Fernet and stored
   as `name|token` in `passwords.txt`.

## Files generated at runtime (not committed)

- `key.key` — the PBKDF2 salt
- `check.key` — the encrypted canary used to verify the master password
- `passwords.txt` — your encrypted vault entries

These are excluded via `.gitignore` since they're personal, per-installation
data — never commit your real vault files to a public repo.
