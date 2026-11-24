# File Integrity Monitor — hardened edition

Windows 10/11, Python 3.10+.

## Install and run

```powershell
py -m pip install -r requirements.txt
py main.py
```

Run as your ordinary Windows account for normal monitoring. Security Event Log access may require elevated permissions, and Security 4663 events require both Object Access auditing and file/folder SACL entries. Sysmon must be installed and configured separately. Events are correlations, **not proof of who modified a file**.

## What's improved

- **Atomic baseline + event history sealing:** A keyed HMAC covers folders, file hashes, and the complete SQLite event history. The seal lives in the same SQLite database transaction as the records it protects, preventing a crash between a commit and a separate seal-file update. A DPAPI-protected key is stored in `%LOCALAPPDATA%\SimpleFIM\baseline.key.dpapi`.
- **Legacy migration:** On first run with the previous version, the old baseline seal is verified, then a new database seal is established. Pre-migration event history was *not* protected before this migration; sealing it now does not retroactively prove authenticity.
- **Selective hashing:** Regular scans skip hashing when size and nanosecond modification time are unchanged; every 5 minutes a full hash verification is performed. Watchdog triggers earlier scans. This is a performance trade-off, not a guarantee against timestamp manipulation.
- **Read failures:** Read errors are recorded once per continuously failing path. The monitor does not treat unreadable files as deleted.
- **Event investigation:** Windows Security 4663 and Sysmon 11/23/26 are searched with a larger bounded scan window (up to 5000 recent records per channel), showing user, process, and access mask when available.
- **Critical notifications:** A critical change produces a single high-priority alert instead of two duplicate notifications.
- **Exports, tray operation, detailed file history, and notifications** are retained.

## Upgrade and recovery

1. Back up `%LOCALAPPDATA%\SimpleFIM` while the old app is **closed**, including `fim.db`, any `fim.db-wal` / `fim.db-shm`, `baseline.key.dpapi`, and `baseline.seal`.
2. Extract this package to a new directory, install requirements, and run.
3. If the legacy seal is valid, the app migrates it. Do not delete the DPAPI key.
4. If verification fails, investigate before taking recovery action. The **Reset Baseline** button permanently deletes tracked folders, saved hashes, and event history, then creates a fresh seal. Export or preserve the database first if you need forensic evidence.
5. If the DPAPI key cannot be decrypted (for example, a different Windows user profile), recovery requires restoring the original profile/key or manually archiving the old application data and starting with a new empty app data directory. Do not mistake this for proof of an attack.

## Security limitations

- Same-user malware and administrators may read/write the database and obtain access to the DPAPI-unprotected key via the user's session. This is tamper-evidence, **not** tamper-proof audit logging. For stronger assurance, forward logs to a remote append-only collector.
- This is polling plus filesystem notifications, not a kernel driver or Windows service. The application must be running in the logged-in session. Changes can be missed if made and reverted between scans, or if the application is offline.
- Hashes are compared against the **latest observed state**, not an immutable golden baseline. A trusted immutable reference requires a separate approval workflow.
- Directory traversal errors suppress deletion detection for that scan. Some junctions and reparse points may require additional handling.
- Full-history HMAC verification is O(number of events). Very large databases may need a checkpointed hash-chain design.
- Windows toast notifications depend on OS notification settings. Files protected by Windows permissions may be unreadable.

## Test safely

Create `C:\FIM_Test` and add it to the app. Create, edit, and delete files; verify `CREATED`, `MODIFIED`, and `DELETED` events. Change a file's modification timestamp without changing its contents to test `METADATA`. Deny read access to a test file to test `READ_ERROR`. Close to tray, reopen, and export CSV/TXT. To test tamper detection, **back up** the database, close the app, alter a row with a SQLite tool, and reopen. The app should lock the baseline.
