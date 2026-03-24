# Deployment Guide

## Database Backup Strategy

Health Watchers stores protected health information (PHI). Automated daily backups are required to meet HIPAA data availability obligations.

### Overview

| Property | Value |
|---|---|
| Database | MongoDB |
| Tool | `mongodump` / `mongorestore` |
| Schedule | Daily at 02:00 UTC |
| Retention | 30 days |
| Format | Compressed `.tar.gz` (mongodump `--gzip` + tar) |
| Storage | `/var/backups/health-watchers/` (override with `BACKUP_DIR`) |

Backups are encrypted at rest by the host filesystem/volume encryption (e.g. AWS EBS encryption, LUKS). Ensure the storage volume has encryption enabled before deploying.

---

### Running a Backup Manually

```bash
# Uses MONGO_URI from environment; falls back to localhost default
MONGO_URI="mongodb://localhost:27017/health_watchers" ./scripts/backup.sh
```

The script produces a file named `backup-YYYY-MM-DD.tar.gz` in `BACKUP_DIR` and automatically deletes archives older than 30 days.

---

### Automated Cron Job

Add the following entry to the crontab of the user running the application (`crontab -e`):

```cron
# Health Watchers — daily MongoDB backup at 02:00 UTC
0 2 * * * MONGO_URI="mongodb://localhost:27017/health_watchers" BACKUP_DIR="/var/backups/health-watchers" /path/to/health_watchers/scripts/backup.sh >> /var/log/health-watchers-backup.log 2>&1
```

Replace `/path/to/health_watchers` with the absolute path to the project root.

Verify the cron is registered:

```bash
crontab -l
```

---

### Restore Procedure

1. Identify the backup archive to restore:

```bash
ls /var/backups/health-watchers/backup-*.tar.gz
```

2. Extract the archive:

```bash
tar -xzf /var/backups/health-watchers/backup-YYYY-MM-DD.tar.gz \
    -C /tmp/hw-restore
```

3. Restore with `mongorestore`:

```bash
mongorestore \
  --uri="mongodb://localhost:27017/health_watchers" \
  --gzip \
  --drop \
  /tmp/hw-restore/dump-YYYY-MM-DD
```

> `--drop` removes existing collections before restoring. Omit it if you want to merge instead of replace.

4. Verify the restore:

```bash
mongosh "mongodb://localhost:27017/health_watchers" --eval "db.stats()"
```

5. Clean up the temporary extraction directory:

```bash
rm -rf /tmp/hw-restore
```

---

### Testing the Restore (Recommended Before Production)

Run against a staging database to confirm data integrity without touching production:

```bash
mongorestore \
  --uri="mongodb://localhost:27017/health_watchers_staging" \
  --gzip \
  --drop \
  /tmp/hw-restore/dump-YYYY-MM-DD
```

Confirm record counts match the source database before promoting.
