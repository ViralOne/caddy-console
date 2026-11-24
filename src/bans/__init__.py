"""IP bans: manual file mode (docs/security.md, spec Phase 1).

State lives in BACKUP_DIR/bans.json; the generated Caddy policy lives in
BANS_DIR/bans-manual.caddy; both change only through txn.apply_locked().
"""
