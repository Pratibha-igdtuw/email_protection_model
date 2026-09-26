"""
One-off migration for the multi-source evidence ingestion + incident
timeline update:
  - creates the new evidence_items table (Evidence model) if missing
  - adds attachment_flags / url_flags columns to cases if missing

Run with: python migrate_evidence_and_timeline.py
"""
import sqlite3
import os

DB_PATH = os.path.join("instance", "threat_platform.db")


def column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cur.fetchall())


def table_exists(cur, table):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None


def main():
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH} -- check path / run from project root.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # --- cases: attachment_flags / url_flags (modules/timeline.py) ---
    for col_name, col_def in [("attachment_flags", "TEXT"), ("url_flags", "TEXT")]:
        if column_exists(cur, "cases", col_name):
            print(f"Skipping cases.{col_name} (already exists)")
            continue
        sql = f"ALTER TABLE cases ADD COLUMN {col_name} {col_def}"
        print(f"Running: {sql}")
        cur.execute(sql)

    # --- evidence_items table (Evidence model / modules/evidence_ingest.py) ---
    if table_exists(cur, "evidence_items"):
        print("Skipping evidence_items (already exists)")
    else:
        print("Creating evidence_items table")
        cur.execute("""
            CREATE TABLE evidence_items (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER REFERENCES users(id),
                evidence_ref VARCHAR(32) NOT NULL UNIQUE,
                evidence_type VARCHAR(24) NOT NULL,
                original_filename VARCHAR(512),
                stored_path VARCHAR(512),
                file_size INTEGER,
                mime_type VARCHAR(128),
                sha256 VARCHAR(64) NOT NULL,
                metadata_json TEXT,
                linked_case_ref VARCHAR(32),
                notes TEXT,
                uploaded_at DATETIME
            )
        """)
        cur.execute("CREATE INDEX ix_evidence_items_owner_id ON evidence_items (owner_id)")
        cur.execute("CREATE INDEX ix_evidence_items_linked_case_ref ON evidence_items (linked_case_ref)")

    conn.commit()
    conn.close()
    print("Done. Schema updated for evidence ingestion + timeline flags.")


if __name__ == "__main__":
    main()