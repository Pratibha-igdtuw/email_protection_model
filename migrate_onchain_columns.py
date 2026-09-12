"""
One-off migration: add onchain_* columns to chain_blocks if missing.
Run with: python migrate_onchain_columns.py
"""
import sqlite3
import os

DB_PATH = os.path.join("instance", "threat_platform.db")

def column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cur.fetchall())

def main():
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH} -- check path / run from project root.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    columns_to_add = [
        ("onchain_status", "VARCHAR(24) NOT NULL DEFAULT 'not_configured'"),
        ("onchain_tx_hash", "VARCHAR(80)"),
        ("onchain_network", "VARCHAR(32)"),
        ("onchain_confirmed_at", "DATETIME"),
        ("onchain_error", "TEXT"),
    ]

    for col_name, col_def in columns_to_add:
        if column_exists(cur, "chain_blocks", col_name):
            print(f"Skipping {col_name} (already exists)")
            continue
        sql = f"ALTER TABLE chain_blocks ADD COLUMN {col_name} {col_def}"
        print(f"Running: {sql}")
        cur.execute(sql)

    conn.commit()
    conn.close()
    print("Done. chain_blocks schema updated.")

if __name__ == "__main__":
    main()