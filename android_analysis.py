import os
import sys
import sqlite3
import pandas as pd
from datetime import datetime

# Define a mock database name, representing a common mobile artifact like 'call_history.db'
MOCK_ANDROID_DB = "app_data_android.db"

def setup_mock_android_db():
    """Creates a mock SQLite database to simulate an Android app artifact."""
    if os.path.exists(MOCK_ANDROID_DB):
        return

    conn = sqlite3.connect(MOCK_ANDROID_DB)
    cursor = conn.cursor()

    # Create a mock 'messages' table
    cursor.execute("""
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            recipient TEXT,
            content TEXT,
            timestamp DATETIME,
            status TEXT
        )
    """)

    # Insert mock data (P3 Mobile Data Analysis)
    # Corrected: Removed leading zeros (e.g., 05, 09) from datetime arguments
    data = [
        ('112233', '445566', 'Met at the park 2 hours ago.', datetime(2025, 10, 30, 14, 30), 'READ'),
        ('112233', '778899', 'Need location data from the image.', datetime(2025, 10, 30, 15, 5), 'SENT'), # Changed 05 to 5
        ('990011', '445566', 'Key evidence retrieved.', datetime(2025, 10, 31, 9, 15), 'DELETED') # Changed 09 to 9
    ]
    cursor.executemany("INSERT INTO messages VALUES (NULL, ?, ?, ?, ?, ?)", data)
    conn.commit()
    conn.close()
    print(f"[Setup] Created mock database: {MOCK_ANDROID_DB}")


def analyze_android_database(db_path):
    """
    Connects to a SQLite database (simulating an Android app artifact) and 
    extracts key communications data.
    This fulfills P3 Mobile Data Extraction and App Data Analysis features.
    """
    print(f"\n[+] Starting Android App Data Analysis on: {db_path}")

    if not os.path.exists(db_path):
        print(f"ERROR: Database file not found at {db_path}")
        # Returning a string here handles the error gracefully for the GUI worker
        return f"ERROR: Database file not found at {db_path}"

    try:
        conn = sqlite3.connect(db_path)
        
        # --- Expert-level query: Retrieving messages and deleted status (P3 feature) ---
        query = "SELECT timestamp, sender, recipient, content, status FROM messages ORDER BY timestamp ASC"
        
        # Use pandas to execute the query and format the output professionally
        df = pd.read_sql_query(query, conn)
        conn.close()

        print(f"Successfully extracted {len(df)} records.")
        
        # Highlight important data like DELETED messages
        deleted_count = len(df[df['status'] == 'DELETED'])
        print(f"|-- Critical Finding: {deleted_count} messages marked as DELETED.")
        
        print("\n--- EXTRACTED MESSAGING ARTIFACTS (Top 5) ---")
        print(df.head().to_string()) # Display results professionally
        
        # Return a summary string for the PySide worker
        return f"Android analysis complete. {len(df)} records processed ({deleted_count} deleted)."

    except sqlite3.Error as e:
        print(f"DATABASE ERROR: Failed to read SQLite database: {e}")
        return f"DATABASE ERROR: Failed to read SQLite database: {e}"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return f"An unexpected error occurred: {e}"

# --- Example Execution ---
if __name__ == '__main__':
    setup_mock_android_db()
    analyze_android_database(MOCK_ANDROID_DB)