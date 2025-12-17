import sqlite3
import os
from typing import List, Dict, Optional

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'email_platforms.db')

def init_db():
    """Initialize the database with the required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create table for email-platform mappings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_platforms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            platform TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create table for platforms
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS platforms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            color TEXT DEFAULT '#4a90e2',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default platforms if they don't exist
    default_platforms = [
        ('Steam', 'Gaming platform for PC games', '#00adee'),
        ('Rockstar', 'Gaming platform for Rockstar games', '#fcaf17'),
        ('Epic Games', 'Gaming platform for Epic games', '#3a3a3a'),
        ('Ubisoft', 'Gaming platform for Ubisoft games', '#f5f5f5'),
        ('Microsoft', 'Microsoft services and accounts', '#00bcf2'),
        ('Google', 'Google services and accounts', '#4285f4'),
        ('Apple', 'Apple services and accounts', '#a2aaad'),
        ('Amazon', 'Amazon services and accounts', '#ff9900'),
        ('Netflix', 'Streaming service', '#e50914'),
        ('Spotify', 'Music streaming service', '#1db954'),
        ('Business', 'Business-related accounts', '#4a90e2'),
        ('Personal', 'Personal accounts', '#50c878'),
        ('Social Media', 'Social media accounts', '#8a3ab9'),
        ('Banking', 'Financial institutions', '#009900'),
        ('Other', 'Miscellaneous accounts', '#6c757d')
    ]
    
    for platform in default_platforms:
        cursor.execute(
            'INSERT OR IGNORE INTO platforms (name, description, color) VALUES (?, ?, ?)',
            platform
        )
    
    conn.commit()
    conn.close()

def add_email_platform(email: str, platform: str, notes: str = '') -> bool:
    """Add or update an email-platform mapping"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO email_platforms 
            (email, platform, notes, updated_at) 
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (email, platform, notes))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error adding email-platform mapping: {e}")
        return False

def get_email_platform(email: str) -> Optional[Dict]:
    """Get the platform for a specific email"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT email, platform, notes, created_at, updated_at
            FROM email_platforms 
            WHERE email = ?
        ''', (email,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'email': row[0],
                'platform': row[1],
                'notes': row[2],
                'created_at': row[3],
                'updated_at': row[4]
            }
        return None
    except Exception as e:
        print(f"Error getting email platform: {e}")
        return None

def get_all_email_platforms() -> List[Dict]:
    """Get all email-platform mappings"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT email, platform, notes, created_at, updated_at
            FROM email_platforms
            ORDER BY platform, email
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'email': row[0],
                'platform': row[1],
                'notes': row[2],
                'created_at': row[3],
                'updated_at': row[4]
            }
            for row in rows
        ]
    except Exception as e:
        print(f"Error getting all email platforms: {e}")
        return []

def get_platform_statistics() -> List[Dict]:
    """Get statistics for each platform"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT platform, COUNT(*) as count
            FROM email_platforms
            GROUP BY platform
            ORDER BY count DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{'platform': row[0], 'count': row[1]} for row in rows]
    except Exception as e:
        print(f"Error getting platform statistics: {e}")
        return []

def get_all_platforms() -> List[Dict]:
    """Get all available platforms"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, description, color
            FROM platforms
            ORDER BY name
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'name': row[0],
                'description': row[1],
                'color': row[2]
            }
            for row in rows
        ]
    except Exception as e:
        print(f"Error getting all platforms: {e}")
        return []

def delete_email_platform(email: str) -> bool:
    """Delete an email-platform mapping"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM email_platforms WHERE email = ?', (email,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error deleting email-platform mapping: {e}")
        return False

# Initialize the database when this module is imported
init_db()