"""Example vulnerable code for testing UniSecure code scanner.

WARNING: This code contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import os
import sqlite3


# SQL Injection vulnerability
def get_user_by_id(user_id):
    """Get user from database (VULNERABLE TO SQL INJECTION)."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: Using string formatting with user input
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()


# Hardcoded credentials
def connect_to_api():
    """Connect to API (HARDCODED CREDENTIALS)."""
    # Vulnerable: Hardcoded credentials in source code
    api_key = "sk_live_abcdef123456789"
    password = "MySecretPassword123"
    
    return {
        'api_key': api_key,
        'password': password
    }


# Command injection vulnerability
def run_system_command(filename):
    """Run system command (VULNERABLE TO COMMAND INJECTION)."""
    # Vulnerable: Using os.system with user input
    os.system(f"cat {filename}")


# Path traversal vulnerability
def read_user_file(filename):
    """Read user file (VULNERABLE TO PATH TRAVERSAL)."""
    # Vulnerable: No validation of file path
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()


# Another SQL injection example
def search_products(search_term):
    """Search products (VULNERABLE TO SQL INJECTION)."""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    # Vulnerable: Concatenating user input in SQL query
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()


if __name__ == '__main__':
    print("This is example vulnerable code for testing UniSecure scanner.")
    print("These vulnerabilities are intentional for demonstration purposes.")
