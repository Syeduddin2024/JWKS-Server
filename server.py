# Import required libraries
import base64
import json
import jwt
import datetime
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs


# Filename for the database to store keys
database_file = "totally_not_my_privateKeys.db"

# Local host name and port number for the HTTP server
local_host = "localhost"
port_number = 8080

# Generate a new RSA private key
generated_private_keys = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Generate an expired RSA private key
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Convert the generated private key to PEM format
private_key_pem = generated_private_keys.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert the expired private key to PEM format
expired_key_pem = expired_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Extract private numbers from the generated private key
private_key_numbers = generated_private_keys.private_numbers()

# Function to create the keys table in the database if it doesn't exist
def create_keys_table():
    conn = sqlite3.connect(database_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to insert a key into the database
def insert_key(key, exp):
    conn = sqlite3.connect(database_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    conn.commit()
    conn.close()

# Function to retrieve an unexpired or expired key from the database
def get_key(expired=False):
    conn = sqlite3.connect(database_file)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT * FROM keys WHERE exp <= ?", (int(time.time()),))
    else:
        cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    row = cursor.fetchone()
    conn.close()
    return row

# Function to retrieve all unexpired keys from the database
def get_keys():
    conn = sqlite3.connect(database_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    rows = cursor.fetchall()
    conn.close()
    return rows

# Function to convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Define a custom HTTP request handler class
class MyServer(BaseHTTPRequestHandler):

    # Handle HTTP PUT requests by sending a 405 Method Not Allowed response
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    # Handle HTTP PATCH requests by sending a 405 Method Not Allowed response
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    # Handle HTTP DELETE requests by sending a 405 Method Not Allowed response
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    # Handle HTTP HEAD requests by sending a 405 Method Not Allowed response
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Modified the do_POST method to handle /auth requests
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Retrieve the private key from the database
            key_record = get_key('expired' in params)
            if key_record is not None:
                token_headers = {
                    "kid": str(key_record[0])
                }
                token_claims = {
                    "exp": key_record[2]
                }
                private_keys = serialization.load_pem_private_key(key_record[1], None)
                signed_jwt = jwt.encode(token_claims, private_keys, algorithm="RS256", headers=token_headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(signed_jwt, "utf-8"))
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Private key not found.")
            return

    # Modified the do_GET method to handle requests for the JWKS endpoint
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            key_record = get_keys()
            jwks_list = []
            print(key_record)
            for key_entry in key_record:
                key_numbers = serialization.load_pem_private_key(key_entry[1], None).private_numbers()
                jwks_list.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key_entry[0]),
                    "n": int_to_base64(key_numbers.public_numbers.n),
                    "e": int_to_base64(key_numbers.public_numbers.e),
                })
            response_data = {
                "keys": jwks_list
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
            return

if __name__ == "__main__":

    print(f"Starting http server on {local_host}:{port_number}")
    
    # Create a table to store keys
    create_keys_table()
    
    # Insert keys into the table with an expiration timestamp
    # The first key will expire 1000 seconds from now
    insert_key(private_key_pem, int(time.time() + 1000))
    
    # The second key has already expired 1000 seconds ago
    insert_key(expired_key_pem, int(time.time() - 1000))
    
    # Create an HTTP server instance
    http_server = HTTPServer((local_host, port_number), MyServer)
    
    try:
        print("Server started. Press Ctrl+C to stop.")
        http_server.serve_forever()
    except KeyboardInterrupt:
        # Handle keyboard interrupt and display a message
        print("Server is shutting down...")
    except Exception as e:
        # Handle any other exceptions and display the error
        print(f"Error occurred: {e}")
    
    # Close the server
    http_server.server_close()

    print("Server stopped.")
