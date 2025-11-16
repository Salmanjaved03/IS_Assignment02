# client.py

import socket
import json
import getpass
import threading
import time
import sys
import traceback
import datetime
from pathlib import Path

# Import our helper module
import security_utils as sec
from cryptography.hazmat.primitives import serialization
from cryptography import x509  # <-- ADD THIS LINE
from cryptography.hazmat.backends import default_backend  # <-- ADD THIS LINE

HOST = 'localhost'
PORT = 65432

# Global flag to signal threads to stop
chat_active = threading.Event()

def send_secure_command(sock, key, command_data):
    """Encrypts, sends a command, and returns the decrypted response."""
    request_json = json.dumps(command_data).encode('utf-8')
    encrypted_request = sec.encrypt_aes_cbc(key, request_json)
    sock.sendall(encrypted_request)

    encrypted_response = sock.recv(4096)
    if not encrypted_response:
        raise ConnectionError("Server disconnected.")

    decrypted_response = sec.decrypt_aes_cbc(key, encrypted_response)
    if not decrypted_response:
        raise Exception("Failed to decrypt server response.")

    return json.loads(decrypted_response.decode('utf-8'))

def receive_loop(sock, session_key, server_public_key, log_file):
    """
    Thread target function to continuously receive messages.
    (This is a simple demo: a real server would send messages,
    but here we just listen for a 'logout' broadcast or error)
    """
    try:
        while chat_active.is_set():
            # This simple client doesn't expect messages *from* the server
            # in the chat loop, so we just wait.
            # A real chat app would listen here.
            # We use a timeout to check the chat_active flag.
            sock.settimeout(1.0)
            try:
                data = sock.recv(4096)
                if not data:
                    print("\n[Server disconnected. Press Enter to exit.]")
                    chat_active.clear()
                    break
                # If server *did* send a message, we'd handle it here
                # For this assignment, we'll assume it doesn't and
                # just focus on client->server.
            except socket.timeout:
                continue # Loop back up to check chat_active
            except Exception as e:
                if chat_active.is_set():
                    print(f"\n[Receiver Error: {e}]")
                    chat_active.clear()
                break
    finally:
        sock.settimeout(None)


def log_message(file_handle, message):
    """Helper to log to file."""
    file_handle.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} | {message}\n")


def main():
    """Main client function."""

    server_cert = None
    client_cert = None
    client_key = None
    session_key = None

    transcript_path = Path("client_transcript.log")

    # Open transcript file
    with transcript_path.open("a") as transcript_file:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
                log_message(transcript_file, f"Connected to server at {HOST}:{PORT}")

                # --- 1. Load Client Credentials ---
                log_message(transcript_file, "Loading client credentials...")
                client_cert = sec.load_cert("client")
                client_key = sec.load_private_key("client")
                ca_cert = sec.load_ca_cert()

                # --- 2. Control Plane: Certificate Exchange (Req 1.1, 2.1) ---
                log_message(transcript_file, "Waiting for server certificate...")
                server_cert_bytes = s.recv(4096)
                if not server_cert_bytes:
                    raise ConnectionError("Server disconnected during handshake.")

                server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())

                # --- 3. Control Plane: Mutual Verification (Req 2.1) ---
                if not sec.verify_peer_cert(server_cert, ca_cert, "localhost"):
                    raise Exception("Server certificate verification FAILED.")

                log_message(transcript_file, "Server certificate verified.")

                log_message(transcript_file, "Sending client certificate...")
                s.sendall(client_cert.public_bytes(serialization.Encoding.PEM))

                # --- 4. Control Plane: Temporary DH Exchange (Req 2.2) ---
                log_message(transcript_file, "Starting temporary DH key exchange...")
                server_dh_public_bytes = s.recv(4096)
                if not server_dh_public_bytes:
                    raise ConnectionError("Server disconnected during DH exchange.")

                client_dh_private, client_dh_public_bytes = sec.dh_generate_keys()
                s.sendall(client_dh_public_bytes)

                temp_shared_secret = sec.dh_derive_shared_secret(client_dh_private, server_dh_public_bytes)
                temp_aes_key = sec.derive_key_from_dh_secret(temp_shared_secret)
                log_message(transcript_file, "Temporary AES key established.")

                # --- 5. Control Plane: Secure Login/Register (Req 2.2) ---

                while True:
                    print("\n--- Secure Portal ---")
                    action = input("Type 'register' or 'login': ").strip().lower()

                    if action == 'register':
                        email = input("Email: ")
                        username = input("Username: ")
                        password = getpass.getpass("Password: ")

                        salt = sec.generate_salt()
                        pwd_hash = sec.hash_password(password, salt)

                        command = { "type": "register", "email": email, "username": username, "salt_hex": salt.hex(), "pwd_hash": pwd_hash }
                        response = send_secure_command(s, temp_aes_key, command)
                        print(f"Server: {response['message']}")

                    elif action == 'login':
                        email = input("Email: ")
                        password = getpass.getpass("Password: ")

                        salt_request = {"type": "login_request", "email": email}
                        response = send_secure_command(s, temp_aes_key, salt_request)

                        if response['status'] != 'ok' or response['salt_hex'] is None:
                            print("Server: Invalid email or password.")
                            continue

                        salt = bytes.fromhex(response['salt_hex'])
                        pwd_hash = sec.hash_password(password, salt)

                        login_command = { "type": "login", "email": email, "pwd_hash": pwd_hash }
                        response = send_secure_command(s, temp_aes_key, login_command)
                        print(f"Server: {response['message']}")

                        if response['status'] == 'ok':
                            log_message(transcript_file, "Login successful!")
                            break 

                    else:
                        print("Invalid command.")

                # --- 6. Session Key Establishment (Req 2.3) ---
                log_message(transcript_file, "Starting SESSION key exchange...")
                server_session_dh_public_bytes = s.recv(4096)
                if not server_session_dh_public_bytes:
                    raise ConnectionError("Server disconnected during session key exchange.")

                session_dh_private, session_dh_public_bytes = sec.dh_generate_keys()
                s.sendall(session_dh_public_bytes)

                session_shared_secret = sec.dh_derive_shared_secret(session_dh_private, server_session_dh_public_bytes)
                session_key = sec.derive_key_from_dh_secret(session_shared_secret)
                log_message(transcript_file, "✅ Secure session key established.")

                # --- 7. Data Plane (Req 2.4) ---
                print("\n--- Secure Chat Started ---")
                print("Type your message and press Enter. Type 'logout' to exit.")

                chat_active.set() # Set flag to activate chat

                # Start receiver thread
                # (We don't really use it, but this is the correct structure)
                receiver = threading.Thread(target=receive_loop, args=(s, session_key, server_cert.public_key(), transcript_file))
                receiver.start()

                seq_no = 0

                while chat_active.is_set():
                    plaintext_msg = input() # Blocking call
                    if not chat_active.is_set():
                        break

                    if plaintext_msg.strip().lower() == 'logout':
                        # Send logout message
                        msg = {"type": "logout"}
                        msg_json = json.dumps(msg).encode('utf-8')
                         	
                        
                        encrypted_msg = sec.encrypt_aes_cbc(session_key, msg_json)
                        s.sendall(encrypted_msg)

                        log_message(transcript_file, "Sent logout message.")
                        chat_active.clear() # Signal threads to stop
                        break

                    # Build the secure message
                    seq_no += 1
                    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

                    # Encrypt the plaintext for the message body
                    ct_bytes = sec.encrypt_aes_cbc(session_key, plaintext_msg.encode('utf-8'))

                    # Create data for signature: seqno || timestamp || ciphertext
                    data_to_sign = f"{seq_no}{timestamp}".encode('utf-8') + ct_bytes
                    digest = sec.hash_sha256(data_to_sign)

                    # Sign with CLIENT's private key
                    signature = sec.sign(client_key, digest)

                    # This is the message we send to the server
                    message_to_server = {
                        "type": "msg",
                        "seqno": seq_no,
                        "ts": timestamp,
                        "ct_hex": ct_bytes.hex(), # Send as hex
                        "sig_hex": signature.hex() # Send as hex
                    }

                    # This outer encryption is for the *channel*
                    # The server's chat loop expects a single encrypted blob
                    message_json = json.dumps(message_to_server).encode('utf-8')
                  
		    
                    encrypted_message = sec.encrypt_aes_cbc(session_key, message_json)

                    s.sendall(encrypted_message)
                    
                    log_message(transcript_file, f"Sent[seq={seq_no}]: {plaintext_msg}")

                # Wait for receiver thread to finish
                receiver.join()

            except Exception as e:
                log_message(transcript_file, f"\nERROR: {e}")
                traceback.print_exc()
            finally:
                log_message(transcript_file, "Disconnected from server.")

                # --- 8. Non-Repudiation: Session Receipt (Req 2.5) ---
                if client_key and transcript_file:
                    transcript_file.flush()

                    transcript_data = Path(transcript_path).read_bytes()
                    transcript_hash = sec.hash_sha256(transcript_data)

                    # Sign the hash with the CLIENT's key
                    receipt_sig = sec.sign(client_key, transcript_hash)

                    receipt = {
                        "type": "SessionReceipt",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "client_cert": client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        "server_cert": server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                        "transcript_hash_hex": transcript_hash.hex(),
                        "signature_hex": receipt_sig.hex()
                    }

                    receipt_path = Path("client_receipt.json")
                    with receipt_path.open("w") as f:
                        json.dump(receipt, f, indent=2)

                    print(f"Session receipt saved to {receipt_path}")

                s.close()

if __name__ == "__main__":
    main()
