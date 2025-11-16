# mitm_proxy.py
# A simple MitM proxy for testing data integrity.

import socket
import threading
import json
import base64

# --- CONFIGURATION ---
# Port for the client to connect to
PROXY_HOST = 'localhost'
PROXY_PORT = 65432

# Port where the REAL server is running
SERVER_HOST = 'localhost'
SERVER_PORT = 65433  # Note: Run your real server on this port
# --- END CONFIGURATION ---

def tamper(data):
    """
    Finds and tampers with the ciphertext (ct) in a "msg" type JSON.
    """
    try:
        msg_str = data.decode('utf-8')
        msg_json = json.loads(msg_str)
        
        # We only tamper with chat messages
        if msg_json.get("type") == "msg":
            print(f"[MITM] Intercepted 'msg': {msg_str}")
            
            # Decode the base64 ciphertext
            ct_b64 = msg_json["ct"]
            ct_bytes = base64.b64decode(ct_b64)
            
            # Tamper: Flip the first byte of the ciphertext
            tampered_bytes = bytes([ct_bytes[0] ^ 0x01]) + ct_bytes[1:]
            
            # Re-encode to base64
            tampered_b64 = base64.b64encode(tampered_bytes).decode('utf-8')
            msg_json["ct"] = tampered_b64
            
            # Re-serialize the JSON
            tampered_data_str = json.dumps(msg_json)
            print(f"[MITM] Tampered 'msg': {tampered_data_str}")
            return tampered_data_str.encode('utf-8')
            
    except Exception as e:
        # Not a JSON we care about, or not a 'msg' type, pass it through
        print(f"[MITM] Passing through data (Error: {e}): {data[:50]}...")
        pass
        
    return data # Pass-through unmodified

def handle_client(client_socket):
    try:
        # Connect to the real server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"[MITM] Client connected, proxying to {SERVER_HOST}:{SERVER_PORT}")

        # Start threads to forward data in both directions
        threading.Thread(target=forward, args=(client_socket, server_socket, 'client_to_server'), daemon=True).start()
        threading.Thread(target=forward, args=(server_socket, client_socket, 'server_to_client'), daemon=True).start()
        
    except Exception as e:
        print(f"[MITM] Error connecting to server: {e}")
        client_socket.close()

def forward(src, dst, direction):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            
            if direction == 'client_to_server':
                data = tamper(data) # Try to tamper with data
            
            dst.sendall(data)
    except Exception as e:
        print(f"[MITM] Forwarding error ({direction}): {e}")
    finally:
        src.close()
        dst.close()
        print(f"[MITM] Connection closed ({direction}).")

def main():
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_server.bind((PROXY_HOST, PROXY_PORT))
    proxy_server.listen(5)
    print(f"[MITM] Proxy server listening on {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, addr = proxy_server.accept()
        print(f"[MITM] Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    main()