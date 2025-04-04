import paho.mqtt.client as mqtt
import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import threading
import time
import queue
import sys
import platform
import secrets

if platform.system() == "Windows":
    import msvcrt
else:
    import select

# MQTT Broker settings
BROKER = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
PORT = 8883
USERNAME = "ESP32"
PASSWORD = "12345"
CA_CERT = "C:/Users/Milad/Documents/OTA_Python_Server/emqx_ca.crt"  # Update path
PROVISION_REQUEST_TOPIC = "dev_pass_req"
PROVISION_RESPONSE_TOPIC = "dev_pass_res"
OTA_TOPIC = "OTA_Update"
STATUS_TOPIC = "esp32_status"
CHUNK_SIZE = 1024

# Load or generate static server key pair
KEY_FILE = "server_private_key.pem"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
else:
    PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEY_FILE, "wb") as f:
        f.write(pem)

PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_PEM = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Global variables
client = None
command_queue = queue.Queue()
chunk_ack_event = threading.Event()
last_chunk_sent = -1
chunk_buffer = {}
ota_in_progress = False



def load_devices():
    try:
        with open("devices.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_devices(devices):
    with open("devices.json", "w") as f:
        json.dump(devices, f, indent=4)


def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message.encode('utf-8'))
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def compute_firmware_hash(file_path):
    sha = sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha.update(chunk)
    return sha.hexdigest()

def sign_firmware(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash_value = digest.finalize()
    signature = PRIVATE_KEY.sign(hash_value, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC, qos=1)
        client.subscribe(STATUS_TOPIC, qos=1)
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC} and {STATUS_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")

def on_message(client, userdata, msg):
    global last_chunk_sent, ota_in_progress
    payload = msg.payload.decode('utf-8')
    topic = msg.topic
    print(f"Received - Topic: {topic}, Payload: {payload[:50]}...")

    if topic == PROVISION_REQUEST_TOPIC:
        if payload.startswith("UUID:") and ":NONCE:" in payload and ":PUBKEY:" in payload:
            parts = payload.split(":NONCE:")
            uuid = parts[0][5:]
            rest = parts[1].split(":PUBKEY:")
            nonce = rest[0]
            pubkey_b64 = rest[1]
            command_queue.put(("provision", (uuid, nonce, pubkey_b64)))
    elif topic == STATUS_TOPIC:
        if payload.startswith("OTA:PROGRESS:"):
            parts = payload.split(":")
            if len(parts) >= 6 and parts[4] == "DEVICE":
                chunk_num = int(parts[2])
                sizes = parts[3].split('/')
                received_size = int(sizes[0])
                total_size = int(sizes[1])
                device_id = parts[5]
                print(f"Progress for {device_id}: {received_size}/{total_size} bytes, chunk: {chunk_num}")
                if ota_in_progress and chunk_num == last_chunk_sent:
                    chunk_ack_event.set()
        elif payload == "OTA:STARTED":
            print("ESP32 confirmed OTA start")
            if ota_in_progress:
                chunk_ack_event.set()
        elif payload.startswith("OTA:REQUEST:"):
            missing_chunks = payload.split(":")[2].split(",")
            for chunk_num in missing_chunks:
                chunk_num = int(chunk_num)
                if chunk_num in chunk_buffer:
                    client.publish(OTA_TOPIC, chunk_buffer[chunk_num], qos=1)
                    print(f"Resent chunk {chunk_num}")
                    last_chunk_sent = chunk_num
                    chunk_ack_event.clear()
                    if not chunk_ack_event.wait(timeout=10):
                        print(f"Timeout waiting for chunk {chunk_num} ack")
        elif payload.startswith("OTA:ERROR:"):
            print(f"OTA error: {payload}")
            ota_in_progress = False
            chunk_ack_event.set()
        elif payload == "OTA:SUCCESS:PENDING_VALIDATION":
            print("OTA completed, pending validation")
            ota_in_progress = False
        elif payload == "OTA:CANCELLED":
            print("OTA cancelled")
            ota_in_progress = False
            chunk_ack_event.set()

def send_ota_firmware(file_path):
    global last_chunk_sent, chunk_buffer, ota_in_progress
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return
        
        with open(file_path, "rb") as f:
            if f.read(1) != b'\xe9':
                print("Error: Invalid firmware file (magic byte != 0xE9)")
                return
            file_size = os.path.getsize(file_path)
            firmware_hash = compute_firmware_hash(file_path)
            signature = sign_firmware(file_path)
            begin_command = f"OTA:BEGIN:{file_size}:{firmware_hash}:{signature}"
            client.publish(OTA_TOPIC, begin_command, qos=1)
            print(f"Sent: {begin_command}")
            
            chunk_ack_event.clear()
            ota_in_progress = True
            if not chunk_ack_event.wait(timeout=10):
                print("Timeout waiting for OTA:STARTED")
                ota_in_progress = False
                return
            
            f.seek(0)
            chunk_num = 0
            total_bytes_sent = 0
            chunk_buffer.clear()
            
            while total_bytes_sent < file_size and ota_in_progress:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) < CHUNK_SIZE and total_bytes_sent + len(chunk) < file_size:
                    chunk += b'\x00' * (CHUNK_SIZE - len(chunk))
                chunk_data = chunk_num.to_bytes(4, byteorder='big') + chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                chunk_buffer[chunk_num] = encoded_chunk
                
                client.publish(OTA_TOPIC, encoded_chunk, qos=1)
                print(f"Sent chunk {chunk_num} ({len(chunk)} bytes)")
                
                total_bytes_sent += len(chunk)
                last_chunk_sent = chunk_num
                
                chunk_ack_event.clear()
                if not chunk_ack_event.wait(timeout=20):
                    print(f"Timeout waiting for chunk {chunk_num} ack")
                    ota_in_progress = False
                    return
                
                chunk_num += 1
            
            if total_bytes_sent != file_size:
                print(f"Error: Sent {total_bytes_sent} bytes, expected {file_size}")
                ota_in_progress = False
                return
            
            if ota_in_progress:
                client.publish(OTA_TOPIC, "OTA:END", qos=1)
                print("Sent: OTA:END")
                ota_in_progress = False
    except Exception as e:
        print(f"Error during OTA: {e}")
        ota_in_progress = False

def input_handler():
    print("Server running... Enter 'cmd' for commands.")
    input_buffer = ""
    devices = load_devices()

    while True:
        if not command_queue.empty():
            cmd_type, data = command_queue.get()
            if cmd_type == "provision":
                uuid, nonce, pubkey_b64 = data
                print(f"Provisioning for UUID: {uuid}")
                client_pubkey_bytes = base64.b64decode(pubkey_b64)
                # Check if it's a valid 65-byte uncompressed point
                if len(client_pubkey_bytes) != 65 or client_pubkey_bytes[0] != 0x04:
                    print(f"Invalid public key format: {len(client_pubkey_bytes)} bytes, first byte: {client_pubkey_bytes[0]}")
                    command_queue.task_done()
                    continue
                # Manually construct DER-encoded SubjectPublicKeyInfo for SECP256R1
                # SECP256R1 OID: 1.2.840.10045.3.1.7
                der_prefix = bytes.fromhex(
                    "3059301306072a8648ce3d020106082a8648ce3d030107034200"  # Fixed header for SECP256R1
                )
                der_pubkey = der_prefix + client_pubkey_bytes  # Append the 65-byte point
                
                try:
                    client_pubkey = serialization.load_der_public_key(der_pubkey, default_backend())
                except ValueError as e:
                    print(f"Failed to load public key: {e}")
                    command_queue.task_done()
                    continue
                shared_secret = PRIVATE_KEY.exchange(ec.ECDH(), client_pubkey)
                derived_key = sha256(shared_secret).digest()
                
                # Generate a unique custom device ID
                custom_id = f"ESP32_{secrets.token_hex(4)}"  # e.g., "ESP32_abcd1234"
                devices[custom_id] = {"uuid": uuid, "status": "provisioned"}  # Log device
                save_devices(devices)

                password = input(f"Provide password for {custom_id} (min 12 chars): ").strip()
                if password and len(password) >= 12:
                    creds = f"DEVICE_ID:{custom_id}:USERNAME:{USERNAME}:PASSWORD:{password}"
                    iv = base64.b64decode(nonce)
                    encrypted_response = encrypt_message(creds, derived_key, iv)
                    response = f"CREDENTIALS:{encrypted_response}"
                    client.publish(PROVISION_RESPONSE_TOPIC, response, qos=1)
                    print(f"Sent encrypted credentials for {custom_id}")
                    print(f"Payload of Credentials: {response}")
                else:
                    print("Password too short")
                command_queue.task_done()
        
        if platform.system() == "Windows":
            if msvcrt.kbhit():
                char = msvcrt.getch().decode('utf-8')
                if char in ['\r', '\n']:
                    action = input_buffer.strip().lower()
                    if action == "cmd":
                        command = input("Enter command ('OTA' or 'reverse old firmware'): ").strip().lower()
                        if command == "ota":
                            file_path = input("Enter firmware file path: ").strip()
                            if os.path.exists(file_path):
                                send_ota_firmware(file_path)
                        elif command == "reverse old firmware":
                            client.publish(OTA_TOPIC, "reverse old firmware", qos=1)
                            print("Sent: reverse old firmware")
                        else:
                            print("Invalid command")
                    input_buffer = ""
                else:
                    input_buffer += char
        else:
            if select.select([sys.stdin], [], [], 0.1)[0]:
                char = sys.stdin.read(1)
                if char in ['\n', '\r']:
                    action = input_buffer.strip().lower()
                    if action == "cmd":
                        command = input("Enter command ('OTA' or 'reverse old firmware'): ").strip().lower()
                        if command == "ota":
                            file_path = input("Enter firmware file path: ").strip()
                            if os.path.exists(file_path):
                                send_ota_firmware(file_path)
                        elif command == "reverse old firmware":
                            client.publish(OTA_TOPIC, "reverse old firmware", qos=1)
                            print("Sent: reverse old firmware")
                        else:
                            print("Invalid command")
                    input_buffer = ""
                else:
                    input_buffer += char
        time.sleep(0.01)

def setup_mqtt():
    global client
    client = mqtt.Client(client_id="Python_Server_" + str(int(time.time())), protocol=mqtt.MQTTv311)
    client.username_pw_set(USERNAME, PASSWORD)
    #client.tls_set(ca_certs=CA_CERT)
    client.tls_set()
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        client.connect(BROKER, PORT)
        print("Connecting to MQTT broker...")
    except Exception as e:
        print(f"Failed to connect: {e}")
        exit(1)
    
    mqtt_thread = threading.Thread(target=client.loop_forever, daemon=True)
    mqtt_thread.start()
    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
        client.disconnect()

if __name__ == "__main__":
    print(f"Server Public Key:\n{PUBLIC_KEY_PEM}")
    setup_mqtt()