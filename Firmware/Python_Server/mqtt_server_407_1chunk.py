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
        PRIVATE_KEY = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())
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
acknowledged_chunks = set()  # Reverted to a single set, no device-specific tracking

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
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature)
    raw_signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    return base64.b64encode(raw_signature).decode('utf-8')

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC, qos=1)
        client.subscribe(STATUS_TOPIC, qos=1)
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC} and {STATUS_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")


def on_message(client, userdata, msg):
    global last_chunk_sent, ota_in_progress, chunk_ack_event, acknowledged_chunks
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
                acknowledged_chunks.add(chunk_num)
                print(f"Added chunk {chunk_num}, current count: {len(acknowledged_chunks)}")
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
            chunk_ack_event.set()
        elif payload == "OTA:CANCELLED":
            print("OTA cancelled")
            ota_in_progress = False
            chunk_ack_event.set()


def send_ota_firmware(file_path):
    global last_chunk_sent, chunk_buffer, ota_in_progress, acknowledged_chunks
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    FINAL_CONFIRMATION_TIMEOUT = 20

    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return

        file_size = os.path.getsize(file_path)
        print(f"File size: {file_size} bytes")
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        print(f"Total chunks to send: {total_chunks}")

        with open(file_path, "rb") as f:
            magic_byte = f.read(1)
            print(f"Magic byte: {magic_byte}")
            if magic_byte != b'\xe9':
                print("Error: Invalid firmware file (magic byte != 0xE9)")
                return

            firmware_hash = compute_firmware_hash(file_path)
            signature = sign_firmware(file_path)
            begin_command = f"OTA:BEGIN:{file_size}:{firmware_hash}:{signature}"

            for attempt in range(MAX_RETRIES):
                client.publish(OTA_TOPIC, begin_command, qos=1)
                print(f"Sent: {begin_command} (attempt {attempt + 1}/{MAX_RETRIES})")
                chunk_ack_event.clear()
                ota_in_progress = True
                if chunk_ack_event.wait(timeout=10):
                    print("OTA:STARTED received, proceeding with chunks")
                    break
                elif attempt == MAX_RETRIES - 1:
                    print("Max retries reached for OTA:BEGIN, aborting")
                    ota_in_progress = False
                    return
                time.sleep(RETRY_DELAY)

            f.seek(0)
            chunk_num = 0
            total_bytes_sent = 0
            chunk_buffer.clear()
            acknowledged_chunks.clear()

            print("Starting chunk transmission...")
            while chunk_num < total_chunks and ota_in_progress:
                remaining_bytes = file_size - total_bytes_sent
                if remaining_bytes < 0:
                    print(f"Error: total_bytes_sent ({total_bytes_sent}) exceeds file_size ({file_size})")
                    break
                
                chunk_size = min(CHUNK_SIZE, remaining_bytes)
                chunk = f.read(chunk_size)
                
                if len(chunk) == 0:  # Check if we actually read data
                    print(f"Error: No data read for chunk {chunk_num} at {total_bytes_sent} bytes")
                    break

                chunk_data = chunk_num.to_bytes(4, byteorder='big') + chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                chunk_buffer[chunk_num] = encoded_chunk

                for attempt in range(MAX_RETRIES):
                    client.publish(OTA_TOPIC, encoded_chunk, qos=1)
                    print(f"Sent chunk {chunk_num} ({len(chunk)} bytes, attempt {attempt + 1}/{MAX_RETRIES})")
                    total_bytes_sent += len(chunk)
                    last_chunk_sent = chunk_num
                    chunk_ack_event.clear()
                    if chunk_ack_event.wait(timeout=20):
                        break
                    elif attempt == MAX_RETRIES - 1:
                        print(f"Max retries reached for chunk {chunk_num}, aborting")
                        ota_in_progress = False
                        client.publish(OTA_TOPIC, "OTA:CANCELLED", qos=1)
                        return
                    time.sleep(RETRY_DELAY)

                chunk_num += 1

            if chunk_num != total_chunks:
                print(f"Error: Sent {chunk_num} chunks, expected {total_chunks}")
                ota_in_progress = False
                return

            if ota_in_progress:
                print(f"All {total_chunks} chunks sent, waiting for ESP32 confirmation...")
                while ota_in_progress and len(acknowledged_chunks) < total_chunks:
                    chunk_ack_event.clear()
                    print(f"Current acknowledged chunks: {len(acknowledged_chunks)}/{total_chunks}")
                    if not chunk_ack_event.wait(timeout=FINAL_CONFIRMATION_TIMEOUT):
                        print(f"Timeout waiting for acknowledgment, {len(acknowledged_chunks)}/{total_chunks} chunks confirmed")
                        missing_chunks = [i for i in range(total_chunks) if i not in acknowledged_chunks]
                        if missing_chunks:
                            missing_str = ",".join(map(str, missing_chunks))
                            client.publish(OTA_TOPIC, f"OTA:REQUEST:{missing_str}", qos=1)
                            print(f"Requested missing chunks: {missing_str}")
                    else:
                        print(f"Ack event set, acknowledged chunks: {len(acknowledged_chunks)}/{total_chunks}")

                if ota_in_progress and len(acknowledged_chunks) == total_chunks:
                    client.publish(OTA_TOPIC, "OTA:END", qos=1)
                    print("Sent: OTA:END")
    except Exception as e:
        print(f"Error during OTA: {e}")
        ota_in_progress = False

def input_handler():
    print("Server running... Enter 'cmd' for commands.")
    input_buffer = ""
    devices = load_devices()

    while True:
        # Process provisioning requests first
        if not command_queue.empty():
            cmd_type, data = command_queue.get()
            if cmd_type == "provision":
                imei, nonce, pubkey_b64 = data
                print(f"Provisioning for IMEI: {imei}")
                client_pubkey_bytes = base64.b64decode(pubkey_b64)
                if len(client_pubkey_bytes) != 65 or client_pubkey_bytes[0] != 0x04:
                    print(f"Invalid public key format: {len(client_pubkey_bytes)} bytes, first byte: {client_pubkey_bytes[0]}")
                    command_queue.task_done()
                    continue
                der_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
                der_pubkey = der_prefix + client_pubkey_bytes

                try:
                    client_pubkey = serialization.load_der_public_key(der_pubkey, default_backend())
                except ValueError as e:
                    print(f"Failed to load public key: {e}")
                    command_queue.task_done()
                    continue
                shared_secret = PRIVATE_KEY.exchange(ec.ECDH(), client_pubkey)
                derived_key = sha256(shared_secret).digest()

                device_id = imei
                username = f"ESP32_{imei}"
                devices[device_id] = {"imei": imei, "status": "provisioned"}
                save_devices(devices)

                # Fix password prompt by ensuring immediate display
                sys.stdout.write(f"Provide password for {device_id} (min 12 chars): ")
                sys.stdout.flush()
                password = input().strip()
                if password and len(password) >= 12:
                    creds = f"DEVICE_ID:{device_id}:USERNAME:{username}:PASSWORD:{password}"
                    iv = base64.b64decode(nonce)
                    encrypted_response = encrypt_message(creds, derived_key, iv)
                    response = f"CREDENTIALS:{encrypted_response}"
                    client.publish(PROVISION_RESPONSE_TOPIC, response, qos=1)
                    print(f"Sent encrypted credentials for {device_id}")
                    print(f"Payload of Credentials: {response}")
                else:
                    print("Password too short or invalid")
                command_queue.task_done()
                continue  # Ensure loop continues after provisioning

        # Handle user commands
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
                                send_ota_firmware(file_path)  # No device_id prompt
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
                                send_ota_firmware(file_path)  # No device_id prompt
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
    # Update to use callback_api_version parameter instead of deprecated version
    client = mqtt.Client(
        client_id="Python_Server_" + str(int(time.time())),
        protocol=mqtt.MQTTv311,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.username_pw_set(USERNAME, PASSWORD)
    # client.tls_set(ca_certs=CA_CERT)  # Uncomment and update path if needed
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