import paho.mqtt.client as mqtt
import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import threading
import time
import sys
import platform
import secrets
import logging

if platform.system() == "Windows":
    import msvcrt
else:
    import select

# MQTT Broker settings
BROKER = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
PORT = 8883
USERNAME = "ESP32"
PASSWORD = "12345"
CA_CERT = "emqx_ca.crt"
PROVISION_REQUEST_TOPIC = "dev_pass_req"
PROVISION_RESPONSE_TOPIC = "dev_pass_res"
OTA_TOPIC = "OTA_Update"
STATUS_TOPIC = "esp32_status"
COMMAND_TOPIC = "server_cmd"
CHUNK_SIZE = 1024

# Load server key pair
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
chunk_ack_event = threading.Event()
last_chunk_sent = -1
chunk_buffer = {}
ota_in_progress = False
acknowledged_chunks = set()
device_status = {}  # Track status by IMEI
provisioned_devices = {}  # Maps UUID to (username, password)

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
    r, s = utils.decode_dss_signature(signature)
    raw_signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    return base64.b64encode(raw_signature).decode('utf-8')

def handle_provisioning(uuid, nonce, pubkey_b64):
    device_id = uuid  # IMEI
    print(f"Provisioning for IMEI: {device_id}")
    try:
        client_pubkey_bytes = base64.b64decode(pubkey_b64)
        if len(client_pubkey_bytes) != 65 or client_pubkey_bytes[0] != 0x04:
            print(f"Invalid public key format: {len(client_pubkey_bytes)} bytes")
            return
        der_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        der_pubkey = der_prefix + client_pubkey_bytes
        client_pubkey = serialization.load_der_public_key(der_pubkey, default_backend())

        shared_secret = PRIVATE_KEY.exchange(ec.ECDH(), client_pubkey)
        derived_key = sha256(shared_secret).digest()

        if device_id in provisioned_devices:
            username, password = provisioned_devices[device_id]
            print(f"Reusing cached credentials for {device_id}")
        else:
            sys.stdout.write(f"Provide password for {device_id} (min 12 chars): ")
            sys.stdout.flush()
            password = input().strip()
            if not password or len(password) < 12:
                print("Password too short or invalid")
                return
            username = f"ESP32_{device_id}"
            provisioned_devices[device_id] = (username, password)

        creds = f"DEVICE_ID:{device_id}:USERNAME:{username}:PASSWORD:{password}"
        iv = base64.b64decode(nonce)
        encrypted_response = encrypt_message(creds, derived_key, iv)
        response = f"CREDENTIALS:{encrypted_response}"
        client.publish(PROVISION_RESPONSE_TOPIC, response, qos=1)
        print(f"Sent encrypted credentials for {device_id}")
    except Exception as e:
        print(f"Provisioning error for {device_id}: {e}")

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC, qos=1)
        client.subscribe(STATUS_TOPIC, qos=1)
        client.subscribe(COMMAND_TOPIC, qos=1)
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC}, {STATUS_TOPIC}, and {COMMAND_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")

def send_ota_firmware(file_path, device_id=None):
    global last_chunk_sent, chunk_buffer, ota_in_progress, acknowledged_chunks
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    FINAL_CONFIRMATION_TIMEOUT = 20

    try:
        if not os.path.exists(file_path):
            print(f"File '{file_path}' not found")
            return

        file_size = os.path.getsize(file_path)
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        print(f"Starting OTA: File size: {file_size} bytes, Total chunks: {total_chunks}")

        with open(file_path, "rb") as f:
            magic_byte = f.read(1)
            if magic_byte != b'\xe9':
                print("Invalid firmware file (magic byte != 0xE9)")
                return

            firmware_hash = compute_firmware_hash(file_path)
            signature = sign_firmware(file_path)
            begin_command = f"OTA:BEGIN:{file_size}:{firmware_hash}:{signature}"
            if device_id:
                begin_command += f":DEVICE:{device_id}"

            for attempt in range(MAX_RETRIES):
                client.publish(OTA_TOPIC, begin_command, qos=1)
                print(f"Sent OTA:BEGIN (attempt {attempt + 1}/{MAX_RETRIES})")
                chunk_ack_event.clear()
                ota_in_progress = True
                if chunk_ack_event.wait(timeout=10):
                    print("OTA:STARTED received")
                    break
                elif attempt == MAX_RETRIES - 1:
                    print("Max retries reached for OTA:BEGIN")
                    ota_in_progress = False
                    return
                time.sleep(RETRY_DELAY)

            f.seek(0)
            chunk_num = 0
            total_bytes_sent = 0
            chunk_buffer.clear()
            acknowledged_chunks.clear()

            while total_bytes_sent < file_size and ota_in_progress:
                remaining_bytes = file_size - total_bytes_sent
                chunk_size = min(CHUNK_SIZE, remaining_bytes)
                chunk = f.read(chunk_size)
                if not chunk:
                    print(f"Unexpected empty read at chunk {chunk_num}")
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
                        progress_percentage = (total_bytes_sent / file_size) * 100
                        print(f"Chunk {chunk_num} acknowledged - OTA Progress: {progress_percentage:.2f}%")
                        break
                    elif attempt == MAX_RETRIES - 1:
                        print(f"Max retries reached for chunk {chunk_num}")
                        client.publish(OTA_TOPIC, "OTA:CANCELLED", qos=1)
                        ota_in_progress = False
                        return
                    time.sleep(RETRY_DELAY)

                chunk_num += 1

            if total_bytes_sent != file_size:
                print(f"Sent {total_bytes_sent} bytes, expected {file_size}")
                ota_in_progress = False
                return

            print(f"All {chunk_num} chunks sent, awaiting final confirmation")
            while ota_in_progress and len(acknowledged_chunks) < total_chunks:
                chunk_ack_event.clear()
                progress_percentage = (total_bytes_sent / file_size) * 100
                print(f"Acknowledged chunks: {len(acknowledged_chunks)}/{total_chunks} - OTA Progress: {progress_percentage:.2f}%")
                if not chunk_ack_event.wait(timeout=FINAL_CONFIRMATION_TIMEOUT):
                    missing_chunks = [i for i in range(total_chunks) if i not in acknowledged_chunks]
                    if missing_chunks:
                        for chunk_num in missing_chunks:
                            if chunk_num in chunk_buffer:
                                client.publish(OTA_TOPIC, chunk_buffer[chunk_num], qos=1)
                                print(f"Resent chunk {chunk_num}")
                        chunk_ack_event.clear()
                        if not chunk_ack_event.wait(timeout=20):
                            print(f"Timeout waiting for missing chunk acknowledgments")
                else:
                    print("Received confirmation update")

            if ota_in_progress:
                client.publish(OTA_TOPIC, "OTA:END", qos=1)
                print(f"OTA completed successfully")
    except Exception as e:
        print(f"Unexpected error during OTA: {e}")
        ota_in_progress = False
    finally:
        if not ota_in_progress:
            print("OTA process terminated")

def on_message(client, userdata, msg):
    global last_chunk_sent, ota_in_progress, chunk_ack_event, acknowledged_chunks
    payload = msg.payload.decode('utf-8')
    topic = msg.topic
    print(f"Received - Topic: {topic}, Payload: {payload[:50]}...")

    if topic == PROVISION_REQUEST_TOPIC:
        parts = payload.split(":NONCE:")
        uuid = parts[0][5:]
        rest = parts[1].split(":PUBKEY:")
        nonce = rest[0]
        pubkey_b64 = rest[1]
        threading.Thread(target=handle_provisioning, args=(uuid, nonce, pubkey_b64), daemon=True).start()
    elif topic == STATUS_TOPIC:
        if payload.startswith("OTA:PROGRESS:"):
            parts = payload.split(":")
            if len(parts) >= 6 and parts[4] == "DEVICE":
                chunk_num = int(parts[2])
                sizes = parts[3].split('/')
                received_size = int(sizes[0])
                total_size = int(sizes[1])
                device_id = parts[5]
                device_status[device_id] = {"received": received_size, "total": total_size}
                acknowledged_chunks.add(chunk_num)
                progress_percentage = (received_size / total_size) * 100
                print(f"Progress for {device_id}: {received_size}/{total_size} bytes, chunk: {chunk_num} - {progress_percentage:.2f}%")
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
            print(f"OTA error from ESP32: {payload}")
            ota_in_progress = False
            chunk_ack_event.set()
        elif payload == "OTA:SUCCESS:PENDING_VALIDATION":
            print("OTA completed on ESP32, pending validation")
            ota_in_progress = False
            chunk_ack_event.set()
        elif payload == "OTA:CANCELLED":
            print("OTA cancelled by ESP32")
            ota_in_progress = False
            chunk_ack_event.set()
        elif payload == "OTA:REVERTED":
            print("ESP32 reverted to factory firmware")
        elif payload.startswith("MODBUS:"):
            parts = payload.split(":")
            command = parts[1]
            status = parts[2]
            if status == "SUCCESS":
                if command == "READ":
                    reg = parts[4]
                    count = int(parts[6])
                    print(f"Modbus READ successful for register {reg}, count {count}:")
                    for i in range(count):
                        value_idx = 7 + i * 2
                        print(f"  Register {int(reg, 16) + i}: 0x{parts[value_idx + 1]}")
                elif command == "WRITE_REG":
                    reg = parts[4]
                    value = parts[6]
                    print(f"Modbus WRITE_REG successful for register {reg}: 0x{value}")
                elif command == "WRITE_COIL":
                    reg = parts[4]
                    state = parts[6]
                    print(f"Modbus WRITE_COIL successful for register {reg}: state {state}")
                elif command == "WRITE_MULTI":
                    reg = parts[4]
                    count = int(parts[6])
                    print(f"Modbus WRITE_MULTI successful for register {reg}, count {count}:")
                    for i in range(count):
                        value_idx = 7 + i * 2
                        print(f"  Register {int(reg, 16) + i}: 0x{parts[value_idx + 1]}")
            else:
                error = parts[3]
                print(f"Modbus {command} failed: error 0x{error}")
        elif payload.startswith("RESET:"):
            parts = payload.split(":")
            device_id = parts[3] if len(parts) > 3 else None
            if "CONFIRMED" in payload:
                print(f"Reset confirmed for {device_id}: {parts[1]}")
    elif topic == COMMAND_TOPIC:
        if payload.startswith("RESET:"):
            parts = payload.split(":")
            device_id = parts[3] if len(parts) > 3 else None
            if "CONFIRMED" in payload:
                print(f"Reset confirmed for {device_id}: {parts[1]}")

def input_handler():
    print("Server running... Enter 'cmd' for commands.")
    input_buffer = ""
    while True:
        if platform.system() == "Windows":
            if msvcrt.kbhit():
                char = msvcrt.getch().decode('utf-8', errors='ignore')
                if char in ['\r', '\n']:
                    action = input_buffer.strip().lower()
                    if action == "cmd":
                        command = input("Enter command ('ota', 'reset soft', 'reset factory', 'reverse', 'read', 'write_reg', 'write_coil', 'write_multi'): ").strip().lower()
                        device_id = input("Enter IMEI (or press Enter for all devices, but device-specific is recommended): ").strip()
                        if not device_id:
                            print("Warning: Device ID is required for safety. Please specify an IMEI.")
                            device_id = input("Enter IMEI: ").strip()
                            if not device_id:
                                print("No IMEI provided, aborting command.")
                                input_buffer = ""
                                continue
                        if command == "ota":
                            file_path = input("Enter firmware file path: ").strip()
                            if os.path.exists(file_path):
                                send_ota_firmware(file_path, device_id)
                            else:
                                print(f"File not found: {file_path}")
                        elif command == "reset soft":
                            msg = f"RESET:SOFT:DEVICE:{device_id}"
                            client.publish(COMMAND_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "reset factory":
                            msg = f"RESET:FACTORY:DEVICE:{device_id}"
                            client.publish(COMMAND_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "reverse":
                            msg = f"reverse old firmware:DEVICE:{device_id}"
                            client.publish(OTA_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "read":
                            reg = input("Enter register (e.g., 0x1F4 or 500): ").strip()
                            count = input("Enter count (1-10): ").strip()
                            try:
                                count_val = int(count)
                                if count_val < 1 or count_val > 10:
                                    print("Count must be between 1 and 10")
                                    input_buffer = ""
                                    continue
                                # Normalize register to hex
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                msg = f"MODBUS:READ:DEVICE:{device_id}:{reg_val}:{count_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or count")
                        elif command == "write_reg":
                            reg = input("Enter register (e.g., 0x64 or 100): ").strip()
                            value = input("Enter value (e.g., 0x1F4 or 500): ").strip()
                            try:
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                if value.startswith("0x") or value.startswith("0X"):
                                    value_val = int(value[2:], 16)
                                else:
                                    value_val = int(value)
                                msg = f"MODBUS:WRITE_REG:DEVICE:{device_id}:{reg_val}:{value_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or value")
                        elif command == "write_coil":
                            reg = input("Enter register (e.g., 0x32 or 50): ").strip()
                            state = input("Enter state (0 or 1): ").strip()
                            try:
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                state_val = int(state)
                                if state_val not in [0, 1]:
                                    print("State must be 0 or 1")
                                    input_buffer = ""
                                    continue
                                msg = f"MODBUS:WRITE_COIL:DEVICE:{device_id}:{reg_val}:{state_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or state")
                        elif command == "write_multi":
                            reg = input("Enter starting register (e.g., 0x64 or 100): ").strip()
                            count = input("Enter count (1-10): ").strip()
                            try:
                                count_val = int(count)
                                if count_val < 1 or count_val > 10:
                                    print("Count must be between 1 and 10")
                                    input_buffer = ""
                                    continue
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                values = []
                                for i in range(count_val):
                                    value = input(f"Enter value {i+1} (e.g., 0x1F4 or 500): ").strip()
                                    if value.startswith("0x") or value.startswith("0X"):
                                        value_val = int(value[2:], 16)
                                    else:
                                        value_val = int(value)
                                    values.append(value_val)
                                values_str = ":".join(str(v) for v in values)
                                msg = f"MODBUS:WRITE_MULTI:DEVICE:{device_id}:{reg_val}:{count_val}:{values_str}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register, count, or values")
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
                        command = input("Enter command ('ota', 'reset soft', 'reset factory', 'reverse', 'read', 'write_reg', 'write_coil', 'write_multi'): ").strip().lower()
                        device_id = input("Enter IMEI (or press Enter for all devices): ").strip()
                        if not device_id:
                            print("Warning: Device ID is required for safety. Please specify an IMEI.")
                            device_id = input("Enter IMEI: ").strip()
                            if not device_id:
                                print("No IMEI provided, aborting command.")
                                input_buffer = ""
                                continue
                        if command == "ota":
                            file_path = input("Enter firmware file path: ").strip()
                            if os.path.exists(file_path):
                                send_ota_firmware(file_path, device_id)
                            else:
                                print(f"File not found: {file_path}")
                        elif command == "reset soft":
                            msg = f"RESET:SOFT:DEVICE:{device_id}"
                            client.publish(COMMAND_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "reset factory":
                            msg = f"RESET:FACTORY:DEVICE:{device_id}"
                            client.publish(COMMAND_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "reverse":
                            msg = f"reverse old firmware:DEVICE:{device_id}"
                            client.publish(OTA_TOPIC, msg, qos=1)
                            print(f"Sent: {msg}")
                        elif command == "read":
                            reg = input("Enter register (e.g., 0x1F4 or 500): ").strip()
                            count = input("Enter count (1-10): ").strip()
                            try:
                                count_val = int(count)
                                if count_val < 1 or count_val > 10:
                                    print("Count must be between 1 and 10")
                                    input_buffer = ""
                                    continue
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                msg = f"MODBUS:READ:DEVICE:{device_id}:{reg_val}:{count_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or count")
                        elif command == "write_reg":
                            reg = input("Enter register (e.g., 0x64 or 100): ").strip()
                            value = input("Enter value (e.g., 0x1F4 or 500): ").strip()
                            try:
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                if value.startswith("0x") or value.startswith("0X"):
                                    value_val = int(value[2:], 16)
                                else:
                                    value_val = int(value)
                                msg = f"MODBUS:WRITE_REG:DEVICE:{device_id}:{reg_val}:{value_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or value")
                        elif command == "write_coil":
                            reg = input("Enter register (e.g., 0x32 or 50): ").strip()
                            state = input("Enter state (0 or 1): ").strip()
                            try:
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                state_val = int(state)
                                if state_val not in [0, 1]:
                                    print("State must be 0 or 1")
                                    input_buffer = ""
                                    continue
                                msg = f"MODBUS:WRITE_COIL:DEVICE:{device_id}:{reg_val}:{state_val}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register or state")
                        elif command == "write_multi":
                            reg = input("Enter starting register (e.g., 0x64 or 100): ").strip()
                            count = input("Enter count (1-10): ").strip()
                            try:
                                count_val = int(count)
                                if count_val < 1 or count_val > 10:
                                    print("Count must be between 1 and 10")
                                    input_buffer = ""
                                    continue
                                if reg.startswith("0x") or reg.startswith("0X"):
                                    reg_val = int(reg[2:], 16)
                                else:
                                    reg_val = int(reg)
                                values = []
                                for i in range(count_val):
                                    value = input(f"Enter value {i+1} (e.g., 0x1F4 or 500): ").strip()
                                    if value.startswith("0x") or value.startswith("0X"):
                                        value_val = int(value[2:], 16)
                                    else:
                                        value_val = int(value)
                                    values.append(value_val)
                                values_str = ":".join(str(v) for v in values)
                                msg = f"MODBUS:WRITE_MULTI:DEVICE:{device_id}:{reg_val}:{count_val}:{values_str}"
                                client.publish(COMMAND_TOPIC, msg, qos=1)
                                print(f"Sent: {msg}")
                            except ValueError:
                                print("Invalid register, count, or values")
                        else:
                            print("Invalid command")
                    input_buffer = ""
                else:
                    input_buffer += char
        time.sleep(0.01)

def setup_mqtt():
    global client
    client = mqtt.Client(
        client_id="Python_Server_" + str(int(time.time())),
        protocol=mqtt.MQTTv311,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(ca_certs=CA_CERT)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT)
    threading.Thread(target=client.loop_forever, daemon=True).start()
    threading.Thread(target=input_handler, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.loop_stop()
        client.disconnect()
        sys.exit(0)

if __name__ == "__main__":
    print(f"Server Public Key:\n{PUBLIC_KEY_PEM}")
    setup_mqtt()