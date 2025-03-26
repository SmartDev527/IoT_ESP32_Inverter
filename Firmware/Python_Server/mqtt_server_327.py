import paho.mqtt.client as mqtt
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import threading
import time
import queue
import sys
import platform

if platform.system() == "Windows":
    import msvcrt
else:
    import select

# MQTT Broker settings
BROKER = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
PORT = 8883
USERNAME = "ESP32"
PASSWORD = "12345"
CA_CERT = "C:/Users/Milad/Documents/OTA_Python_Server/emqx_ca.crt"
PROVISION_REQUEST_TOPIC = "dev_pass_req"
PROVISION_RESPONSE_TOPIC = "dev_pass_res"
OTA_TOPIC = "OTA_Update"
STATUS_TOPIC = "esp32_status"
AES_KEY = bytes.fromhex("3031323334353637383941424344454630313233343536373839414243444546")
AES_IV = bytes.fromhex("30313233343536373839414243444546")
CHUNK_SIZE = 1024
BATCH_SIZE = 10
chunk_buffer = {}  # Buffer for all chunks
MAX_RETRIES = 3

# Global variables
client = None
provisioning_imei = None
command_queue = queue.Queue()
chunk_ack_event = threading.Event()
last_chunk_sent = -1
chunk_buffer = {}

def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def encrypt_message(message):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message.encode('utf-8'))
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def compute_firmware_hash(file_path):
    sha = sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC)
        client.subscribe(STATUS_TOPIC)
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC} and {STATUS_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")

def on_message(client, userdata, msg):
    global last_chunk_sent
    payload = msg.payload.decode('utf-8')
    topic = msg.topic
    print(f"Received on {topic}: {payload}")

    if topic == STATUS_TOPIC:
        if payload.startswith("OTA:PROGRESS:"):
            parts = payload.split(":")
            if len(parts) >= 4:
                chunk_num = int(parts[2])
                sizes = parts[3].split('/')
                received_size = int(sizes[0])
                total_size = int(sizes[1])
                print(f"Progress: {received_size}/{total_size} bytes, chunk: {chunk_num}")
                if chunk_num == last_chunk_sent:
                    chunk_ack_event.set()
        elif payload == "OTA:STARTED":
            print("ESP32 confirmed OTA start")
            chunk_ack_event.set()
        elif payload.startswith("OTA:REQUEST:"):
            missing_chunks = payload.split(":")[2].split(",")
            for chunk_num in missing_chunks:
                chunk_num = int(chunk_num)
                if chunk_num in chunk_buffer:
                    client.publish(OTA_TOPIC, chunk_buffer[chunk_num], qos=1)
                    print(f"Resent chunk {chunk_num}")
        elif payload.startswith("OTA:ERROR:"):
            print(f"OTA error from ESP32: {payload}")
            chunk_ack_event.set()
        elif payload == "OTA:SUCCESS":
            print("OTA update completed successfully")

def send_ota_firmware(file_path):
    global last_chunk_sent, chunk_buffer
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return
        
        with open(file_path, "rb") as f:
            first_byte = f.read(1)
            if first_byte != b'\xe9':
                print(f"Error: Invalid firmware file (magic byte != 0xE9)")
                return
            file_size = os.path.getsize(file_path)
            firmware_hash = compute_firmware_hash(file_path)
            print(f"Firmware size: {file_size} bytes, SHA256: {firmware_hash}")
            begin_command = f"OTA:BEGIN:{file_size}:{firmware_hash}"
            client.publish(OTA_TOPIC, begin_command, qos=1)
            print(f"Sent: {begin_command}")
            
            chunk_ack_event.clear()
            if not chunk_ack_event.wait(timeout=10):
                print("Timeout waiting for OTA:STARTED")
                return
            
            time.sleep(1)
            f.seek(0)
            chunk_num = 0
            total_bytes_sent = 0
            chunk_buffer.clear()
            
            while total_bytes_sent < file_size:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) < CHUNK_SIZE and total_bytes_sent + len(chunk) < file_size:
                    print(f"Warning: Chunk {chunk_num} is {len(chunk)} bytes, padding to {CHUNK_SIZE}")
                    chunk = chunk + b'\x00' * (CHUNK_SIZE - len(chunk))
                chunk_data = chunk_num.to_bytes(4, byteorder='big') + chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                chunk_buffer[chunk_num] = encoded_chunk
                
                client.publish(OTA_TOPIC, encoded_chunk, qos=1)
                print(f"Sent chunk {chunk_num} ({len(chunk)} bytes)")
                last_chunk_sent = chunk_num
                
                for attempt in range(MAX_RETRIES):
                    chunk_ack_event.clear()
                    if chunk_ack_event.wait(timeout=15):
                        break
                    print(f"No acknowledgment for chunk {chunk_num}, retrying attempt {attempt + 1}")
                    client.publish(OTA_TOPIC, encoded_chunk, qos=1)
                    print(f"Resent chunk {chunk_num}")
                else:
                    print(f"Failed to send chunk {chunk_num} after {MAX_RETRIES} attempts")
                    return
                
                total_bytes_sent += len(chunk)
                chunk_num += 1
                time.sleep(0.1)
            
            if total_bytes_sent != file_size:
                print(f"Error: Sent {total_bytes_sent} bytes, expected {file_size}")
                return
            
            client.publish(OTA_TOPIC, "OTA:END", qos=1)
            print("Sent: OTA:END")
    except Exception as e:
        print(f"Error during OTA: {e}")


def input_handler():
    global provisioning_imei
    print("Starting server... Enter 'cmd' for commands.")
    input_buffer = ""
    while True:
        if not command_queue.empty():
            cmd_type, data = command_queue.get_nowait()
            if cmd_type == "provision":
                password = input(f"Provide password for ESP_{data}: ").strip()
                if password:
                    response = f"PASSWORD:{password}"
                    encrypted_response = encrypt_message(response)
                    client.publish(PROVISION_RESPONSE_TOPIC, encrypted_response)
                    print(f"Sent encrypted password: {encrypted_response}")
                    provisioning_imei = None
                command_queue.task_done()
        
        if platform.system() == "Windows":
            if msvcrt.kbhit():
                char = msvcrt.getch().decode('utf-8')
                print(f"Key pressed: '{char}'")
                if char in ['\r', '\n']:
                    action = input_buffer.strip().lower()
                    print(f"Action: '{action}'")
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
                print(f"Key pressed: '{char}'")
                if char in ['\n', '\r']:
                    action = input_buffer.strip().lower()
                    print(f"Action: '{action}'")
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
    client = mqtt.Client(client_id="ESP32_SIM7600_Client", protocol=mqtt.MQTTv311)
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(ca_certs=CA_CERT)
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
    time.sleep(1)
    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()
    input_thread.join()

if __name__ == "__main__":
    setup_mqtt()