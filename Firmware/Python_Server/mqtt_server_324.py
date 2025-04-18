import paho.mqtt.client as mqtt
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading
import time
import queue
import sys
import msvcrt  # For Windows non-blocking input

# MQTT Broker settings
BROKER = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
PORT = 8883
USERNAME = "ESP32"
PASSWORD = "12345"
CA_CERT = "C:/Users/Milad/Documents/OTA_Python_Server/emqx_ca.crt"
PROVISION_REQUEST_TOPIC = "dev_pass_req"
PROVISION_RESPONSE_TOPIC = "dev_pass_res"
OTA_TOPIC = "OTA_Update"
STATUS_TOPIC = "esp32_status"  # Topic for ESP32 responses
AES_KEY = bytes.fromhex("3031323334353637383941424344454630313233343536373839414243444546")
AES_IV = bytes.fromhex("30313233343536373839414243444546")
CHUNK_SIZE = 508

# Global variables
client = None
provisioning_imei = None
command_queue = queue.Queue()
chunk_ack_event = threading.Event()  # Event to wait for chunk acknowledgment
last_chunk_sent = -1  # Track the last chunk sent

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

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC)
        client.subscribe(STATUS_TOPIC)  # Subscribe to ESP32 status updates
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC} and {STATUS_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")

def on_message(client, userdata, msg):
    global last_chunk_sent
    payload = msg.payload.decode('utf-8')
    topic = msg.topic
    if topic == PROVISION_REQUEST_TOPIC and payload.startswith("IMEI:"):
        global provisioning_imei
        if provisioning_imei != payload[5:]:
            provisioning_imei = payload[5:]
            print(f"Provisioning request from IMEI: {provisioning_imei}")
            command_queue.put(("provision", provisioning_imei))
        else:
            print(f"Duplicate provisioning request from IMEI: {provisioning_imei} ignored")
    elif topic == STATUS_TOPIC:
        if payload.startswith("OTA:PROGRESS:"):
            parts = payload.split(":")
            if len(parts) >= 5 and parts[3] == "CHUNK":
                chunk_num = int(parts[4])
                print(f"Received acknowledgment for chunk {chunk_num}")
                if chunk_num == last_chunk_sent:
                    chunk_ack_event.set()
        elif payload == "OTA:STARTED":
            print("ESP32 confirmed OTA start")
            chunk_ack_event.set()
        elif payload.startswith("OTA:REQUEST:"):
            chunk_num = int(payload.split(":")[2])
            print(f"ESP32 requested chunk {chunk_num} - ignoring for now")
            # Optionally: Add logic to resend chunk here if needed
        elif payload.startswith("OTA:ERROR:"):
            print(f"OTA error from ESP32: {payload}")
            chunk_ack_event.set()
        else:
            print(f"Received status: {payload}")
    elif payload.strip() != "OK":
        print(f"Received message on {topic}: {payload}")

def send_ota_firmware(file_path):
    global last_chunk_sent
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return
        
        with open(file_path, "rb") as f:
            first_byte = f.read(1)
            if first_byte != b'\xe9':
                print(f"Error: '{file_path}' is not a valid ESP32 firmware file (magic byte != 0xE9)")
                return
            file_size = os.path.getsize(file_path)
            print(f"Firmware file size: {file_size} bytes")
            begin_command = f"OTA:BEGIN:{file_size}"
            client.publish(OTA_TOPIC, begin_command, qos=1)
            print(f"Sent: {begin_command}")
            
            chunk_ack_event.clear()
            if not chunk_ack_event.wait(timeout=10):
                print("Timeout waiting for OTA:STARTED response")
                return
            
            print("Waiting 1 second before sending first chunk...")
            time.sleep(1)
            
            f.seek(0)
            chunk_num = 0
            total_bytes_sent = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) < CHUNK_SIZE and total_bytes_sent + len(chunk) < file_size:
                    print(f"Warning: Chunk {chunk_num} is {len(chunk)} bytes, expected {CHUNK_SIZE}")
                chunk_data = chunk_num.to_bytes(4, byteorder='big') + chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                last_chunk_sent = chunk_num
                client.publish(OTA_TOPIC, encoded_chunk, qos=1)
                print(f"Sent chunk {chunk_num} ({len(chunk)} bytes) - First 8 bytes: {chunk_data[:8].hex()}")
                
                chunk_ack_event.clear()
                if not chunk_ack_event.wait(timeout=10):
                    print(f"Timeout waiting for acknowledgment of chunk {chunk_num}")
                    return
                
                chunk_num += 1
                total_bytes_sent += len(chunk)
                if chunk_num < file_size // CHUNK_SIZE + 1:  # Only delay if more chunks remain
                    print(f"Waiting 0.5 seconds before sending chunk {chunk_num}...")
                    time.sleep(0.5)  # Delay between chunks
            
            if total_bytes_sent != file_size:
                print(f"Error: Sent {total_bytes_sent} bytes, expected {file_size}")
                return
            
            client.publish(OTA_TOPIC, "OTA:END", qos=1)
            print("Sent: OTA:END")
    except Exception as e:
        print(f"Error during OTA: {e}")

def input_handler():
    global provisioning_imei
    print("Starting server... Waiting for provisioning requests or commands.")
    input_buffer = ""
    while True:
        if not command_queue.empty():
            try:
                cmd_type, data = command_queue.get_nowait()
                if cmd_type == "provision":
                    password = input(f"Provide the password for ESP_{data}: ").strip()
                    if password:
                        response = f"PASSWORD:{password}"
                        encrypted_response = encrypt_message(response)
                        client.publish(PROVISION_RESPONSE_TOPIC, encrypted_response)
                        print(f"Sent encrypted password to {PROVISION_RESPONSE_TOPIC}: {encrypted_response}")
                        provisioning_imei = None
                    else:
                        print("No password entered, skipping response")
                        provisioning_imei = None
                    command_queue.task_done()
            except queue.Empty:
                pass
        else:
            if msvcrt.kbhit():
                char = msvcrt.getch().decode('utf-8')
                if char == '\r':
                    action = input_buffer.strip().lower()
                    input_buffer = ""
                    if action == "cmd":
                        command = input("Enter command ('OTA' to send firmware, 'reverse old firmware' to revert): ").strip().lower()
                        if command == "ota":
                            file_path = input("Enter path to firmware file (e.g., 'C:/Users/Milad/firmware.bin'): ").strip()
                            if os.path.exists(file_path):
                                send_ota_firmware(file_path)
                            else:
                                print(f"Error: File '{file_path}' not found")
                        elif command == "reverse old firmware":
                            client.publish(OTA_TOPIC, "reverse old firmware", qos=1)
                            print(f"Sent: reverse old firmware")
                        else:
                            print("Invalid command. Use 'OTA' or 'reverse old firmware'")
                else:
                    input_buffer += char
            time.sleep(0.1)

def setup_mqtt():
    global client
    client = mqtt.Client(client_id="ESP32_SIM7600_Client", protocol=mqtt.MQTTv311)
    client.username_pw_set(USERNAME, PASSWORD)
    
    if not os.path.exists(CA_CERT):
        print(f"Error: CA certificate file '{CA_CERT}' not found. Please update CA_CERT path.")
        exit(1)
    
    try:
        client.tls_set(ca_certs=CA_CERT)
    except Exception as e:
        print(f"Failed to set TLS: {e}")
        exit(1)

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
    time.sleep(2)
    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()
    input_thread.join()

if __name__ == "__main__":
    setup_mqtt()