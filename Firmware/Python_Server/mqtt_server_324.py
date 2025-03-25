import paho.mqtt.client as mqtt
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading
import time
import queue

# MQTT Broker settings (unchanged)
BROKER = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
PORT = 8883
USERNAME = "ESP32"
PASSWORD = "12345"
CA_CERT = "C:/Users/Milad/Documents/OTA_Python_Server/emqx_ca.crt"
PROVISION_REQUEST_TOPIC = "dev_pass_req"
PROVISION_RESPONSE_TOPIC = "dev_pass_res"
OTA_TOPIC = "OTA_Update"
AES_KEY = bytes.fromhex("3031323334353637383941424344454630313233343536373839414243444546")
AES_IV = bytes.fromhex("30313233343536373839414243444546")
CHUNK_SIZE = 508

# Global variables
client = None
provisioning_imei = None
command_queue = queue.Queue()

# PKCS7 padding function (unchanged)
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

# Encrypt message with AES-256-CBC (unchanged)
def encrypt_message(message):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message.encode('utf-8'))
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

# Callback when connected to MQTT broker (unchanged)
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(PROVISION_REQUEST_TOPIC)
        print(f"Subscribed to {PROVISION_REQUEST_TOPIC}")
    else:
        print(f"Connection failed with code {rc}")

# Callback when a message is received (unchanged)
def on_message(client, userdata, msg):
    payload = msg.payload.decode('utf-8')
    topic = msg.topic
    if payload.strip() != "OK" and topic == PROVISION_REQUEST_TOPIC and payload.startswith("IMEI:"):
        global provisioning_imei
        if provisioning_imei != payload[5:]:
            provisioning_imei = payload[5:]
            print(f"Provisioning request from IMEI: {provisioning_imei}")
            command_queue.put(("provision", provisioning_imei))
        else:
            print(f"Duplicate provisioning request from IMEI: {provisioning_imei} ignored")
    elif payload.strip() != "OK":
        print(f"Received message on {topic}: {payload}")

# Function to send OTA firmware (unchanged)
def send_ota_firmware(file_path):
    try:
        file_size = os.path.getsize(file_path)
        print(f"Firmware file size: {file_size} bytes")
        begin_command = f"OTA:BEGIN:{file_size}"
        client.publish(OTA_TOPIC, begin_command)
        print(f"Sent: {begin_command}")
        time.sleep(1)
        with open(file_path, "rb") as f:
            chunk_num = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_data = chunk_num.to_bytes(4, byteorder='big') + chunk
                encoded_chunk = base64.b64encode(chunk_data).decode('utf-8')
                client.publish(OTA_TOPIC, encoded_chunk)
                print(f"Sent chunk {chunk_num} ({len(chunk)} bytes)")
                chunk_num += 1
                time.sleep(0.1)
        client.publish(OTA_TOPIC, "OTA:END")
        print("Sent: OTA:END")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error during OTA: {e}")

# Non-blocking input handler
def input_handler():
    global provisioning_imei
    print("Starting server... Waiting for provisioning requests or commands.")
    while True:
        # Check queue for provisioning requests
        if not command_queue.empty():
            try:
                cmd_type, data = command_queue.get_nowait()
                if cmd_type == "provision":
                    password = input(f"Provide the password for ESP32_{data}: ").strip()
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
                pass  # Queue might be emptied by another iteration
        else:
            # Prompt for command only when explicitly requested
            action = input("Type 'cmd' to enter a command, or press Enter to wait for provisioning requests: ").strip().lower()
            if action == "cmd":
                command = input("Enter command ('OTA' to send firmware, 'reverse old firmware' to revert): ").strip().lower()
                if command == "ota":
                    file_path = input("Enter path to firmware file: ").strip()
                    if os.path.exists(file_path):
                        send_ota_firmware(file_path)
                    else:
                        print(f"Error: File '{file_path}' not found")
                elif command == "reverse old firmware":
                    client.publish(OTA_TOPIC, "reverse old firmware")
                    print(f"Sent: reverse old firmware")
                else:
                    print("Invalid command. Use 'OTA' or 'reverse old firmware'")
            elif action == "":
                print("Waiting for provisioning requests...")
            else:
                print("Invalid input. Type 'cmd' or press Enter.")
        time.sleep(0.1)  # Small delay to prevent tight looping

# Setup MQTT client
def setup_mqtt():
    global client
    client = mqtt.Client(client_id="PythonServer", protocol=mqtt.MQTTv311)
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
    # Wait for MQTT connection to stabilize
    time.sleep(2)
    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()
    input_thread.join()  # Keep main thread alive

if __name__ == "__main__":
    setup_mqtt()