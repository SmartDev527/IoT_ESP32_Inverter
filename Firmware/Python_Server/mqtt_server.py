import paho.mqtt.client as mqtt
import time
import os
import base64
import struct

# MQTT settings
broker = "u008dd8e.ala.dedicated.aws.emqxcloud.com"
port = 8883
username = "ESP32"
password = "12345"
topic_firmware = "firmware/update"
topic_status = "esp32_status"
client_id = "OTA_Server"

# Firmware file settings
firmware_file = "OTA_test.bin"
chunk_size = 508
response_timeout = 20  # Increased to 20 seconds

# Global variables
ota_in_progress = False
total_size = 0
sent_size = 0
last_chunk_num = 0
last_chunk_size = 0
response_received = False

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker with result code " + str(rc))
        client.subscribe(topic_status, qos=1)
        print(f"Subscribed to {topic_status}")
    else:
        print(f"Connection failed with code {rc}")

def on_subscribe(client, userdata, mid, granted_qos):
    print(f"Subscription confirmed, MID: {mid}, QoS: {granted_qos}")

def on_publish(client, userdata, mid):
    print(f"Message {mid} published successfully")

def on_message(client, userdata, msg):
    global ota_in_progress, sent_size, last_chunk_num, last_chunk_size, response_received
    payload = msg.payload.decode('utf-8')
    print(f"Received on {msg.topic}: {payload}")

    if msg.topic == topic_status:
        if payload == "OTA:STARTED":
            print("ESP32 confirmed OTA start")
            response_received = True
        elif payload.startswith("OTA:PROGRESS:"):
            parts = payload.split(':')
            received_size = int(parts[2].split('/')[0])
            total_size_check = int(parts[2].split('/')[1])
            chunk_num = int(parts[4]) if len(parts) > 4 else -1
            print(f"ESP32 progress: {received_size}/{total_size_check} bytes, chunk {chunk_num}")

            # Calculate expected cumulative size
            expected_size = min(last_chunk_num * chunk_size, total_size)
            if chunk_num == last_chunk_num and received_size == expected_size:
                print(f"Chunk {chunk_num} confirmed received correctly")
                response_received = True
            else:
                print(f"Invalid response: Expected chunk {last_chunk_num} with cumulative {expected_size} bytes, got chunk {chunk_num} with {received_size} bytes")
        elif payload == "OTA:SUCCESS":
            print("ESP32 OTA completed successfully")
            ota_in_progress = False
            response_received = True
        elif payload.startswith("OTA:ERROR:"):
            print(f"ESP32 reported OTA error: {payload}")
            ota_in_progress = False
            response_received = True

def send_firmware_update(client, firmware_path):
    global ota_in_progress, total_size, sent_size, last_chunk_num, last_chunk_size, response_received

    if not os.path.exists(firmware_path):
        print(f"Firmware file {firmware_path} not found")
        return False

    total_size = os.path.getsize(firmware_path)
    print(f"File size on disk: {total_size} bytes")
    sent_size = 0
    last_chunk_num = 0
    response_received = False

    with open(firmware_path, "rb") as f:
        firmware_data = f.read()
        if len(firmware_data) != total_size:
            print(f"Error: Read {len(firmware_data)} bytes, expected {total_size} bytes")
            return False
        print(f"Total firmware size to send: {total_size} bytes")

        # Send OTA:BEGIN
        begin_msg = f"OTA:BEGIN:{total_size}"
        begin_encoded = base64.b64encode(begin_msg.encode('utf-8')).decode('utf-8')
        client.publish(topic_firmware, begin_encoded, qos=1)
        print(f"Sending: {begin_msg} (Base64: {begin_encoded})")
        ota_in_progress = True

        timeout = time.time() + response_timeout
        while not response_received and time.time() < timeout:
            time.sleep(0.1)
        if not response_received:
            print("Timeout waiting for OTA:STARTED")
            return False
        response_received = False

        # Send chunks
        num_chunks = (total_size + chunk_size - 1) // chunk_size
        print(f"Calculated {num_chunks} chunks for {total_size} bytes with chunk size {chunk_size}")

        for i in range(num_chunks):
            start = i * chunk_size
            chunk = firmware_data[start:start + chunk_size]
            chunk_size_actual = len(chunk)
            last_chunk_num = i + 1
            last_chunk_size = chunk_size_actual

            chunk_data = struct.pack('>I', last_chunk_num) + chunk
            chunk_encoded = base64.b64encode(chunk_data).decode('utf-8')
            retries = 10
            while retries > 0:
                pub_result = client.publish(topic_firmware, chunk_encoded, qos=1)
                print(f"Sending chunk {last_chunk_num}/{num_chunks} ({chunk_size_actual} bytes, Base64 length: {len(chunk_encoded)}, Total sent: {sent_size + chunk_size_actual}/{total_size})")
                print(f"Publish result: {pub_result.rc}, MID: {pub_result.mid}")

                timeout = time.time() + response_timeout
                while not response_received and time.time() < timeout:
                    time.sleep(0.1)
                
                if response_received:
                    sent_size += chunk_size_actual
                    response_received = False
                    break
                else:
                    retries -= 1
                    print(f"Timeout waiting for response to chunk {last_chunk_num}, retries left: {retries}")
                    time.sleep(2)  # Increased delay between retries

            if retries == 0:
                print(f"Failed to get valid response for chunk {last_chunk_num} after retries")
                return False

        # Send OTA:END
        end_msg = "OTA:END"
        end_encoded = base64.b64encode(end_msg.encode('utf-8')).decode('utf-8')
        client.publish(topic_firmware, end_encoded, qos=1)
        print(f"Sending: {end_msg} (Base64: {end_encoded})")

        timeout = time.time() + response_timeout
        while ota_in_progress and time.time() < timeout:
            time.sleep(0.1)
        if ota_in_progress:
            print("Timeout waiting for OTA completion")
            return False

        return True

    return False

def main():
    client = mqtt.Client(client_id=client_id, callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
    client.username_pw_set(username, password)
    client.tls_set()
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_publish = on_publish

    print(f"Connecting to {broker}:{port}...")
    client.connect(broker, port)
    client.loop_start()

    time.sleep(2)
    if send_firmware_update(client, firmware_file):
        print("OTA process finished successfully")
    else:
        print("Firmware update failed")

    client.loop_stop()
    client.disconnect()
    print("Disconnected from broker")

if __name__ == "__main__":
    main()