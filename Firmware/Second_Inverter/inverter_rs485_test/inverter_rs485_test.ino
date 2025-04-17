#include <HardwareSerial.h>

// RS485 pins
#define RS485_RX 10
#define RS485_TX 11

// Serial port for RS485
HardwareSerial RS485Serial(1);

// Buffer for received data
uint8_t rxBuffer[128];
int rxIndex = 0;

// Function to calculate CRC16-Modbus
uint16_t calculateCRC16(uint8_t *data, uint8_t length) {
    uint16_t crc = 0xFFFF;
    for (uint8_t pos = 0; pos < length; pos++) {
        crc ^= (uint16_t)data[pos];
        for (uint8_t i = 8; i != 0; i--) {
            if ((crc & 0x0001) != 0) {
                crc >>= 1;
                crc ^= 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

// Function to send device parameter query
void sendDeviceParameterQuery(uint16_t deviceAddress) {
    uint8_t frame[] = {
        0x7E,                     // Frame header
        (uint8_t)(deviceAddress >> 8), // Device address high
        (uint8_t)(deviceAddress & 0xFF), // Device address low
        0x00, 0x02,               // Data length
        0x01,                     // Function code
        0x01,                     // Command type
        0x00, 0x00                // CRC (to be calculated)
    };
    
    // Calculate CRC from device address to command type (bytes 1 to 6)
    uint16_t crc = calculateCRC16(&frame[1], 6);
    frame[7] = (uint8_t)(crc & 0xFF);        // CRC low
    frame[8] = (uint8_t)(crc >> 8);          // CRC high
    
    // Send frame
    RS485Serial.write(frame, sizeof(frame));
    RS485Serial.flush();
}

// Function to parse received frame
void parseResponse(uint8_t *buffer, int length) {
    // Check minimum length and frame header
    if (length < 8 || buffer[0] != 0x7E) {
        Serial.println("Invalid frame");
        return;
    }
    
    // Verify CRC (from device address to data end)
    uint16_t receivedCRC = (buffer[length-1] << 8) | buffer[length-2];
    uint16_t calculatedCRC = calculateCRC16(&buffer[1], length-3);
    if (receivedCRC != calculatedCRC) {
        Serial.println("CRC error");
        return;
    }
    
    // Check function code and command type
    if (buffer[5] != 0x01 || buffer[6] != 0x01) {
        Serial.println("Unexpected response");
        return;
    }
    
    // Extract data (assuming data length is 0x3C as specified)
    if (buffer[4] != 0x3C) {
        Serial.println("Unexpected data length");
        return;
    }
    
    // Print manufacturer (bytes 7-22)
    Serial.print("Manufacturer: ");
    for (int i = 7; i <= 22; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
            Serial.write((char)buffer[i]);
        }
    }
    Serial.println();
    
    // Print model (bytes 23-38)
    Serial.print("Model: ");
    for (int i = 23; i <= 38; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
            Serial.print((char)buffer[i]);
        }
    }
    Serial.println();
    
    // Print serial number (bytes 39-54)
    Serial.print("Serial Number: ");
    for (int i = 39; i <= 54; i++) {
        if (buffer[i] >= 32 && buffer[i] <= 126) {
            Serial.print((char)buffer[i]);
        }
    }
    Serial.println();
    
    // Machine type (byte 55)
    Serial.print("Machine Type: ");
    switch (buffer[55]) {
        case 0x01: Serial.println("Single-phase grid-connected"); break;
        case 0x03: Serial.println("Three-phase grid-connected"); break;
        case 0xE1: Serial.println("Single-phase energy storage"); break;
        case 0xE3: Serial.println("Three-phase energy storage"); break;
        default: Serial.println("Unknown"); break;
    }
    
    // Firmware version (bytes 56-57)
    Serial.print("Firmware Version: ");
    Serial.print(buffer[56], HEX);
    Serial.print(".");
    Serial.println(buffer[57], HEX);
    
    // Communication version (bytes 58-59)
    Serial.print("Communication Version: ");
    Serial.print(buffer[58], HEX);
    Serial.print(".");
    Serial.println(buffer[59], HEX);
    
    // Safety regulation type (bytes 60-61)
    Serial.print("Safety Regulation Type: 0x");
    Serial.println((buffer[60] << 8) | buffer[61], HEX);
    
    // Power rating (bytes 62-63)
    uint16_t powerRating = (buffer[62] << 8) | buffer[63];
    Serial.print("Power Rating: ");
    Serial.print(powerRating);
    Serial.println(" W");
    
    // Number of PV (byte 64)
    Serial.print("Number of PV: ");
    Serial.println(buffer[64]);
}

void setup() {
    // Initialize USB Serial for debugging
    Serial.begin(115200);
    while (!Serial) {
        delay(10);
    }
    
    // Initialize RS485 Serial
    RS485Serial.begin(9600, SERIAL_8N1, RS485_RX, RS485_TX);
    
    Serial.println("ESP32-S3 RS485 Inverter Test");
}

void loop() {
    // Send query every 5 seconds
    static unsigned long lastQuery = 0;
    if (millis() - lastQuery >= 5000) {
        Serial.println("Sending device parameter query...");
        sendDeviceParameterQuery(0x0001); // Using default address 0x0001
        lastQuery = millis();
    }
    
    // Read incoming data
    while (RS485Serial.available()) {
        uint8_t data = RS485Serial.read();
        
        // Look for frame header
        if (data == 0x7E && rxIndex == 0) {
            rxBuffer[rxIndex++] = data;
        }
        // Continue collecting frame
        else if (rxIndex > 0) {
            rxBuffer[rxIndex++] = data;
            
            // Check if we have a complete frame
            if (rxIndex >= 4 && rxIndex >= (rxBuffer[4] + 7)) {
                parseResponse(rxBuffer, rxIndex);
                rxIndex = 0; // Reset buffer
            }
        }
        
        // Prevent buffer overflow
        if (rxIndex >= sizeof(rxBuffer)) {
            rxIndex = 0;
        }
    }
}