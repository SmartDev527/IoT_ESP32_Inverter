#include <HardwareSerial.h>
#include <ModbusMaster.h>

// RS485 UART1 Pins
#define RS485_RX 10  // UART1 RX pin
#define RS485_TX 11  // UART1 TX pin
#define RS485_EN 15  // Enable pin for RS485 module

// Modbus settings
#define SLAVE_ID 1   // Verify this matches your inverter's slave ID
#define MODBUS_BAUD 9600

// HardwareSerial instances
HardwareSerial rs485(1);  // UART1 for Modbus

// ModbusMaster object
ModbusMaster node;

// Pre- and post-transmission for RS485
void preTransmission() {
  digitalWrite(RS485_EN, HIGH);
  delay(1);
  //Serial.println("RS485 Enabled (HIGH)");
}

void postTransmission() {
  digitalWrite(RS485_EN, LOW);
  delay(1);
  //Serial.println("RS485 Disabled (LOW)");
  delay(100); // Added delay to give inverter time to respond
}

// Write Single Register (Function Code 0x06)
void writeSingleRegister(uint16_t reg, uint16_t value) {
  Serial.print("Writing register "); Serial.print(reg); 
  Serial.print(" with value 0x"); Serial.println(value, HEX);
  preTransmission();
  uint8_t result = node.writeSingleRegister(reg, value);
  postTransmission();
  if (result == node.ku8MBSuccess) {
    Serial.println("Write Single Register successful");
  } else {
    Serial.print("Write failed, error: 0x");
    Serial.println(result, HEX);
  }
}

// Write Single Coil (Function Code 0x05)
void writeSingleCoil(uint16_t reg, bool state) {
  Serial.print("Writing coil "); Serial.print(reg); 
  Serial.print(" with state "); Serial.println(state);
  preTransmission();
  uint8_t result = node.writeSingleCoil(reg, state ? 0xFF00 : 0x0000);
  postTransmission();
  if (result == node.ku8MBSuccess) {
    Serial.println("Write Single Coil successful");
  } else {
    Serial.print("Write failed, error: 0x");
    Serial.println(result, HEX);
  }
}

// Write Multiple Registers (Function Code 0x10)
void writeMultipleRegisters(uint16_t reg, uint16_t* values, uint8_t count) {
  Serial.print("Writing "); Serial.print(count); Serial.print(" registers starting at "); Serial.println(reg);
  preTransmission();
  for (uint8_t i = 0; i < count; i++) {
    node.setTransmitBuffer(i, values[i]);
    Serial.print("Buffer["); Serial.print(i); Serial.print("] = 0x"); Serial.println(values[i], HEX);
  }
  uint8_t result = node.writeMultipleRegisters(reg, count);
  postTransmission();
  if (result == node.ku8MBSuccess) {
    Serial.println("Write Multiple Registers successful");
  } else {
    Serial.print("Write failed, error: 0x");
    Serial.println(result, HEX);
  }
}

// Read Holding Registers (Function Code 0x03)
void readHoldingRegisters(uint16_t startReg, uint8_t count) {
  Serial.print("Reading "); Serial.print(count); Serial.print(" registers starting at "); Serial.printf("0x%x\n", startReg);
  preTransmission();
  uint8_t result = node.readHoldingRegisters(startReg, count);
  postTransmission();
  if (result == node.ku8MBSuccess) {
    Serial.println("Read successful:");
    for (uint8_t i = 0; i < count; i++) {
      Serial.print("Register ");
      Serial.printf("0x%2x", (startReg + i));
      Serial.print(": 0x");
      Serial.println(node.getResponseBuffer(i), HEX);
    }
  } else {
    Serial.print("Read failed, error: 0x");
    Serial.println(result, HEX);
    switch (result) {
      case 0x01: Serial.println("Illegal Function"); break;
      case 0x02: Serial.println("Illegal Data Address"); break;
      case 0x03: Serial.println("Illegal Data Value"); break;
      case 0x04: Serial.println("Device Failure"); break;
      case 0xE0: Serial.println("Invalid Slave ID or No Response"); break;
      case 0xE2: Serial.println("Response Timed Out"); break;
      default: Serial.println("Unknown Error"); break;
    }
  }
}

// Helper function to parse hex or decimal string
uint16_t parseNumber(String str) {
  str.trim();
  if (str.startsWith("0x") || str.startsWith("0X")) {
    return (uint16_t)strtol(str.c_str() + 2, NULL, 16);
  }
  return (uint16_t)str.toInt();
}

// Parse and execute commands from Serial input
void processCommand(String command) {
  command.trim();
  if (command.startsWith("read")) {
    int space1 = command.indexOf(' ');
    int space2 = command.lastIndexOf(' ');
    if (space1 != -1 && space2 != -1 && space1 != space2) {
      uint16_t reg = parseNumber(command.substring(space1 + 1, space2));
      uint8_t count = parseNumber(command.substring(space2 + 1));
      readHoldingRegisters(reg, count);
    } else {
      Serial.println("Invalid read command. Use: read <register> <count> (e.g., read 0x1F4 10)");
    }
  } 
  else if (command.startsWith("write_reg")) {
    int space1 = command.indexOf(' ');
    int space2 = command.lastIndexOf(' ');
    if (space1 != -1 && space2 != -1 && space1 != space2) {
      uint16_t reg = parseNumber(command.substring(space1 + 1, space2));
      uint16_t value = parseNumber(command.substring(space2 + 1));
      writeSingleRegister(reg, value);
    } else {
      Serial.println("Invalid write_reg command. Use: write_reg <register> <value> (e.g., write_reg 0x64 0x1F4)");
    }
  } 
  else if (command.startsWith("write_coil")) {
    int space1 = command.indexOf(' ');
    int space2 = command.lastIndexOf(' ');
    if (space1 != -1 && space2 != -1 && space1 != space2) {
      uint16_t reg = parseNumber(command.substring(space1 + 1, space2));
      bool state = parseNumber(command.substring(space2 + 1)) == 1;
      writeSingleCoil(reg, state);
    } else {
      Serial.println("Invalid write_coil command. Use: write_coil <register> <0/1> (e.g., write_coil 0x32 1)");
    }
  } 
  else if (command.startsWith("write_multi")) {
    int space1 = command.indexOf(' ');
    int space2 = command.indexOf(' ', space1 + 1);
    int space3 = command.indexOf(' ', space2 + 1);
    if (space1 != -1 && space2 != -1 && space3 != -1) {
      uint16_t reg = parseNumber(command.substring(space1 + 1, space2));
      uint8_t count = parseNumber(command.substring(space2 + 1, space3));
      if (count > 10) { // Arbitrary limit for safety
        Serial.println("Count too large. Max 10 registers.");
        return;
      }
      uint16_t values[10];
      int lastSpace = space3;
      for (uint8_t i = 0; i < count; i++) {
        int nextSpace = command.indexOf(' ', lastSpace + 1);
        if (nextSpace == -1 && i < count - 1) {
          Serial.println("Not enough values provided.");
          return;
        }
        String valStr = command.substring(lastSpace + 1, nextSpace == -1 ? command.length() : nextSpace);
        values[i] = parseNumber(valStr);
        lastSpace = nextSpace;
      }
      writeMultipleRegisters(reg, values, count);
    } else {
      Serial.println("Invalid write_multi command. Use: write_multi <register> <count> <value1> <value2> ... (e.g., write_multi 0x64 2 0x1F4 0xC8)");
    }
  } 
  else {
    Serial.println("Unknown command. Available commands:");
    Serial.println("  read <register> <count> (e.g., read 0x1F4 10)");
    Serial.println("  write_reg <register> <value> (e.g., write_reg 0x64 0x1F4)");
    Serial.println("  write_coil <register> <0/1> (e.g., write_coil 0x32 1)");
    Serial.println("  write_multi <register> <count> <value1> <value2> ... (e.g., write_multi 0x64 2 0x1F4 0xC8)");
  }
}

void setup() {
  // UART0 for debug (default Serial on ESP32)
  Serial.begin(115200);
  delay(1000);
  Serial.println("ESP32 Modbus RTU Inverter Test (UART1 for Modbus)");
  Serial.println("Enter commands via Serial Monitor (e.g., 'read 0x1F4 10')");
  Serial.print("Modbus Slave ID: "); Serial.println(SLAVE_ID);
  Serial.print("Modbus Baud Rate: "); Serial.println(MODBUS_BAUD);
  Serial.println("Note: Using default ModbusMaster timeout (typically 1000ms)");
  Serial.println("Values can be in decimal or hex (e.g., 500 or 0x1F4)");

  // Initialize RS485 on UART1
  pinMode(RS485_EN, OUTPUT);
  digitalWrite(RS485_EN, LOW);
  rs485.begin(MODBUS_BAUD, SERIAL_8N1, RS485_RX, RS485_TX);
  node.begin(SLAVE_ID, rs485);
  node.preTransmission(preTransmission);
  node.postTransmission(postTransmission);
}

void loop() {
  // Check for incoming commands on UART0 (Serial)
  static String inputString = "";
  while (Serial.available()) {
    char inChar = (char)Serial.read();
    if (inChar == '\n') {
      processCommand(inputString);
      inputString = "";
    } else {
      inputString += inChar;
    }
  }
}