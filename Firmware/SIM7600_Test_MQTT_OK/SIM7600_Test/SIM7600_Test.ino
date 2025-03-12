#define TINY_GSM_MODEM_SIM7600 // Define modem type

#include <TinyGsmClient.h>
#include <PubSubClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>

#define RGB_LED_PIN 48 // Adjust based on your ESP32-S3 board
#define NUM_PIXELS 1   // Typically, onboard RGB LEDs have 1 pixel

Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);

// SIM7600 Serial Configuration
#define MODEM_TX 16
#define MODEM_RX 17

// APN Configuration
const char apn[] = "internet"; // Replace with your SIM provider APN
const char gprsUser[] = "";
const char gprsPass[] = "";

// Initialize Serial Interfaces
HardwareSerial sim7600(1);

#define TINY_GSM_MODEM_SIM7600

// Set serial for debug console (to the Serial Monitor, default speed 115200)
#define SerialMon Serial
#define SerialAT sim7600

// See all AT commands, if wanted
//#define DUMP_AT_COMMANDS

// Define the serial console for debug prints, if needed
#define TINY_GSM_DEBUG SerialMon

// Range to attempt to autobaud
// NOTE:  DO NOT AUTOBAUD in production code.  Once you've established
// communication, set a fixed baud rate using modem.setBaud(#).
#define GSM_AUTOBAUD_MIN 9600
#define GSM_AUTOBAUD_MAX 115200

// Add a reception delay, if needed.
// This may be needed for a fast processor at a slow baud rate.
// #define TINY_GSM_YIELD() { delay(2); }

// Define how you're planning to connect to the internet.
// This is only needed for this example, not in other code.
#define TINY_GSM_USE_GPRS true
#define TINY_GSM_USE_WIFI false

// set GSM PIN, if any
#define GSM_PIN ""

// Your GPRS credentials, if any

// Your WiFi connection credentials, if applicable
const char wifiSSID[] = "YourSSID";
const char wifiPass[] = "YourWiFiPass";

// MQTT details
// EMQX MQTT Server Configuration
const char *broker = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
const char *mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com"; // Replace with EMQX server URL/IP
const char *mqtt_user = "ESP32";
const char *mqtt_pass = "12345";
const char *mqtt_topic_send = "esp32_status";
const char *mqtt_topic_recv = "server_cmd";

#ifdef DUMP_AT_COMMANDS
#include <StreamDebugger.h>
StreamDebugger debugger(SerialAT, SerialMon);
TinyGsm modem(debugger);
#else
TinyGsm modem(SerialAT);
#endif
TinyGsmClient client(modem);
PubSubClient mqtt(client);

#define LED_PIN 13
uint8_t ledStatus = 0;

uint32_t lastReconnectAttempt = 0;

void mqttCallback(char *topic, byte *payload, unsigned int len)
{
  SerialMon.print("Message arrived [");
  SerialMon.print(topic);
  SerialMon.print("]: ");
  SerialMon.write(payload, len);
  SerialMon.println();

  // Only proceed if incoming message's topic matches
  if (String(topic) == mqtt_topic_recv)
  {
    ledStatus = !ledStatus;

    String esp32_reply = "Hi, I got your message : ";
    for (unsigned int i = 0; i < len; i++)
    {
      esp32_reply += (char)payload[i];
    }
    rgbLed.setPixelColor(0, rgbLed.Color(ledStatus, 0, 0));

    mqtt.publish(mqtt_topic_send, esp32_reply.c_str());
    // mqtt.publish(mqtt_topic_send, ledStatus ? "1" : "0");
  }
}

boolean mqttConnect()
{
  SerialMon.print("Connecting to ");
  SerialMon.print(mqtt_server);
  String clientID = "ESP32_SIM7600_" + String(millis()); // Unique ID every session
  boolean status = mqtt.connect(clientID.c_str(), mqtt_user, mqtt_pass);

  if (status == false)
  {
    SerialMon.println(" fail");
    return false;
  }
  SerialMon.println(" success");
  mqtt.publish(mqtt_topic_send, "Hi, I am Sim7600");
  mqtt.subscribe(mqtt_topic_recv);
  return mqtt.connected();
}

void setup()
{
  // Set console baud rate
  SerialMon.begin(115200);
  delay(10);

  sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
  rgbLed.begin();
  rgbLed.show(); // Initialize with LED off
  pinMode(LED_PIN, OUTPUT);

  // !!!!!!!!!!!
  // Set your reset, enable, power pins here
  // !!!!!!!!!!!

  SerialMon.println("Wait...");

  // Set GSM module baud rate
  //TinyGsmAutoBaud(SerialAT, GSM_AUTOBAUD_MIN, GSM_AUTOBAUD_MAX);
  SerialAT.begin(115200);
  delay(2000);

  // Restart takes quite some time
  // To skip it, call init() instead of restart()
  SerialMon.println("Initializing modem...");
 // modem.restart();
  modem.init();

  String modemInfo = modem.getModemInfo();
  SerialMon.print("Modem Info: ");
  SerialMon.println(modemInfo);

#if TINY_GSM_USE_GPRS
  // Unlock your SIM card with a PIN if needed
  if (GSM_PIN && modem.getSimStatus() != 3)
  {
    modem.simUnlock(GSM_PIN);
  }
#endif

#if TINY_GSM_USE_WIFI
  // Wifi connection parameters must be set before waiting for the network
  SerialMon.print(F("Setting SSID/password..."));
  if (!modem.networkConnect(wifiSSID, wifiPass))
  {
    SerialMon.println(" fail");
    delay(10000);
    return;
  }
  SerialMon.println(" success");
#endif

#if TINY_GSM_USE_GPRS && defined TINY_GSM_MODEM_XBEE
  // The XBee must run the gprsConnect function BEFORE waiting for network!
  modem.gprsConnect(apn, gprsUser, gprsPass);
#endif

  SerialMon.print("Waiting for network...");
  if (!modem.waitForNetwork())
  {
    SerialMon.println(" fail");
    delay(10000);
    return;
  }
  SerialMon.println(" success");

  if (modem.isNetworkConnected())
  {
    SerialMon.println("Network connected");
  }

#if TINY_GSM_USE_GPRS
  // GPRS connection parameters are usually set after network registration
  SerialMon.print(F("Connecting to "));
  SerialMon.print(apn);
  if (!modem.gprsConnect(apn, gprsUser, gprsPass))
  {
    SerialMon.println(" fail");
    delay(5000);
    return;
  }
  SerialMon.println(" success");

  if (modem.isGprsConnected())
  {
    SerialMon.println("GPRS connected");
  }
#endif

  // MQTT Broker setup
  mqtt.setServer(mqtt_server, 1883);
  mqtt.setCallback(mqttCallback);
}

void loop()
{
  // Make sure we're still registered on the network
  if (!modem.isNetworkConnected())
  {
    SerialMon.println("Network disconnected");
    if (!modem.waitForNetwork(180000L, true))
    {
      SerialMon.println(" fail");
      delay(10000);
      return;
    }
    if (modem.isNetworkConnected())
    {
      SerialMon.println("Network re-connected");
    }

#if TINY_GSM_USE_GPRS
    // and make sure GPRS/EPS is still connected
    if (!modem.isGprsConnected())
    {
      SerialMon.println("GPRS disconnected!");
      SerialMon.print(F("Connecting to "));
      SerialMon.print(apn);
      if (!modem.gprsConnect(apn, gprsUser, gprsPass))
      {
        SerialMon.println(" fail");
        delay(10000);
        return;
      }
      if (modem.isGprsConnected())
      {
        SerialMon.println("GPRS reconnected");
      }
    }
#endif
  }

  if (!mqtt.connected())
  {
    SerialMon.println("=== MQTT NOT CONNECTED ===");
    // Reconnect every 10 seconds
    uint32_t t = millis();
    if (t - lastReconnectAttempt > 10000L)
    {
      lastReconnectAttempt = t;
      if (mqttConnect())
      {
        lastReconnectAttempt = 0;
      }
    }
    delay(5000);
    return;
  }

  mqtt.loop();
}
