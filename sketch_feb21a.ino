#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define DEBUG 1   // Set to 0 to disable verbose logs

// ================= CONFIG =================

const char* ssid = "Still didn't concent";
const char* password = "samajnahiaatakya";
const char* server_url = "https://10.251.188.85:8443";

String device_id = "device1";
String firmware_hash = "firmware_v1_hash";

String current_nonce = "";
bool device_registered = false;
bool access_revoked = false;

// ECC
mbedtls_pk_context pk;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

// ================= DEBUG UTIL =================

void debugPrint(String msg) {
  if (DEBUG) {
    Serial.println(msg);
  }
}

void printStatus() {
  Serial.println("\n===== DEVICE STATUS =====");
  Serial.print("WiFi: ");
  Serial.println(WiFi.status() == WL_CONNECTED ? "CONNECTED" : "DISCONNECTED");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
  Serial.print("RSSI: ");
  Serial.println(WiFi.RSSI());
  Serial.print("Nonce: ");
  Serial.println(current_nonce);
  Serial.print("Access Revoked: ");
  Serial.println(access_revoked ? "YES" : "NO");
  Serial.print("Free Heap: ");
  Serial.println(ESP.getFreeHeap());
  Serial.println("=========================\n");
}

// ================= ECC INIT =================

void initECC() {
  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char* pers = "heartchain";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));

  mbedtls_pk_setup(&pk,
                   mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                      mbedtls_pk_ec(pk),
                      mbedtls_ctr_drbg_random,
                      &ctr_drbg);

  debugPrint("[ECC] Key pair generated");
}

// ================= SIGN MESSAGE =================

String signMessage(String message) {

  unsigned char hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const unsigned char*)message.c_str(),
             message.length(),
             hash);

  unsigned char sig[100];
  size_t sig_len;

  int ret = mbedtls_pk_sign(&pk,
                            MBEDTLS_MD_SHA256,
                            hash,
                            0,
                            sig,
                            sizeof(sig),
                            &sig_len,
                            mbedtls_ctr_drbg_random,
                            &ctr_drbg);

  if (ret != 0) {
    debugPrint("[ECC ERROR] Signing failed");
    return "";
  }

  String signature = "";
  for (int i = 0; i < sig_len; i++) {
    if (sig[i] < 16) signature += "0";
    signature += String(sig[i], HEX);
  }

  debugPrint("[ECC] Signature generated");
  return signature;
}

// ================= REGISTER =================

void registerDevice() {

  if (WiFi.status() != WL_CONNECTED) {
    debugPrint("[ERROR] Cannot register. WiFi not connected.");
    return;
  }

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.begin(client, String(server_url) + "/register");

  StaticJsonDocument<512> doc;
  doc["device_id"] = device_id;
  doc["firmware_hash"] = firmware_hash;

  // Export public key
unsigned char buf[200];
int len = mbedtls_pk_write_pubkey_der(&pk, buf, sizeof(buf));

if (len <= 0) {
  debugPrint("[ECC ERROR] Public key export failed");
  return;
}

// KEY IS AT END OF BUFFER
unsigned char* key_start = buf + sizeof(buf) - len;

String pubkey = "";
for (int i = 0; i < len; i++) {
  if (key_start[i] < 16) pubkey += "0";
  pubkey += String(key_start[i], HEX);
}

doc["public_key"] = pubkey;
  String payload;
  serializeJson(doc, payload);

  debugPrint("[REGISTER] Sending request...");

  int code = https.POST(payload);

  if (code == 200) {
    String response = https.getString();
    debugPrint("[REGISTER SUCCESS]");
    StaticJsonDocument<256> resp;
    deserializeJson(resp, response);
    current_nonce = resp["nonce"].as<String>();
    device_registered = true;
  } else {
    debugPrint("[REGISTER FAILED]");
  }

  https.end();
}

// ================= TELEMETRY =================

void sendTelemetry() {

  if (!device_registered) {
    debugPrint("[WARNING] Device not registered.");
    return;
  }

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient https;
  https.begin(client, String(server_url) + "/telemetry");

  StaticJsonDocument<512> doc;
  doc["device_id"] = device_id;
  doc["firmware_hash"] = firmware_hash;
  doc["nonce"] = current_nonce;
  doc["data"] = random(60, 100);

  String message = device_id + firmware_hash + String(doc["data"].as<int>()) + current_nonce;

  String signature = signMessage(message);
  doc["signature"] = signature;

  String payload;
  serializeJson(doc, payload);

  unsigned long start = millis();
  int code = https.POST(payload);
  unsigned long latency = millis() - start;

  debugPrint("[TELEMETRY] HTTP Code: " + String(code));
  debugPrint("[TELEMETRY] Latency: " + String(latency) + " ms");

  if (code == 200) {

    String response = https.getString();
    StaticJsonDocument<256> resp;
    deserializeJson(resp, response);

    String status = resp["status"];

    if (status == "verified") {

      access_revoked = false;
      current_nonce = resp["nonce"].as<String>();
      debugPrint("[SUCCESS] Telemetry verified");

    } else if (status == "revoked") {

      access_revoked = true;
      debugPrint("[ACCESS REVOKED BY SERVER]");

    } else if (status == "invalid_nonce") {

      debugPrint("[ERROR] Nonce invalid. Re-registering...");
      registerDevice();

    } else if (status == "unknown") {

      debugPrint("[ERROR] Device unknown. Re-registering...");
      registerDevice();

    } else {

      debugPrint("[SERVER RESPONSE] " + status);
    }

  } else {
    debugPrint("[ERROR] Telemetry failed");
  }

  https.end();
}

// ================= WIFI =================

void connectWiFi() {
  WiFi.begin(ssid, password);
  debugPrint("Connecting to WiFi...");

  int retry = 0;
  while (WiFi.status() != WL_CONNECTED && retry < 20) {
    delay(500);
    Serial.print(".");
    retry++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    debugPrint("\nWiFi Connected!");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
  } else {
    debugPrint("\nWiFi Failed!");
  }
}

// ================= SETUP =================

void setup() {
  Serial.begin(115200);
  delay(2000);

  debugPrint("HeartChain ESP32 Booting...");
  connectWiFi();
  initECC();
  registerDevice();
}

// ================= LOOP =================

unsigned long lastTelemetry = 0;
unsigned long lastStatusPrint = 0;

void loop() {

  if (millis() - lastTelemetry > 5000) {
    sendTelemetry();
    lastTelemetry = millis();
  }

  if (millis() - lastStatusPrint > 10000) {
    printStatus();
    lastStatusPrint = millis();
  }
}