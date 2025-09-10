#include <WiFi.h>
#include <WiFiClient.h>
#include <HTTPClient.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <cstring>

#include <ArduinoJson.h>

// ---------- User Config ----------
// Set via Serial at boot or use defaults below
String WIFI_SSID = "KABALI RAAA";
String WIFI_PASS = "";
String PI_HOST = "10.223.52.243"; // Pi IP
uint16_t PI_PORT = 5001;          // TCP port
String SHARED_PASSPHRASE = "ecs"; // Must match UI configuration

// ---------- Helpers ----------
static void sha256(const uint8_t *input, size_t len, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, input, len);
  mbedtls_md_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

static int b64decode(const char *in, uint8_t *out, size_t out_size) {
  // Simple base64 decoder for ESP32
  const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int len = strlen(in);
  int out_len = 0;
  
  for (int i = 0; i < len; i += 4) {
    if (out_len >= (int)out_size) return -1;
    
    uint32_t val = 0;
    int pad = 0;
    
    for (int j = 0; j < 4; j++) {
      if (i + j >= len) return -1;
      char c = in[i + j];
      if (c == '=') {
        pad++;
        continue;
      }
      const char *pos = strchr(chars, c);
      if (!pos) return -1;
      val = (val << 6) | (pos - chars);
    }
    
    for (int j = 0; j < 3 - pad; j++) {
      if (out_len >= (int)out_size) return -1;
      out[out_len++] = (val >> (16 - 8*j)) & 0xFF;
    }
  }
  return out_len;
}

static bool aes_gcm_decrypt(const uint8_t key[32], const uint8_t *iv, size_t iv_len,
                             const uint8_t *ciphertext, size_t ct_len, const uint8_t *tag,
                             size_t tag_len, const uint8_t *aad, size_t aad_len,
                             uint8_t *out_plain) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc != 0) { mbedtls_gcm_free(&gcm); return false; }
  rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, iv_len, aad, aad_len, tag, tag_len,
                                ciphertext, out_plain);
  mbedtls_gcm_free(&gcm);
  return rc == 0;
}

WiFiClient client;
WiFiClient httpClient;
uint8_t key[32];

// Function declarations
void sendToWebServer(const String& message, const String& type = "info");

void connectWifi() {
  Serial.printf("Connecting to WiFi %s...\n", WIFI_SSID.c_str());
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 60) {
    delay(500);
    Serial.print(".");
    tries++;
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("WiFi connected, IP: %s\n", WiFi.localIP().toString().c_str());
    sendToWebServer("WiFi connected: " + WiFi.localIP().toString(), "info");
  } else {
    Serial.println("WiFi connect failed.");
    sendToWebServer("WiFi connection failed", "error");
  }
}

void connectTcp() {
  Serial.printf("Connecting TCP %s:%u ...\n", PI_HOST.c_str(), PI_PORT);
  if (!client.connect(PI_HOST.c_str(), PI_PORT)) {
    Serial.println("TCP connect failed.");
    sendToWebServer("TCP connection failed", "error");
    return;
  }
  Serial.println("TCP connected.");
  sendToWebServer("TCP connected to Pi server", "info");
}

void deriveKey() {
  sha256((const uint8_t*)SHARED_PASSPHRASE.c_str(), SHARED_PASSPHRASE.length(), key);
  Serial.println("Derived AES-256 key from passphrase.");
}

void sendToWebServer(const String& message, const String& type) {
  if (WiFi.status() != WL_CONNECTED) return;
  
  HTTPClient http;
  http.begin(httpClient, "http://" + PI_HOST + ":5000/esp32-status");
  http.addHeader("Content-Type", "application/json");
  
  StaticJsonDocument<256> doc;
  doc["message"] = message;
  doc["type"] = type;
  
  String jsonString;
  serializeJson(doc, jsonString);
  
  int httpResponseCode = http.POST(jsonString);
  if (httpResponseCode > 0) {
    Serial.println("Status sent to web server: " + message);
  } else {
    Serial.println("Failed to send status to web server");
  }
  http.end();
}


void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nESP32 Secure Receiver starting...");
  Serial.println("Using hardcoded settings:");
  Serial.println("SSID: " + WIFI_SSID);
  Serial.println("Pi Host: " + PI_HOST);
  Serial.println("Pi Port: " + String(PI_PORT));
  Serial.println("Passphrase: [SET]");
  Serial.println();

  connectWifi();
  deriveKey();
  connectTcp();
  
  // Send initial status to web server
  sendToWebServer("ESP32 Client started and ready", "info");
}

String readLine(WiFiClient &c) {
  String line;
  unsigned long timeout = millis() + 5000; // 5 second timeout
  
  while (c.connected() && millis() < timeout) {
    if (c.available()) {
      char ch = (char)c.read();
      if (ch == '\n') break;
      line += ch;
    } else {
      delay(10);
    }
  }
  
  // Debug: print what we received
  Serial.print("Received line: ");
  Serial.println(line);
  Serial.print("Line length: ");
  Serial.println(line.length());
  
  // Debug: print raw bytes
  Serial.print("Raw bytes: ");
  for (int i = 0; i < line.length(); i++) {
    Serial.print((int)line[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
  
  return line;
}

void loop() {
  if (!client.connected()) {
    delay(500);
    connectTcp();
    delay(500);
    return;
  }

  String line = readLine(client);
  if (line.length() == 0) {
    delay(10);
    return;
  }
  
  // Check if line is too short to be valid JSON
  if (line.length() < 50) {
    Serial.print("Line too short, ignoring: ");
    Serial.println(line);
    return;
  }
  
  // Test with a known good JSON string first
  if (line.indexOf("test") >= 0) {
    Serial.println("Testing with known JSON...");
    String testJson = "{\"iv\":\"dGVzdA==\",\"ciphertext\":\"dGVzdA==\",\"tag\":\"dGVzdA==\"}";
    StaticJsonDocument<256> testDoc;
    DeserializationError testErr = deserializeJson(testDoc, testJson);
    if (testErr) {
      Serial.print("Test JSON failed: ");
      Serial.println(testErr.c_str());
    } else {
      Serial.println("Test JSON parsing works!");
    }
  }
  // Parse JSON { iv, ciphertext, tag }
  Serial.println("Received encrypted message, parsing JSON...");
  sendToWebServer("Received encrypted message, parsing JSON...", "info");
  
  StaticJsonDocument<1024> doc;
  DeserializationError err = deserializeJson(doc, line);
  if (err) {
    Serial.print("JSON parse error: "); Serial.println(err.c_str());
    Serial.print("Raw JSON string: "); Serial.println(line);
    sendToWebServer("JSON parse error: " + String(err.c_str()), "error");
    return;
  }
  
  // Debug: print the parsed document
  Serial.println("JSON document parsed successfully");
  Serial.print("Document size: "); Serial.println(doc.size());
  const char *iv_b64 = doc["iv"] | nullptr;
  const char *ct_b64 = doc["ciphertext"] | nullptr;
  const char *tag_b64 = doc["tag"] | nullptr;
  
  Serial.print("Parsed fields - iv: ");
  Serial.print(iv_b64 ? "OK" : "NULL");
  if (iv_b64) {
    Serial.print(" (");
    Serial.print(iv_b64);
    Serial.print(")");
  }
  Serial.print(", ciphertext: ");
  Serial.print(ct_b64 ? "OK" : "NULL");
  if (ct_b64) {
    Serial.print(" (");
    Serial.print(ct_b64);
    Serial.print(")");
  }
  Serial.print(", tag: ");
  Serial.print(tag_b64 ? "OK" : "NULL");
  if (tag_b64) {
    Serial.print(" (");
    Serial.print(tag_b64);
    Serial.print(")");
  }
  Serial.println();
  
  if (!iv_b64 || !ct_b64 || !tag_b64) {
    Serial.println("Invalid JSON fields - missing required fields.");
    sendToWebServer("Invalid JSON fields - missing required fields", "error");
    return;
  }

  Serial.println("JSON parsed successfully, decoding base64...");
  sendToWebServer("JSON parsed successfully, decoding base64...", "info");

  uint8_t iv[16]; // will use 12
  uint8_t ct[1024];
  uint8_t tag[16];
  int iv_len = b64decode(iv_b64, iv, sizeof(iv));
  int ct_len = b64decode(ct_b64, ct, sizeof(ct));
  int tag_len = b64decode(tag_b64, tag, sizeof(tag));
  if (iv_len <= 0 || ct_len <= 0 || tag_len <= 0) {
    Serial.println("Base64 decode failed.");
    sendToWebServer("Base64 decode failed", "error");
    return;
  }

  Serial.println("Base64 decoded successfully, starting decryption...");
  sendToWebServer("Base64 decoded successfully, starting decryption...", "info");

  uint8_t plain[1024];
  bool ok = aes_gcm_decrypt(key, iv, (size_t)iv_len, ct, (size_t)ct_len, tag, (size_t)tag_len,
                            nullptr, 0, plain);
  if (!ok) {
    Serial.println("Decrypt verify failed.");
    sendToWebServer("Decrypt verify failed", "error");
    return;
  }
  
  Serial.println("Decryption successful, extracting plaintext...");
  sendToWebServer("Decryption successful, extracting plaintext...", "info");
  
  String msg;
  msg.reserve(ct_len + 1);
  for (int i = 0; i < ct_len; ++i) {
    msg += (char)plain[i];
  }
  Serial.print("Decrypted: ");
  Serial.println(msg);
  
  // Send decrypted message to web server
  sendToWebServer("✅ Message decrypted successfully: " + msg, "decrypted");
}


