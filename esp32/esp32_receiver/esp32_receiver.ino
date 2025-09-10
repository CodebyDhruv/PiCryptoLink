#include <WiFi.h>
#include <WiFiClient.h>
#include <HTTPClient.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <cstring>
#include <ArduinoJson.h>

// ---------- User Config ----------
String WIFI_SSID = "KABALI RAAA";
String WIFI_PASS = "";
String PI_HOST = "10.223.52.243"; 
uint16_t PI_PORT = 5001;          
String SHARED_PASSPHRASE = "ecs"; 

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
  const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int len = strlen(in);
  int out_len = 0;
  
  for (int i = 0; i < len; i += 4) {
    if (out_len >= (int)out_size) return -1;
    
    uint32_t val = 0;
    int pad = 0;
    int valid_chars = 0;
    
    for (int j = 0; j < 4 && (i + j) < len; j++) {
      char c = in[i + j];
      if (c == '=') {
        pad++;
        continue;
      }
      if (c == ' ' || c == '\n' || c == '\r') {
        continue;
      }
      const char *pos = strchr(chars, c);
      if (!pos) return -1;
      val = (val << 6) | (pos - chars);
      valid_chars++;
    }
    
    val <<= (6 * (4 - valid_chars));
    
    for (int j = 0; j < 3 - pad && j < 3; j++) {
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
  if (rc != 0) { 
    Serial.printf("GCM setkey failed: %d\n", rc);
    mbedtls_gcm_free(&gcm); 
    return false; 
  }
  rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, iv_len, aad, aad_len, tag, tag_len,
                                ciphertext, out_plain);
  if (rc != 0) {
    Serial.printf("GCM decrypt failed: %d\n", rc);
  }
  mbedtls_gcm_free(&gcm);
  return rc == 0;
}

WiFiClient client;
WiFiClient httpClient;
uint8_t key[32];

void sendToWebServer(const String& message, const String& type = "info") {
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
    Serial.println("Status sent: " + message);
  }
  http.end();
}

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
  Serial.println("=== KEY DERIVATION ===");
  Serial.printf("Passphrase: '%s'\n", SHARED_PASSPHRASE.c_str());
  Serial.print("Key (first 8 bytes): ");
  for (int i = 0; i < 8; i++) {
    Serial.printf("%02X ", key[i]);
  }
  Serial.println();
  Serial.println("Expected: D9 40 B5 64 13 AF 58 48");
  Serial.println("=====================");
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n=== ESP32 CRYPTO DEBUG ===");
  
  connectWifi();
  deriveKey();
  connectTcp();
  
  sendToWebServer("ESP32 ready for crypto debug", "info");
}

String readCompleteJson(WiFiClient &c) {
  String buffer = "";
  unsigned long timeout = millis() + 10000;
  bool jsonStarted = false;
  int braceCount = 0;
  
  while (c.connected() && millis() < timeout) {
    if (c.available()) {
      char ch = (char)c.read();
      
      if (!jsonStarted && (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t')) {
        continue;
      }
      
      buffer += ch;
      
      if (ch == '{') {
        jsonStarted = true;
        braceCount++;
      } else if (ch == '}') {
        braceCount--;
        if (braceCount == 0 && jsonStarted) {
          break;
        }
      }
    } else {
      delay(10);
    }
  }
  
  return buffer;
}

void loop() {
  if (!client.connected()) {
    Serial.println("TCP reconnecting...");
    delay(1000);
    connectTcp();
    delay(1000);
    return;
  }

  if (!client.available()) {
    delay(100);
    return;
  }

  String jsonData = readCompleteJson(client);
  if (jsonData.length() == 0) return;
  
  Serial.println("\n=== RECEIVED MESSAGE ===");
  Serial.println("JSON: " + jsonData);
  
  StaticJsonDocument<2048> doc;
  DeserializationError err = deserializeJson(doc, jsonData);
  
  if (err) {
    Serial.printf("JSON error: %s\n", err.c_str());
    return;
  }
  
  if (!doc.containsKey("iv") || !doc.containsKey("ciphertext") || !doc.containsKey("tag")) {
    Serial.println("Missing JSON fields");
    return;
  }
  
  const char *iv_b64 = doc["iv"];
  const char *ct_b64 = doc["ciphertext"];
  const char *tag_b64 = doc["tag"];
  
  Serial.println("=== BASE64 VALUES ===");
  Serial.printf("IV: %s\n", iv_b64);
  Serial.printf("Ciphertext: %s\n", ct_b64);
  Serial.printf("Tag: %s\n", tag_b64);

  uint8_t iv[16];
  uint8_t ct[1024];
  uint8_t tag[16];
  
  int iv_len = b64decode(iv_b64, iv, sizeof(iv));
  int ct_len = b64decode(ct_b64, ct, sizeof(ct));
  int tag_len = b64decode(tag_b64, tag, sizeof(tag));
  
  if (iv_len <= 0 || ct_len <= 0 || tag_len <= 0) {
    Serial.printf("Base64 decode failed: iv=%d, ct=%d, tag=%d\n", iv_len, ct_len, tag_len);
    return;
  }
  
  Serial.println("=== DECODED BYTES ===");
  Serial.printf("IV (%d): ", iv_len);
  for (int i = 0; i < iv_len; i++) Serial.printf("%02X ", iv[i]);
  Serial.println();
  
  Serial.printf("Ciphertext (%d): ", ct_len);
  for (int i = 0; i < ct_len; i++) Serial.printf("%02X ", ct[i]);
  Serial.println();
  
  Serial.printf("Tag (%d): ", tag_len);
  for (int i = 0; i < tag_len; i++) Serial.printf("%02X ", tag[i]);
  Serial.println();

  Serial.println("=== DECRYPTION PROCESS ===");
  Serial.println("🔐 Starting AES-GCM decryption...");
  sendToWebServer("🔐 Starting AES-GCM decryption...", "info");
  
  Serial.println("⚙️  Setting up cipher context...");
  sendToWebServer("⚙️ Setting up cipher context...", "info");
  
  uint8_t plain[1024];
  bool ok = aes_gcm_decrypt(key, iv, (size_t)iv_len, ct, (size_t)ct_len, tag, (size_t)tag_len,
                            nullptr, 0, plain);
  
  if (!ok) {
    Serial.println("❌ DECRYPTION FAILED");
    Serial.println("🚫 Authentication tag verification failed");
    sendToWebServer("❌ DECRYPTION FAILED", "error");
    sendToWebServer("🚫 Authentication tag verification failed", "error");
    return;
  }
  
  Serial.println("✅ Authentication tag verified successfully");
  sendToWebServer("✅ Authentication tag verified successfully", "info");
  
  Serial.println("🔓 Decryption completed successfully");
  sendToWebServer("🔓 Decryption completed successfully", "info");
  
  Serial.print("📝 Extracting plaintext message: ");
  
  String msg;
  for (int i = 0; i < ct_len; ++i) {
    msg += (char)plain[i];
  }
  
  Serial.println("'" + msg + "'");
  sendToWebServer("📝 Extracted message: '" + msg + "'", "info");
  
  Serial.println("🎉 Message decryption process complete!");
  sendToWebServer("🎉 Message decryption process complete!", "info");
  Serial.println("========================");
  
  sendToWebServer("✅ Successfully decrypted: " + msg, "decrypted");
}