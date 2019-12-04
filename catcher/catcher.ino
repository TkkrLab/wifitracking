/* 
 *  ESP8266 firmware for ShittyTraffic PoC
 *  An ESP8266 based Wifi catcher
 *  By Renze Nicolai and Florian Overkamp
 */
 
//
// Configuration settings
//
#include "config.h"

//
// Hash algorithms from ESP8266-SHA-256, see https://github.com/CSSHL/ESP8266-Arduino-cryptolibs
//
#include <sha256.h>

//
// No user serviceable parts below
//

// Libraries
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include "SimpleMap.h"       // https://github.com/spacehuhn/SimpleMap
#include <WiFiManager.h>
#include <ESP8266httpUpdate.h>

// Global vars
WiFiManager wifiManager;
WiFiClientSecure wificlient;
char nodename[80] = "UNDEF";
String nodeversion;
unsigned int channel = 1;

// Max number of hashes to wait for before we start to send out
#define HASHCOUNT 32
// Create a SimpleMap for the SHA256 hashes
SimpleMap<String, String> *hashmap = new SimpleMap<String, String>([](String &a, String &b) -> int {
  if (a == b) return 0;      // a and b are equal
  else if (a > b) return 1;  // a is bigger than b
  else return -1;            // a is smaller than b
});

extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int  wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int  wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}

#define ETH_MAC_LEN 6

uint8_t broadcast1[3] = { 0x01, 0x00, 0x5e };
uint8_t broadcast2[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t broadcast3[3] = { 0x33, 0x33, 0x00 };

struct beaconinfo
{
  uint8_t bssid[ETH_MAC_LEN];
  uint8_t ssid[33];
  int ssid_len;
  int channel;
  int err;
  signed rssi;
  uint8_t capa[2];
};

struct clientinfo
{
  uint8_t bssid[ETH_MAC_LEN];
  uint8_t station[ETH_MAC_LEN];
  uint8_t ap[ETH_MAC_LEN];
  int channel;
  int err;
  signed rssi;
  uint16_t seq_n;
};

struct RxControl {
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
};

struct LenSeq {
  uint16_t length;
  uint16_t seq;
  uint8_t  address3[6];
};

struct sniffer_buf {
  struct RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  struct LenSeq lenseq[1];
};

struct sniffer_buf2 {
  struct RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};

//
// Called from the promiscuous callback/print routine when a client packet is received
//
void save_mac(char* mac) {

  if(hashmap->has(mac)) {
    //Serial.print(".");
  } else {
    Serial.print("MAC ");
    Serial.print(mac);

    BYTE hash[SHA256_BLOCK_SIZE];
    char texthash[2*SHA256_BLOCK_SIZE+1];
    Sha256* sha256Instance=new Sha256();
  
    BYTE text[12];
    for (int i = 0; i < 12; i++) text[i] = mac[i];
    sha256Instance->update(text, 12);
    sha256Instance->final(hash);

    // Copy the hash in the packet buffer
    for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
      sprintf(texthash+2*i, "%02X", hash[i]);
    
    hashmap->put(mac, texthash);
    Serial.print(" is SHA256 hash ");
    Serial.print(texthash);
    Serial.print(" at map entry ");
    Serial.println(hashmap->size());  

    delete sha256Instance;     
  }
}

//
// Called from the promiscuous callback when a client packet is received
//
struct clientinfo parse_data(uint8_t *frame, uint16_t framelen, signed rssi, unsigned channel)
{
  struct clientinfo ci;
  ci.channel = channel;
  ci.err = 0;
  ci.rssi = rssi;
  int pos = 36;
  uint8_t *bssid;
  uint8_t *station;
  uint8_t *ap;
  uint8_t ds;

  ds = frame[1] & 3;    //Set first 6 bits to 0
  switch (ds) {
    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
    case 0:
      bssid = frame + 16;
      station = frame + 10;
      ap = frame + 4;
      break;
    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
    case 1:
      bssid = frame + 4;
      station = frame + 10;
      ap = frame + 16;
      break;
    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
    case 2:
      bssid = frame + 10;
      // hack - don't know why it works like this...
      if (memcmp(frame + 4, broadcast1, 3) || memcmp(frame + 4, broadcast2, 3) || memcmp(frame + 4, broadcast3, 3)) {
        station = frame + 16;
        ap = frame + 4;
      } else {
        station = frame + 4;
        ap = frame + 16;
      }
      break;
    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
    case 3:
      bssid = frame + 10;
      station = frame + 4;
      ap = frame + 4;
      break;
  }

  memcpy(ci.station, station, ETH_MAC_LEN);
  memcpy(ci.bssid, bssid, ETH_MAC_LEN);
  memcpy(ci.ap, ap, ETH_MAC_LEN);

  ci.seq_n = frame[23] * 0xFF + (frame[22] & 0xF0);
  return ci;
}

//
// Called from the promiscuous callback when a beacon (AP) packet is received
//
struct beaconinfo parse_beacon(uint8_t *frame, uint16_t framelen, signed rssi)
{
  struct beaconinfo bi;
  bi.ssid_len = 0;
  bi.channel = 0;
  bi.err = 0;
  bi.rssi = rssi;
  int pos = 36;

  if (frame[pos] == 0x00) {
    while (pos < framelen) {
      switch (frame[pos]) {
        case 0x00: //SSID
          bi.ssid_len = (int) frame[pos + 1];
          if (bi.ssid_len == 0) {
            memset(bi.ssid, '\x00', 33);
            break;
          }
          if (bi.ssid_len < 0) {
            bi.err = -1;
            break;
          }
          if (bi.ssid_len > 32) {
            bi.err = -2;
            break;
          }
          memset(bi.ssid, '\x00', 33);
          memcpy(bi.ssid, frame + pos + 2, bi.ssid_len);
          bi.err = 0;  // before was error??
          break;
        case 0x03: //Channel
          bi.channel = (int) frame[pos + 2];
          pos = -1;
          break;
        default:
          break;
      }
      if (pos < 0) break;
      pos += (int) frame[pos + 1] + 2;
    }
  } else {
    bi.err = -3;
  }

  bi.capa[0] = frame[34];
  bi.capa[1] = frame[35];
  memcpy(bi.bssid, frame + 10, ETH_MAC_LEN);
  return bi;
}

//
// Called from the promiscuous callback when a beacon (AP) packet is received and parsed
//
void print_beacon(beaconinfo beacon)
{
  /*if (beacon.err != 0) return;
  Serial.print("BC ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", beacon.bssid[i]);
  Serial.printf(" [%32s] ", beacon.ssid);
  Serial.printf(" %2d", beacon.channel);
  Serial.printf(" %4d", beacon.rssi);
  Serial.println();*/
}

//
// Called from the promiscuous callback when a client packet is received and parsed
//
void print_client(clientinfo ci)
{
  if (ci.err != 0) return;
  
  /* Serial.printf("DI ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.station[i]);
  Serial.print(" ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.bssid[i]);
  Serial.print(" ");
  for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.ap[i]);
  Serial.printf(" %4d\r\n", ci.rssi); */

  // Save the MAC
  //
  char clientmac[12] = "";
  sprintf(clientmac, "%02x%02x%02x%02x%02x%02x", ci.station[0], ci.station[1], ci.station[2], ci.station[3], ci.station[4], ci.station[5]);
  save_mac(clientmac);
}

//
// Callback when in promiscuous mode will analyse packets and act accordingly
//
void promisc_cb(uint8_t *buf, uint16_t len)
{
  int i = 0;
  uint16_t seq_n_new = 0;
  if (len == 12) {
    struct RxControl *sniffer = (struct RxControl*) buf;
  } else if (len == 128) {
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    struct beaconinfo beacon = parse_beacon(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
    print_beacon(beacon);
  } else {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    //Is data or QOS?
    if ((sniffer->buf[0] == 0x08) || (sniffer->buf[0] == 0x88)) {
      struct clientinfo ci = parse_data(sniffer->buf, 36, sniffer->rx_ctrl.rssi, sniffer->rx_ctrl.channel);
      if (memcmp(ci.bssid, ci.station, ETH_MAC_LEN)) {
        print_client(ci);
      }
    }
  }
}

//
// If the WifiManager configuration portal is called, we clean the cache
//
void configModeCallback (WiFiManager *myWiFiManager) {
  Serial.println("Entered config mode, clearing current hash buffer");
  hashmap->clear();
}

//
// Connect to AP as client, check fw updates, upload hashbuffer
//
void pushout() {
  wifi_promiscuous_enable(0);
  delay(100);
  bool enabled = WiFi.enableSTA(true);
  if (!enabled) {
    Serial.println("Enable failed!");
    return;
  }

  wifiManager.setConfigPortalTimeout(300); // If no configuration is done in 5 mins, exit/restart quietly
  
  if (wifiManager.autoConnect(nodename)) { // @@@FIXME@@@ we should really set a PSK for the AP (but in my brief testing it crashed the ESP, so what's up with that)
    Serial.println("AP connection up");

    //wificlient.setFingerprint(WTR_SHA1);
    wificlient.setInsecure();    // Do not check fingerprint

    wificlient.setTimeout(15000); // 15 Seconds

    // Only need to post hashes if there is data to push to the server
    if (hashmap->size() >= 1) {

      // 'Native' in WiFiClient because we need to push the entire clientbuffer in the API
      // As a result copying the buffer in to a new String for HTTPClient library use is highly inefficient
      if (!wificlient.connect(WTR_SERVER, WTR_SRVPORT)) {
        Serial.println("HTTPS connection failed");
      } else {
        Serial.println("HTTPS connection up");

        // Send checkin to the server:
        if (https.begin(wificlient, "https://" WTR_SERVER WTR_CHECKIN)) {
          https.addHeader("Accept", "*/*");
          https.addHeader("Content-Type", "application/json");
          
          String json = "{\"node\":\"";
          json.concat(nodename);
          json.concat("\",\"version\":\"" CATCHER_VERSION "\",");
          json.concat("\"millis\":" + String(millis()) + "}");

          int httpcode = https.POST(json);
          if(httpcode > 0) {
            Serial.printf("[HTTP] POST... code: %d\n", httpcode);
            if(httpcode == HTTP_CODE_OK) {
              String payload = https.getString();
              Serial.println(payload);
            }
          }

          https.end();
        } else {
          Serial.println("Checkin API connection failed");
        }

        // Send the hash data to the server        
        wificlient.println("POST " WTR_URI " HTTP/1.1");
        wificlient.println("Host: " WTR_SERVER);
        wificlient.println("Accept: */*");
        wificlient.println("Content-Type: application/json");
        wificlient.print("Content-Length: ");
        wificlient.println(40+(hashmap->size()*65)-1);    // 37 chars plus map size minus the last ',' char we will strip in a bit
        //wificlient.println("Connection: close");
        wificlient.println();
        // Construct the REST/JSON POST data
        wificlient.print("{\"node\":\"");
        wificlient.print(nodename);
        wificlient.print("\",\"clients\":\"");
        // Loop through hashbuffer @@@FIXME@@@
        for(int i=0; i<hashmap->size(); ++i) {
          wificlient.print(hashmap->getData(i));
          if(i < hashmap->size()-1) wificlient.print(",");
        }
        wificlient.println("\"}");
        Serial.println("POST sent");
      
        while (wificlient.connected()) {
          String line = wificlient.readStringUntil('\n');
          if (line == "\r") {
            Serial.println("Headers received");
            break;
          }
        }
        String line = wificlient.readStringUntil('\n');
        Serial.println("reply was:");
        Serial.println("==========");
        Serial.println(line);
        Serial.println("==========");
        Serial.println("closing connection");
        wificlient.stop();  // DISCONNECT FROM THE SERVER
      }
      delay(500);  // Not sure if needed @@@FIXME@@@
    }
    
    // Check for firmware upgrades
    Serial.println("Checking for firmware upgrade");
    t_httpUpdate_return ret = ESPhttpUpdate.update(wificlient, WTR_SERVER, WTR_SRVPORT, "/fw/", nodeversion);
    switch(ret) {
    case HTTP_UPDATE_FAILED: // HTTP 403, 404
        Serial.println("Firmware upgrade available, but update failed");
        break;
    case HTTP_UPDATE_NO_UPDATES: // HTTP 304
        Serial.println("No firmware upgrade available");
        break;
    case HTTP_UPDATE_OK: // HTTP 200
        Serial.println("Firmware upgrade available, upgraded ok."); // may not called we reboot the ESP
        break;
    }
    
  }

  // No sanity, assume buffer can be discarded here
  hashmap->clear();

  wifi_station_disconnect();
  wifi_promiscuous_enable(1);
  Serial.println("AP disconnected, back to listening");
}

//
// Main setup function
//
void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println();

  // Grab our own MAC as the basis for our node identifier
  byte mac[6];
  WiFi.macAddress(mac);
  // Copy them in to a readable char[];
  sprintf(nodename, "WTR");
  sprintf(nodename+3, "%02x", mac[0]);
  sprintf(nodename+5, "%02x", mac[1]);
  sprintf(nodename+7, "%02x", mac[2]);
  sprintf(nodename+9, "%02x", mac[3]);
  sprintf(nodename+11, "%02x", mac[4]);
  sprintf(nodename+13, "%02x", mac[5]);
  nodeversion = nodename;
  nodeversion.concat("-v" CATCHER_VERSION);
  Serial.print("Node ");
  Serial.print(nodeversion);
  Serial.println(" starting up.");

  // Enable WifiManager callback to clear the cache
  wifiManager.setAPCallback(configModeCallback);

  // Initial pushout call
  pushout();
  
  // Prepare to set promisc
  WiFi.persistent(false);
  wifi_set_opmode(STATION_MODE);            // Promiscuous works only with station mode
  wifi_set_channel(channel);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // Set up promiscuous callback
  wifi_promiscuous_enable(1);
}

//
// Main loop
//
void loop() {
  // First, check if buffer is full, if so, send it out
  if((hashmap->size() > HASHCOUNT) || (channel == 15)) pushout();

  // Iterate through Wifi channels (2.4Ghz only)
  if (channel == 15) { channel = 1; }
  Serial.println("Switching to channel "+String(channel)+", "+String(hashmap->size())+" entries in buffer.");  
  wifi_set_channel(channel);
  // Just wait for two seconds (we're in promiscuous mode, so traffic will be handled in callback)
  delay(2000);
  channel++;
}
