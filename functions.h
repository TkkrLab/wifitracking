// This-->tab == "functions.h"

// Expose Espressif SDK functionality
extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int  wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int  wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}



#include <ESP8266WiFi.h>
#include "./structures.h"

#define MAX_APS_TRACKED 100
#define MAX_CLIENTS_TRACKED 200

#define PKTLEN 48
#define PKTBUFFLEN PKTLEN*50

/*char pktBuff[PKTBUFFLEN] = "";
int pktBuffPos = 0;*/

void print_beacon(beaconinfo beacon)
{
  if (beacon.err != 0) {
    //Serial.printf("BEACON ERR: (%d)  ", beacon.err);
  } else {
    Serial.print("BC ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", beacon.bssid[i]);
    Serial.printf(" [%32s] ", beacon.ssid);
    Serial.printf(" %2d", beacon.channel);
    Serial.printf(" %4d", beacon.rssi);
    Serial.println();
  }
}

void print_client(clientinfo ci)
{
  int u = 0;
  int known = 0;   // Clear known flag
  if (ci.err != 0) {
    // nothing
  } else {
    Serial.printf("DI ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.station[i]);
    Serial.print(" ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.bssid[i]);
    Serial.print(" ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.ap[i]);
    Serial.printf(" %4d\r\n", ci.rssi);
/*
    if (pktBuffPos >= PKTBUFFLEN - 48) {
      Serial.println("overflow");
      //Serial.println(pktBuff);
      //pktBuffPos = 0;
      return;
    }
    
    pktBuffPos += sprintf(pktBuff+pktBuffPos, "DI ");
    for (int i = 0; i < 6; i++) pktBuffPos += sprintf(pktBuff+pktBuffPos, "%02x", ci.station[i]);
    pktBuffPos += sprintf(pktBuff+pktBuffPos, " ");
    for (int i = 0; i < 6; i++) pktBuffPos += sprintf(pktBuff+pktBuffPos, "%02x", ci.bssid[i]);
    pktBuffPos += sprintf(pktBuff+pktBuffPos, " ");
    for (int i = 0; i < 6; i++) pktBuffPos += sprintf(pktBuff+pktBuffPos, "%02x", ci.ap[i]);
    pktBuffPos += sprintf(pktBuff+pktBuffPos, " %4d\r\n", ci.rssi);
    //Serial.print(pktBuff);
    //Serial.println("Position: "+String(pktBuffPos));
    */
  }
}

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
