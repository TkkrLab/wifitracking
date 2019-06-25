// by Ray Burnette 20161013 compiled on Linux 16.3 using Arduino 1.6.12

#include <ESP8266WiFi.h>
#include "./functions.h"

#define disable 0
#define enable  1
// uint8_t channel = 1;
unsigned int channel = 1;

void setup() {
  Serial.begin(115200);
  //Serial.println(F("Type:   /-------MAC------/-----WiFi Access Point SSID-----/  /----MAC---/  Chnl  RSSI"));

  wifi_set_opmode(STATION_MODE);            // Promiscuous works only with station mode
  wifi_set_channel(channel);
  wifi_promiscuous_enable(disable);
  wifi_set_promiscuous_rx_cb(promisc_cb);   // Set up promiscuous callback
  wifi_promiscuous_enable(enable);
  channel = 1;
}

void loop() {
  if (channel == 15) channel = 1;
  wifi_set_channel(channel);
  Serial.println("CN " + String(channel));
  for (int i = 0; i < 20; i++) {
    delay(100);
    if (pktBuffPos > PKTLEN*5) {
      Serial.println(pktBuff);
      pktBuffPos = 0;
    }
  }
  channel++;
}
