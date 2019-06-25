import serial
ser = serial.Serial('/dev/ttyUSB0', 115200)

macs = []
aps = []
ssids = {}

while True:
  try:
    data = ser.readline().decode('ascii')
    type = data[0:2]
    if type == "BC":
      mac     = data[3:15]
      ssid    = data[17:49].lstrip()
      channel = int(data[52:54])
      rssi    = int(data[55:60])
      if not mac in aps:
        aps.append(mac)
      if len(ssid)>0:
        if not mac in ssids:
          ssids[mac] = ssid
    elif type == "DI":
      mac   = data[3:15]
      bssid = data[16:28]
      ap    = data[29:41]
      rssi  = int(data[42:46])
      #print(type+" "+mac+" "+bssid+" "+ap+" "+str(rssi))
      if not mac in macs:
        macs.append(mac)
        ssid = "???"
        if bssid in ssids:
          ssid = ssids[bssid]
        print(mac + " ["+ssid+"]")
  except Exception as e:
    #print(e)
    pass
