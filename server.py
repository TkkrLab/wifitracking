import socket

TCP_IP = '0.0.0.0'
TCP_PORT = 8090

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

macs = []

def parse(data):
	global macs
	n = 12
	newMacs = [data[i:i+n] for i in range(0, len(data), n)]
	for mac in newMacs:
		if not mac in macs:
			macs.append(mac)
			print(mac.decode("ascii"))

while 1:
	conn, addr = s.accept()
	#print('Connection address:', addr)
	data = b""
	i = 0
	try:
		while i < 20:
			data = data+conn.recv(4096)
			i+=1
	except e:
		print("except",e)
	parse(data)
	conn.close()
