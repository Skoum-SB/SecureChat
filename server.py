import socket
import sys
import os
import _thread
import secrets

FORMAT = "utf-8"
BITS = 32

if len(sys.argv) != 2:
	print ("Correct usage :", sys.argv[0], "port")
	exit()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = int(sys.argv[1])
print(socket.gethostname())
server.bind(('', port))
server.listen()

clients = []

current_directory = os.getcwd()

path = os.path.join(current_directory, "usernames.txt")
if not os.path.isfile(path):
	FILE = open("usernames.txt", 'w')
	FILE.close()

path = os.path.join(current_directory, "userpswds.txt")
if not os.path.isfile(path):
	FILE = open("userpswds.txt", 'w')
	FILE.close()

def clientthread(socket, addr): 
	while True:
			try:
				message = socket.recv(4)
				if message:
					if  (message.decode(FORMAT) == "REG "):#REGister
						register(socket)

					elif(message.decode(FORMAT) == "LOG "):#LOGin
						login(socket)

					elif(message.decode(FORMAT) == "MSG "):#MeSsaGe
						broadcast(socket)

					elif(message.decode(FORMAT) == "DMS "):#DirectMeSsages
						transfer(socket)

					elif(message.decode(FORMAT) == "SK1 "):#SHaredKey#1
						initSK1(socket)

					elif(message.decode(FORMAT) == "SK2 "):#SHaredKey#2
						initSK2(socket)
				else:
					remove(socket)

			except:
				continue

def register(socket):
	msg = socket.recv(2044)

	username = msg.decode(FORMAT).split(' ')[0]
	password = msg.decode(FORMAT).split(' ')[1]

	#print("msg =", msg.decode(FORMAT))
	#print("username =", username)
	#print("password =", password)

	FILE_NAMES = open('usernames.txt', 'r+')
	FILE_PSWDS = open('userpswds.txt', 'a')

	#Check if username is available
	for l in FILE_NAMES:
		if (l.split('\n')[0] == username):
			#print("Username already used \n")
			msg = "ERR "
			socket.send(msg.encode(FORMAT))
			return
			
	FILE_NAMES.write(username + '\n')
	FILE_PSWDS.write(password + '\n')
	
	msg = "LOG "
	socket.send(msg.encode(FORMAT))

	return

def login(socket):  ##### FAIRE SI UTILISATEUR DEJA LOGGED IN
	msg = socket.recv(2044)

	username = msg.decode(FORMAT).split(' ')[0]
	password = msg.decode(FORMAT).split(' ')[1]

	FILE_NAMES = open('usernames.txt', 'r')
	FILE_PSWDS = open('userpswds.txt', 'r')

	for l in FILE_NAMES:
		if (l.split('\n')[0] == username):
			if(password == FILE_PSWDS.readline().split('\n')[0]):
				for client in clients:
					if client['username'] == username:
						msg = "ERR LOGG"
						socket.send(msg.encode(FORMAT))
						return

				msg = "LOG "
				for client in clients:
					if client['socket'] != socket:
						#Adding to the message the names of the other connected clients
						msg += client['username'] + " "
						#Sending to all other clients the name of the new client
						client['socket'].send(("CON " + username).encode(FORMAT))

				socket.send(msg.encode(FORMAT))
				
				for client in clients:
					if client['socket'] == socket:
						client['username'] = username
						break
			
			else:
				msg = "ERR PSWD"
				socket.send(msg.encode(FORMAT))

			return
		FILE_PSWDS.readline()

	FILE_NAMES.close()
	FILE_PSWDS.close()

	msg = "ERR UNKN"
	socket.send(msg.encode(FORMAT))


def broadcast(socket):
	rcv_msg = socket.recv(2044).decode(FORMAT)

	for client in clients:
		if client['socket'] == socket:
			send_name = client['username']
			break

	send_msg = "MSG " + send_name + ' ' + rcv_msg

	for client in clients:
		client['socket'].send(send_msg.encode(FORMAT))


def remove(socket):
	for client in clients:
		if client['socket'] == socket:
			clients.remove(client)

			msg = "DCN " + client['username']
			for client in clients:
				client['socket'].send(msg.encode(FORMAT))
			break

def transfer(socket):
	rcv_msg = socket.recv(2044)
	dest_name = rcv_msg[:16].decode(FORMAT).split(' ')[0]

	for client in clients:
		if client['socket'] == socket:
			send_name = client['username']
			break

	while len(send_name.encode(FORMAT)) < 16:
		send_name += ' '

	msg = b"DMS " + send_name.encode(FORMAT) + rcv_msg[16:]

	for client in clients:
		if client['username'] == dest_name:
			client['socket'].send(msg)
			break

def initSK1(socket):
	rcv_msg = socket.recv(2044).decode(FORMAT)

	username2 = rcv_msg.split(' ')[0]
	P = rcv_msg.split(' ')[1]
	G = rcv_msg.split(' ')[2]
	user1PublicKey = rcv_msg.split(' ')[3]

	for client in clients:
		if client['socket'] == socket:
			username1 = client['username']

		if client['username'] == username2:
			user2 = client['socket']

	#msg = str(P) + ' ' + str(G)
	#socket.send(msg.encode(FORMAT))

	msg = "SHK " + username1 + ' ' + P + ' ' + G + ' ' + user1PublicKey
	user2.send(msg.encode(FORMAT))

def initSK2(socket):
	rcv_msg = socket.recv(2044)
	
	username1 = rcv_msg[:16].decode(FORMAT).split(' ')[0]
	user2_DH_public = rcv_msg[16:48]
	user2PublicKey = rcv_msg[48:]

	for client in clients:
		if client['username'] == username1:
			user1 = client['socket']
	
	msg = user2_DH_public + user2PublicKey
	user1.send(msg)


while True:
	conn, addr = server.accept()

	clients.append({'socket' : conn, 'username' : ""})

	print (addr[0] + " connected")

	_thread.start_new_thread(clientthread,(conn,addr))