import socket
import select
import sys
import threading
import os

from Signal import *

from tkinter import *
from tkinter import messagebox

from functools import partial

class Graphical_User_Interface:

	def __init__(self):

		self.mainWindow = Tk()
		self.mainWindow.protocol("WM_DELETE_WINDOW", self.quit)
		self.mainWindow.withdraw()
		
		self.warningWindow = Toplevel()
		self.warningWindow.title("Warning")
		self.warningWindow.resizable(width = False, height = False)
		self.warningWindow.geometry('200x60')
		self.warningWindow.withdraw()

		self.connectionWindow = Toplevel()
		self.connectionWindow.title("Connection to the server")
		self.connectionWindow.resizable(width = False, height = False)
		self.connectionWindow.geometry('350x80')
		self.connectionWindow.protocol("WM_DELETE_WINDOW", self.log_quit)

		self.DMWindow = Toplevel()
		self.DMWindow.title("Private Message")
		self.DMWindow.resizable(width = False, height = False)
		self.DMWindow.geometry('500x550')
		self.DMWindow.withdraw()
		self.DMWindow.protocol("WM_DELETE_WINDOW", self.close_DM)

		self.DMHead = Label(self.DMWindow, bg = "#17202A",  fg = "#EAECEE", text = "test", font = "Helvetica 13 bold", pady = 10)
		self.DMHead.place(relwidth = 1)

		self.DMTop = Frame(self.DMWindow, width = 500, bg = "#17202A")
		self.DMTop.place(relheight = 0.825, relwidth = 1, rely = 0.08)

		self.DMCons = Text(self.DMTop, width = 20, height = 2, bg = "#17202A", fg = "#EAECEE", font = "Helvetica 14", padx = 5, pady = 5)
		self.DMCons.place(relheight = 1, relwidth = 1)
		self.DMCons.config(state = DISABLED)

		self.DMBottom = Label(self.DMWindow, bg = "#ABB2B9", height = 80)
		self.DMBottom.place(relwidth = 1, rely = 0.825)

		self.entryDM = Entry(self.DMBottom, bg = "#2C3E50", fg = "#EAECEE", font = "Helvetica 13")
		self.entryDM.place(relwidth = 0.74, relheight = 0.06, rely = 0.008, relx = 0.011)
		self.entryDM.focus()

		self.buttonDM = Button(self.DMBottom, text = "Send", font = "Helvetica 10 bold",  width = 20, bg = "#ABB2B9", command = self.send_DM)
		self.buttonDM.place(relx = 0.77, rely = 0.008, relheight = 0.06,  relwidth = 0.22)

		DMScrollbar = Scrollbar(self.DMCons)
		DMScrollbar.place(relheight = 0.9, relx = 0.974)
		DMScrollbar.config(command = self.DMCons.yview)

		self.server_addressLabel = Label(self.connectionWindow, text = "Server address : ").grid(row = 0, column = 0)
		self.server_address = StringVar()
		self.server_addressEntry = Entry(self.connectionWindow, textvariable = self.server_address)
		self.server_addressEntry.grid(row = 0, column = 1)

		self.portLabel = Label(self.connectionWindow,text = "Port : ").grid(row = 1, column = 0)
		self.port = StringVar()
		self.portEntry = Entry(self.connectionWindow, textvariable = self.port)
		self.portEntry.grid(row = 1, column = 1)

		connection = partial(self.connection, self.server_address, self.port)
		connectionButton = Button(self.connectionWindow, text = "Connection", command = connection).grid(row = 4, column = 0)

		self.mainWindow.mainloop()

	def log_quit(self):
		if messagebox.askokcancel("Quit", "Do you want to quit?"):
			self.mainWindow.destroy()
			sys.exit()

	def quit(self):
		if messagebox.askokcancel("Quit", "Do you want to quit?"):
			self.server.close()
			self.mainWindow.destroy()
			sys.exit()

	def close_DM(self):
		for button in self.buttonList:
			button['relief'] = RAISED
		self.DMWindow.withdraw()
			

	def connection(self, server_address, port):
		if server_address.get() == "":
			self.server_addressEntry['highlightcolor'] = "#FF0000"
			self.server_addressEntry.focus()
			return

		if port.get() == "":
			self.portEntry['highlightcolor'] = "#FF0000"
			self.portEntry.focus()
			return

		print("address entered :", server_address.get())
		print("port entered :", port.get())

		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.server_address = server_address.get()
		self.server_port = int(port.get())

		self.server.connect((self.server_address, self.server_port))

		self.login()

	def login(self):
		self.connectionWindow.destroy()

		self.loginWindow = Toplevel()
		self.loginWindow.title("Authentication")
		self.loginWindow.resizable(width = False, height = False)
		self.loginWindow.protocol("WM_DELETE_WINDOW", self.log_quit)
		
		self.nameLabel = Label(self.loginWindow, text = "Username : ").grid(row = 0, column = 0)
		name = StringVar()
		self.nameEntry = Entry(self.loginWindow, textvariable = name)
		self.nameEntry.grid(row = 0, column = 1)

		self.pswdLabel = Label(self.loginWindow, text="Password : ").grid(row=1, column=0)
		pswd = StringVar()
		self.pswdEntry = Entry(self.loginWindow, textvariable = pswd, show = '*')
		self.pswdEntry.grid(row = 1, column = 1)

		login = partial(self.send_log, name, pswd)
		self.loginButton = Button(self.loginWindow, text = "Login", command = login).grid(row = 2, column = 0)

		register = partial(self.register)
		self.registerButton = Button(self.loginWindow, text = "Register", command = register).grid(row = 2, column = 1)

		return

	def register(self):
		self.loginWindow.withdraw()

		self.registerWindow = Toplevel()
		self.registerWindow.title("Registration")
		self.registerWindow.resizable(width = False, height = False)
		self.registerWindow.protocol("WM_DELETE_WINDOW", self.log_quit)

		self.nameLabel = Label(self.registerWindow, text="Username : ").grid(row=0, column=0)
		name = StringVar()
		self.nameEntry = Entry(self.registerWindow, textvariable = name)
		self.nameEntry.grid(row=0, column=1)

		self.pswdLabel = Label(self.registerWindow, text="Password : ").grid(row=1, column=0)
		pswd = StringVar()
		self.pswdEntry = Entry(self.registerWindow, textvariable = pswd, show = '*')
		self.pswdEntry.grid(row=1, column=1)

		self.pswdConfirmLabel = Label(self.registerWindow, text="Confirm Password : ").grid(row=2, column=0)
		pswdConfirm = StringVar()
		self.pswdConfirmEntry = Entry(self.registerWindow, textvariable = pswdConfirm, show = '*')
		self.pswdConfirmEntry.grid(row=2, column=1)

		register = partial(self.send_reg, name, pswd, pswdConfirm)
		self.registerButton = Button(self.registerWindow, text = "Register", command = register).grid(row = 3, column = 1)
		
		return

	def send_log(self, name, pswd):
		if name.get() == "":
			self.nameEntry['highlightcolor'] = "#FF0000"
			self.nameEntry.focus()
			return

		if pswd.get() == "":
			self.pswdEntry['highlightcolor'] = "#FF0000"
			self.pswdEntry.focus()
			return

		msg = "LOG " + name.get() + ' ' + pswd.get()

		self.server.send(msg.encode(FORMAT))

		msg = self.server.recv(2048)

		if(msg.decode(FORMAT).split(' ')[0] == "ERR"):
			if(msg.decode(FORMAT).split(' ')[1] == "PSWD"):
				warningLabel = Label(self.warningWindow, text = "Wrong Password").grid(row = 0, column = 0)
				warningButton = Button(self.warningWindow, text = "OK", command = self.clear_pswd).grid(row = 1, column = 0)
				self.warningWindow.deiconify()
				return
			elif(msg.decode(FORMAT).split(' ')[1] == "UNKN"):
				warningLabel = Label(self.warningWindow, text = "Unknown Username").grid(row = 0, column = 0)
				warningButton = Button(self.warningWindow, text = "OK", command = self.clear_name).grid(row = 1, column = 0)
				self.warningWindow.deiconify()
				return
			elif(msg.decode(FORMAT).split(' ')[1] == "LOGG"):
				warningLabel = Label(self.warningWindow, text = "User already logged in").grid(row = 0, column = 0)
				warningButton = Button(self.warningWindow, text = "OK", command = self.clear_name).grid(row = 1, column = 0)
				self.warningWindow.deiconify()
				return

		if (msg.decode(FORMAT).split(' ')[0] == "LOG"):
			usernames = msg.decode(FORMAT).split(' ')
			usernames.pop(0)
			
			self.load_chat(name, usernames)
			self.user = User(name.get())
			return

	def send_reg(self, name, pswd, pswdConfirm):
		if name.get() == "":
			self.nameEntry['highlightcolor'] = "#FF0000"
			self.nameEntry.focus()
			return

		if pswd.get() == "":
			self.pswdEntry['highlightcolor'] = "#FF0000"
			self.pswdEntry.focus()
			return

		if pswdConfirm.get() == "":
			self.pswdConfirmEntry['highlightcolor'] = "#FF0000"
			self.pswdConfirmEntry.focus()
			return

		if(pswd.get() != pswdConfirm.get()):
			warningLabel = Label(self.warningWindow, text = "Passwords don't match").grid(row = 0, column = 0)
			warningButton = Button(self.warningWindow, text = "OK", command = self.clear_pswd).grid(row = 1, column = 0)
			self.warningWindow.deiconify()
			return

		msg = "REG " + name.get() + ' ' +  pswd.get()
		
		self.server.send(msg.encode(FORMAT))
		
		msg = self.server.recv(2048)

		if (msg.decode(FORMAT).split(' ')[0] == "ERR"):
			warningLabel = Label(self.warningWindow, text = "Username already used").grid(row = 0, column = 0)
			warningButton = Button(self.warningWindow, text = "OK", command = self.clear_name).grid(row = 1, column = 0)
			self.warningWindow.deiconify()
			return
		
		self.registerWindow.destroy()
		self.loginWindow.deiconify()
		
	def clear_pswd(self):
		self.warningWindow.withdraw()
		self.pswdEntry.delete(0, 'end')
		self.pswdConfirmEntry.delete(0, 'end')
		
	def clear_name(self):
		self.warningWindow.withdraw()
		self.nameEntry.delete(0, 'end')

	def load_chat(self, name, usernames):
		self.loginWindow.destroy()

		self.name = name.get()

		self.mainWindow.deiconify()
		self.mainWindow.title("SecureChat")
		self.mainWindow.resizable(width = False, height = False)
		self.mainWindow.configure(width = 800, height = 550, bg = "#17202A")
		
		self.labelHead = Label(self.mainWindow, bg = "#17202A",  fg = "#EAECEE", text = self.name , font = "Helvetica 13 bold", pady = 10)
		self.labelHead.place(relwidth = 1)

		line = Label(self.mainWindow, width = 450, bg = "#ABB2B9")
		line.place(relwidth = 1, rely = 0.07, relheight = 0.012)

		self.leftFrame = Frame(self.mainWindow, bg = "#ABB2B9")
		self.leftFrame.place(relheight = 0.75, relwidth = 0.25, rely = 0.08)

		self.rightFrame = Frame(self.mainWindow, bg = "#17202A")
		self.rightFrame.place(relheight = 0.75, relwidth = 0.75, relx = 0.25, rely = 0.08)

		self.userList = Canvas(self.leftFrame, width = 20, height = 2, bg = "#1b78e0")
		self.userList.place(relheight = 1, relwidth = 0.91)

		userListScrollbar = Scrollbar(self.leftFrame)
		userListScrollbar.place(relheight = 0.98, relx = 0.92, rely = 0.005)
		userListScrollbar.config(command = self.userList.yview)

		self.userList.config(yscrollcommand = userListScrollbar.set)

		self.nbUsers = 0

		self.buttonList = []

		for username in usernames:
			if username != '':
				userButton = Button(self.userList, bg = "#FFFFFF", text = username.split(' ')[0], width = 20, relief = RAISED, command = lambda i = self.nbUsers : self.open_DM(i))
				userButton.pack(fill = X)
				self.nbUsers += 1
				self.buttonList.append(userButton)

		self.textCons = Text(self.rightFrame, width = 20, height = 2, bg = "#17202A", fg = "#EAECEE", font = "Helvetica 14", padx = 5, pady = 5)
		self.textCons.place(relheight = 1, relwidth = 1)
		self.textCons.config(state = DISABLED)

		self.labelBottom = Label(self.mainWindow, bg = "#ABB2B9", height = 80)
		self.labelBottom.place(relwidth = 1, rely = 0.825)

		self.entryMsg = Entry(self.labelBottom, bg = "#2C3E50", fg = "#EAECEE", font = "Helvetica 13")
		self.entryMsg.place(relwidth = 0.74, relheight = 0.06, rely = 0.008, relx = 0.011)
		self.entryMsg.focus()

		self.buttonMsg = Button(self.labelBottom, text = "Send", font = "Helvetica 10 bold",  width = 20, bg = "#ABB2B9", command = self.send_message)
		self.buttonMsg.place(relx = 0.77, rely = 0.008, relheight = 0.06,  relwidth = 0.22)

		chatScrollbar = Scrollbar(self.textCons)
		chatScrollbar.place(relheight = 1, relx = 0.974)
		chatScrollbar.config(command = self.textCons.yview)

		# the thread to receive messages
		rcv = threading.Thread(target=self.receive_message)
		rcv.daemon = True
		rcv.start()

	def send_message(self):
		msg = self.entryMsg.get()
		if msg == "":
			return

		self.textCons.config(state = DISABLED)
		self.entryMsg.delete(0, END)
		
		message = "MSG " + msg
		self.server.send(message.encode(FORMAT))

	def open_DM(self, userNb):
		path_DM = os.path.join(current_directory, "Message_history")
		if not os.path.isdir(path_DM):
			os.mkdir(path_DM)

		self.DMHead['text'] = self.buttonList[userNb]['text']

		for button in self.buttonList:
						if(button['text']) == self.buttonList[userNb]['text']:
							button['bg'] = "#FFFFFF"
							button['relief'] = SUNKEN
						else:
							button['relief'] = RAISED

		DM_FILE_NAME = self.name + '_' + self.buttonList[userNb]['text']
		path_DM = os.path.join(path_DM, DM_FILE_NAME)
		if not os.path.isfile(path_DM):
			DM_FILE = open("Message_history/" + DM_FILE_NAME, 'w')
		DM_FILE = open("Message_history/" + DM_FILE_NAME, 'r')

		self.DMCons.config(state = NORMAL)
		self.DMCons.delete("1.0","end")
		while True:
			line = DM_FILE.readline()
			if not line:
				break
			self.DMCons.insert(END, line + "\n")
		self.DMCons.config(state = DISABLED)
		self.DMCons.see(END)
		self.DMWindow.deiconify()

		self.user.open_conv(self.buttonList[userNb]['text'], self.server)

	def send_DM(self):
		otherName = self.DMHead['text']

		msg = self.entryDM.get()
		if msg == "":
			return

		self.entryDM.delete(0, END)

		self.DMCons.config(state = NORMAL)
		self.DMCons.insert(END, "You : " + msg + "\n\n")
		self.DMCons.config(state = DISABLED)
		self.DMCons.see(END)

		DM_FILE_NAME = self.name + '_' + otherName
		
		DM_FILE = open("Message_history/" + DM_FILE_NAME, 'a')
		DM_FILE.write("You : " + msg + '\n')

		header, cipher = self.user.RatchetEncrypt(otherName, msg.encode(FORMAT), b'TEST_AD')
		l = len(header)
		bytes_l = (l).to_bytes(1, 'big')
		while len(otherName.encode(FORMAT)) < 16:
			otherName += ' '
		encryptedMessage = b"DMS " + otherName.encode(FORMAT) + bytes_l + header + cipher
		self.server.send(encryptedMessage)
		return

	def receive_message(self):
		while True:
			try:
				message = self.server.recv(2048)
				print(message[:4])
				if(message[:4].decode(FORMAT).split(' ')[0] == "MSG"):
					self.textCons.config(state = NORMAL)
					self.textCons.insert(END, message.decode(FORMAT).split(' ')[1] + " : " + message.decode(FORMAT).split(' ', 2)[2] + "\n\n")
					self.textCons.config(state = DISABLED)
					self.textCons.see(END)

				elif(message[:4].decode(FORMAT).split(' ')[0] == "CON"):
					userButton = Button(self.userList, bg = "#FFFFFF", text = message.decode(FORMAT).split(' ')[1], width = 20, relief = RAISED, command = lambda i = self.nbUsers : self.open_DM(i))
					userButton.pack(fill = X)
					self.nbUsers += 1
					self.buttonList.append(userButton)

				elif(message[:4].decode(FORMAT).split(' ')[0] == "DMS"):
					path = os.path.join(current_directory, "Message_history")
					if not os.path.isdir(path):
						os.mkdir(path)

					print("Message recu !!! :", message)
					otherName = message[4:20].decode(FORMAT).split(' ')[0]
					
					DM_FILE_NAME = self.name + '_' + otherName
					DM_FILE = open("Message_history/" + DM_FILE_NAME, 'a')

					decyptedMessage = self.user.RatchetDecrypt(otherName, message[20:])

					DM_FILE.write(decyptedMessage.decode(FORMAT) + '\n')

					#TEST
					'''header, cipher = self.user.RatchetEncrypt(otherName, b'TEST_MSG_2', b'TEST_AD')
					l = len(header)
					bytes_l = (l).to_bytes(1, 'big')
					while len(otherName.encode(FORMAT)) < 16:
						otherName += ' '
					msg = b"DMS " + otherName.encode(FORMAT) + bytes_l + header + cipher
					self.server.send(msg)'''

					'''otherName = otherName.split(' ')[0]
					header, cipher = self.user.RatchetEncrypt(otherName, b'TEST_MSG_3', b'TEST_AD')
					l = len(header)
					bytes_l = (l).to_bytes(1, 'big')
					while len(otherName.encode(FORMAT)) < 16:
						otherName += ' '
					msg = b"DMS " + otherName.encode(FORMAT) + bytes_l + header + cipher
					self.server.send(msg)'''

					print(decyptedMessage.decode(FORMAT))
					for button in self.buttonList:
						if button['text'] == otherName:
							self.DMCons.config(state = NORMAL)
							self.DMCons.insert(END, decyptedMessage.decode(FORMAT) + "\n\n")
							self.DMCons.config(state = DISABLED)
							self.DMCons.see(END)
							if self.DMHead['text'] != otherName or self.DMWindow.state() == "withdrawn":
								button['bg'] = "#ff0000"

				elif(message[:4].decode(FORMAT).split(' ')[0] == "DCN"):
					userDeleted = False
					userNb = 0

					while userNb < len(self.buttonList):
						if self.buttonList[userNb]['text'] == message.decode(FORMAT).split(' ')[1]:
							self.buttonList[userNb].destroy()
							self.nbUsers -= 1
							self.buttonList.pop(userNb)
							userDeleted = True
							continue

						if userDeleted:
							self.buttonList[userNb].configure(command = lambda i = userNb : self.open_DM(i))

						userNb += 1

				elif(message[:4].decode(FORMAT).split(' ')[0] == "SHK"):
					self.user.create_SK(message.decode(FORMAT).split(' ')[1], message.decode(FORMAT).split(' ')[2], message.decode(FORMAT).split(' ')[3], message.decode(FORMAT).split(' ')[4], self.server)


			except:
				print("An error occured!")
				self.server.close()
				break

main = Graphical_User_Interface()
