import tkinter as tk
from tkinter import messagebox, filedialog
import configparser
from datetime import datetime
from getpass import getpass
import hashlib, uuid
import os
import psycopg2
import socket

import textwrap
import jsonpickle
import re

from cls.typeclass import pkt,cmd
from cls.scktclass import sckt

#encryption libraries
from cls.enc.symencclass import symenc
from cls.enc.symencchaclass import symenccha
from cls.enc.helloclass import DHEHello

global SymEnc
classes=""
sct = None
usr = ""
HOST = ""
PORT = ""
ENC= ""
PUBKEY = ""
LOGFILE = ""


def login():
    usr = entry_username.get()
    passw = entry_password.get()
    Now=datetime.now().timestamp()
    errm=DHEHello.Client(sct,SymEnc,usr,passw,PUBKEY)	
    print("CHello processing time:" + str(datetime.now().timestamp()-Now) +" s\n")

    if errm!="": 
        messagebox.showerror("Error", errm.decode("utf-8"))
        root.quit()
        login_window.destroy()
        exit()

    status_bar.config(text=usr +":"+str(HOST) +":"+ str(PORT) +":"+str(ENC))
    cm=cmd("Cmd.ClassList",usr,{})
    p= pkt("1",HOST,"CMD",ENC, 1,cm) #DHSYM
    sct.sendall(sckt.Build(p,SymEnc))
    data = sckt.Parse(sct.recv(60000),SymEnc)
    if data.ptype!="ERROR":
    	classes=data.message
    	class_listbox.delete(0, tk.END)
    	for cls in classes:
    		class_listbox.insert(tk.END, cls)
    	print("Data:",classes)
    login_window.destroy()
    root.deiconify()
    root.mainloop()

def fetch_commands(class_name):
    cm=cmd(class_name+".CmdList",usr,{})
    p= pkt("1",HOST,"CMD",ENC, 1,cm) #DHSYM
    sct.sendall(sckt.Build(p,SymEnc))
    data = sckt.Parse(sct.recv(60000),SymEnc)
    data.message
    return data.message

def fetch_params(class_name, command):
    cm=cmd(class_name+"."+command +".ParamList",usr,{})
    p= pkt("1",HOST,"CMD",ENC, 1,cm) #DHSYM
    sct.sendall(sckt.Build(p,SymEnc))
    data = sckt.Parse(sct.recv(60000),SymEnc)
    data.message
    return data.message

#    return ["param1", "param2"]

global selected_class, CmdParam, selected_command
selected_class = None
selected_command = None
CmdParam = {}

def select_file(event, entry_widget):
    file_path = filedialog.askopenfilename(title="Выберите файл")
    file_path = os.path.normpath(file_path)
    if file_path:
    	entry_widget["FileName"].delete(0, tk.END)
    	entry_widget["FileName"].insert(0, file_path)
    	try:

    		with open(file_path, "r", encoding="utf-8") as file: #, encoding="utf-8" "rb"
    			CmdParam["FileData"] = file.read()
    		_, fname = os.path.split(file_path)
    		update_cmd_param("FileName", fname)
    		entry_widget["FileData"].delete(0, tk.END)
    		entry_widget["FileData"].insert(0, "Read " + str(len(CmdParam["FileData"]))+" bytes.")
    	except:
    		entry_widget["FileData"].delete(0, tk.END)
    		entry_widget["FileData"].insert(1, "Error opening file:" + file_path)

def on_class_selected(event):
    global selected_class
    try:
        selected_class = class_listbox.get(class_listbox.curselection())
        commands = fetch_commands(selected_class)
        command_listbox.delete(0, tk.END)
        for cmd in commands:
            command_listbox.insert(tk.END, cmd)
        param_frame.pack_propagate(False)
        for widget in param_frame.winfo_children():
            widget.destroy()
        response_text.delete("1.0", tk.END)
    except:
        pass

def on_command_selected(event):
    global CmdParam
    global selected_command
    if selected_class:
        try:
            selected_command = command_listbox.get(command_listbox.curselection())
            CmdParam = {"Command": selected_command}
            params = fetch_params(selected_class, selected_command)
            for widget in param_frame.winfo_children():
                widget.destroy()
            param_entries = {}
            for param in params:
                param_container = tk.Frame(param_frame)
                param_container.pack(fill=tk.X)
                tk.Label(param_container, text=param + ":").pack(side=tk.LEFT)
                entry = tk.Entry(param_container)
                entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)
                param_entries[param] = entry
                entry.bind("<KeyRelease>", lambda e, p=param: update_cmd_param(p, e.widget.get()))
                if param == "FileName":
                	entry.bind("<Button-1>", lambda e, w=param_entries: select_file(e, w))
        except:
            pass

def update_cmd_param(param, value):
    CmdParam[param] = value

def execute_command():
    response_text.delete("1.0", tk.END)
    CmdParam["Now"]=datetime.now().timestamp()
    response_text.insert(tk.END, f"Executing:{selected_class}.{selected_command}.{CmdParam}\n\n")

    cm=cmd(selected_class+"."+selected_command,usr,CmdParam)
    p= pkt("1",HOST,"CMD",ENC, 1,cm) #DHSYM
    sct.sendall(sckt.Build(p,SymEnc))
    data = sckt.Parse(sct.recv(60000),SymEnc)

    if data.ptype=="ERROR":
    	print("Got Error from server:", data.message.decode('utf-8'))	
    	response_text.insert(tk.END, "Got Error from server:" + data.message.decode('utf-8'))
    else:
    	print("Response ("+str(data.seq)+"):")
    	if str(data.message).count('\n')>0:
    		print(str(data.message))
    		response_text.insert(tk.END, data.message)
    	else:
    		print(textwrap.indent( textwrap.fill(str(data.message), width=80),  ' '*16))
    		response_text.insert(tk.END, textwrap.indent( textwrap.fill(str(data.message), width=50),''))


def on_closing():
    root.quit()
    login_window.destroy()
    exit()

#================================================MAIN====================================================
#config init
config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
config.read('./cfg/asgucli.cfg')

try:
	HOST = config.get('Connection','Host')  # The server's hostname or IP address
	PORT = config.getint('Connection','Port')   # The port used by the server
	ENC= config.get('Connection','Encryption')	
	PUBKEY = config.get('Other','PublicKey')
	LOGFILE = config.get('Other','LogFile')
except Exception as err:
	print("Configuration error:",err)
	exit()


# Создание окна логина
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("300x190")

tk.Label(login_window, text="\nServer:\n" + str(HOST) +" : "+ str(PORT)+" : "+str(ENC)).pack()
tk.Label(login_window, text="Username:").pack()
entry_username = tk.Entry(login_window)
entry_username.pack()

tk.Label(login_window, text="Password:").pack()
entry_password = tk.Entry(login_window, show="*")
entry_password.pack()
entry_password.bind("<Return>", lambda event: login())

tk.Button(login_window, text="Login", command=login).pack()
login_window.protocol("WM_DELETE_WINDOW", on_closing)



# Создание главного окна (изначально скрыто)
root = tk.Tk()
root.title("Command Selector")
root.geometry("600x450")
root.resizable(width=False, height=False)
root.minsize(width=600, height=450)
root.maxsize(width=600, height=450)
root.withdraw()

main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=False)
                      
# Левая часть (Classes & Commands)
left_frame = tk.Frame(main_frame, width=200)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

label_classes = tk.Label(left_frame, text="Classes:")
label_classes.pack()
class_listbox = tk.Listbox(left_frame)
class_listbox.pack()
#for cls in fetch_classes():
#    class_listbox.insert(tk.END, cls)
class_listbox.bind("<<ListboxSelect>>", on_class_selected)

label_commands = tk.Label(left_frame, text="Commands:")
label_commands.pack()
command_listbox = tk.Listbox(left_frame)
command_listbox.pack()
command_listbox.bind("<<ListboxSelect>>", on_command_selected)

# Правая часть (Parameters & Responses)
right_frame = tk.Frame(main_frame)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Верхняя половина (Parameters)

label_commands1 = tk.Label(right_frame, text="Parameters:")
label_commands1.pack()

param_frame = tk.LabelFrame(right_frame, height=185, width=300)
param_frame.pack(fill=tk.X)
param_frame.pack_propagate(False)

# Нижняя половина (Command Response)
response_frame = tk.Frame(right_frame, height=200)
response_frame.pack(fill=tk.BOTH, expand=True)

response_label = tk.Label(response_frame, text="Command Response:", font=("Arial", 10, "bold"))
response_label.pack()
response_text = tk.Text(response_frame, height=5)
response_text.pack(fill=tk.BOTH, expand=True)

execute_button = tk.Button(response_frame, text="Execute", command=execute_command)
execute_button.pack()

# Добавление статусной строки внизу основного окна
status_bar = tk.Label(root, text=f"Logged in as:", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)


#network & encryption init
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()

	print("\nInit SYM Encryption")
	if ENC =="SYMAES":
		SymEnc=symenc() #Symmetric encryption AES
	elif ENC =="SYMCHA":
		SymEnc=symenccha() #Symmetric encryption CHA
	else:
		print("		ERROR:Unsupported Encryption Type:",ENC)
		exit()

	print(" 	"+ENC+ " encryption enabled.")
	print("	Ready:",SymEnc.Ready())

# Запуск GUI
	login_window.mainloop()

