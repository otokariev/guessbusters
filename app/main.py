from vidstream import *
import tkinter as tk
import socket
import threading


# My local IP address is: 192.168.1.127
local_ip_address = socket.gethostbyname(socket.gethostname())
print(local_ip_address)

# To get public IP address you can use requests
# public_ip_address = requests.get('https://api.ipify.org').text
# Or visit myip.is - site to get your public IP address

# My public IP(IPv4) address is: 89.151.32.214

# server = StreamingServer('192.168.1.127', 9999)


# GUI

window = tk.Tk()
window.title('TestVideoChat')
window.geometry('300x200')

label_target_ip = tk.Label(window, text='Targer IP: ')
label_target_ip.pack()

text_target_ip = tk.Text(window, height=1)
text_target_ip.pack()

btn_listen = tk.Button(window, text='Start listening', width=50)
btn_listen.pack(anchor=tk.CENTER, expand=True)

btn_camera = tk.Button(window, text='Start camera stream', width=50)
btn_camera.pack(anchor=tk.CENTER, expand=True)

btn_screen = tk.Button(window, text='Start screen sharing', width=50)
btn_screen.pack(anchor=tk.CENTER, expand=True)

btn_audio = tk.Button(window, text='Start audio stream', width=50)
btn_audio.pack(anchor=tk.CENTER, expand=True)

window.mainloop()
