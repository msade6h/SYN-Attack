import tkinter as tk
from tkinter import filedialog
import socket
import time
import threading
import nmap

class PortScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Port Scanner")

        self.label = tk.Label(master, text="Enter start and end ports:", font=("Arial", 12))
        self.label.pack()
        self.start_port_entry = tk.Entry(master)
        self.start_port_entry.pack()
        self.end_port_entry = tk.Entry(master)
        self.end_port_entry.pack()

        self.remote_scan_var = tk.IntVar()
        self.remote_scan_checkbox = tk.Checkbutton(master, text="Remote Scan", variable=self.remote_scan_var, command=self.toggle_remote_scan)
        self.remote_scan_checkbox.pack()

        self.local_scan_var = tk.IntVar()
        self.local_scan_checkbox = tk.Checkbutton(master, text="Local Scan", variable=self.local_scan_var)
        self.local_scan_checkbox.pack()

        self.nmap_var = tk.IntVar()
        self.nmap_checkbox = tk.Checkbutton(master, text="Nmap Scan", variable=self.nmap_var)
        self.nmap_checkbox.pack()

        self.spoofer_var = tk.IntVar()
        self.spoofer_checkbox = tk.Checkbutton(master, text="Spoofing", variable=self.spoofer_var, command=self.toggle_spoofer)
        self.spoofer_checkbox.pack()

        self.spoofer_ip_label = tk.Label(master, text="Enter spoofing IP address:", font=("Arial", 12))
        self.spoofer_ip_label.pack()
        self.spoofer_ip_entry = tk.Entry(master, state=tk.DISABLED)
        self.spoofer_ip_entry.pack()

        self.address_label = tk.Label(master, text="Enter website or IP address:", font=("Arial", 12))
        self.address_label.pack()
        self.address_entry = tk.Entry(master, state=tk.DISABLED)
        self.address_entry.pack()

        self.start_button = tk.Button(master, text="Start Scan", command=self.start_scan, font=("Arial", 12))
        self.start_button.pack()
        self.end_button = tk.Button(master, text="End Scan", command=self.end_scan, state=tk.DISABLED, font=("Arial", 12))
        self.end_button.pack()
        self.save_button = tk.Button(master, text="Save Output", command=self.save_output_dialog, state=tk.DISABLED, font=("Arial", 12))
        self.save_button.pack()

        self.output_text = tk.Text(master, font=("Arial", 14))
        self.output_text.pack()

        self.output_text.tag_config("green", foreground="green")
        self.output_text.tag_config("red", foreground="red")

        self.scan_thread = None
        self.scan_in_progress = False

    def toggle_remote_scan(self):
        if self.remote_scan_var.get() == 1:
            self.address_entry.config(state=tk.NORMAL)
        else:
            self.address_entry.config(state=tk.DISABLED)

    def toggle_spoofer(self):
        if self.spoofer_var.get() == 1:
            self.spoofer_ip_entry.config(state=tk.NORMAL)
        else:
            self.spoofer_ip_entry.config(state=tk.DISABLED)

    def start_scan(self):
        if not self.scan_in_progress:
            self.scan_in_progress = True
            self.start_button.config(state=tk.DISABLED)
            self.end_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.DISABLED)
            self.scan_thread = threading.Thread(target=self.scan_ports)
            self.scan_thread.start()

    def end_scan(self):
        if self.scan_in_progress:
            self.display_message("End Scan.", color="red")
            self.scan_in_progress = False
            self.start_button.config(state=tk.NORMAL)
            self.end_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)

    def scan_ports(self):
        self.output_text.delete(1.0, tk.END)
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())
        target = ""

        if self.remote_scan_var.get() == 1:
            target = self.address_entry.get()
        elif self.local_scan_var.get() == 1:
            target = "127.0.0.1"
        else:
            target = ""

        try:
            ip_address = socket.gethostbyname(target)
            self.display_message(f"IP address for {target}: {ip_address}", color="green")
            self.display_message("Scanning ports. Please wait...", color="green")
        except Exception as e:
            self.display_message(f"Error: {e}", color="red")
            return

        for port in range(start_port, end_port + 1):
            if not self.scan_in_progress:
                break
            self.scan_single_port(ip_address, port)

        if self.nmap_var.get() == 1:
            nmap_info = self.run_nmap_scan(target)
            if nmap_info:
                self.display_message("Nmap Scan Results:", color="purple")
                for key, value in nmap_info.items():
                    self.display_message(f"{key}: {value}", color="purple")

        if self.scan_in_progress:
            self.display_message("Scan completed", color="green")
            self.end_scan()

    def scan_single_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                self.display_message(f"Port {port} is open", color="red")
            sock.close()
        except Exception as e:
            self.display_message(f"Error scanning port {port}: {e}", color="red")

    def display_message(self, message, color="black"):
        self.output_text.insert(tk.END, message + "\n", color)
        self.master.update()
        time.sleep(0.1)

    def save_output_dialog(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.save_output(file_path)

    def save_output(self, file_path):
        output = self.output_text.get(1.0, tk.END)
        with open(file_path, "w") as file:
            file.write(output)

    def run_nmap_scan(self, target):
        try:
            nm = nmap.PortScanner()
            target_ip = socket.gethostbyname(target)
            nm.scan(hosts=target_ip, arguments='-O')
            nmap_info = nm[target_ip]
            return nmap_info
        except Exception as e:
            self.display_message(f"Nmap error: {e}", color="red")
            return None


root = tk.Tk()
my_gui = PortScannerGUI(root)
root.mainloop()

#Code By 3135 , MsTeam 