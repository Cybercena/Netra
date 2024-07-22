from tkinter import *
from tkinter import Menu, messagebox ,ttk , filedialog
from scapy.all import ARP, Ether, srp
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import re
from datetime import datetime


# Create the main window
root = Tk()
root.title("Network Scanner")
root.geometry("600x600")

#function to get local IP and local mac 
def get_local_ip_and_mac():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    local_mac = "AA:BB:CC:DD:DD:FF"
    return local_ip, local_mac
#function to create and send ARP request
def arp_request(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply_arp, _ = srp(arp_request, timeout=3, verbose=False)
    if reply_arp:
        for _, received in reply_arp:
            return received.psrc, received.hwsrc
    return None
#function to scan the network with subnet
def scan_network(subnet):
    active_devices = []
    local_ip, local_mac = get_local_ip_and_mac()
    active_devices.append((local_ip, local_mac))

    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(arp_request, str(ip)): ip for ip in ipaddress.IPv4Network(subnet).hosts()}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    active_devices.append(result)
            except Exception as e:
                print(f"An error occurred: {e}")
    return active_devices

#createing a variable for subnet
subnet_var = StringVar()
#creating a function for new scan
def new_scan():
    hide_all_frames()
    new_scan_frame.pack(fill="both", expand=1)
    subnet_label = Label(new_scan_frame , text = "Entet the Subnet[192.168.18.0/24]")
    subnet_label.pack()
    subnet = Entry(new_scan_frame,width= 20 , textvariable=subnet_var).pack()
    submit_btn = Button(new_scan_frame,text = "Submit",width = 18 , command=validation_and_scan).pack()

#ip subnet formating  using regex
def validate_ip_subnet(ip_subnet):
    # Regular expression for validating an IP address with subnet mask
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){2}[0-9]{1,3}\.0/(?:[0-9]|[1-2][0-9]|3[0-2])$")

    return pattern.match(ip_subnet)

#validating ip scan
def validation_and_scan():
    subnet = subnet_var.get()
    if validate_ip_subnet(subnet):
        scan()
    elif subnet == "":
        messagebox.showerror("Error","No IP were entered !")
    else:
        messagebox.showerror("Error","The IP address and subnet format is incorrect.")   

#binding enter key for event triggering
root.bind('<Return>', lambda event: validation_and_scan())

#creating a actual scan funtion and printing the data

def scan():
    hide_all_frames()
    new_scan_frame.pack(fill="both", expand=1)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_device = Label(new_scan_frame, 
                          text=f"Active devices on : {current_time}", 
                          height=3,
                          font=('Helvetica', 14),  # Change font to 'Helvetica' with size 14
                          fg='blue')
    active_device.pack(fill='x')

    columns = ("IP Address", "MAC Address")
    table = ttk.Treeview(new_scan_frame, columns=columns, show="headings")
    for col in columns:
        table.heading(col, text=col)
        table.column(col, anchor="center")

    # Example data
    subnet = subnet_var.get()
    data = scan_network(subnet)


    # Insert data into the table
    for row in data:
        table.insert("", "end", values=row)

    table.pack(fill="both", expand=1)

    save_btn = Button(new_scan_frame , text = "Save" , command=lambda:save_scan_results(data))
    save_btn.pack()


#creating a function to save results
def save_scan_results(data_list):
    hide_all_frames()
    text_area = Text(save_scan_frame, wrap='word')
    text_area.pack(expand=True, fill='both')
    save_scan_frame.pack(fill = "both" , expand = 1)
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"),
                                                        ("All files", "*.*")])
    
    if file_path:
        try:
            with open(file_path, 'w') as file:
                for item in data_list:
                    file.write(f"{item}\n")
        except Exception as e:
            messagebox.showerror("Save File", f"Failed to save file: {e}")


#creating a open file options  


def open_scan_results():
    hide_all_frames()
    open_scan_frame.pack(fill = "both" , expand = 1)
    #createa a text area for notepads
    text_area = Text(open_scan_frame, wrap='word')
    text_area.pack(expand=True, fill='both')

    file_path = filedialog.askopenfilename(defaultextension=".txt",
                                           filetypes=[("Text files", "*.txt"),
                                                      ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                text_area.delete(1.0, END)
                text_area.insert(END, file.read())
        except Exception as e:
            messagebox.showerror("Open File", f"Failed to open file: {e}")


#creating a function to exit from the app 
def exit_app():
    root.quit()

# def quick_scan():
#     clear_screen()
#creating dummy funtions for menus
def intense_scan():
    messagebox.showinfo("Intense Scan", "Performing an intense scan...")

def ping_scan():
    messagebox.showinfo("Ping Scan", "Performing a ping scan...")

def port_scan():
    messagebox.showinfo("Port Scan", "Performing a port scan...")

def udp_scan():
    messagebox.showinfo("UDP Scan", "Performing a UDP scan...")

def syn_scan():
    messagebox.showinfo("SYN Scan", "Performing a SYN scan...")

def custom_scan():
    messagebox.showinfo("Custom Scan", "Configuring a custom scan...")

def stop_scan():
    messagebox.showinfo("Stop Scan", "Stopping the scan...")

def ip_lookup():
    messagebox.showinfo("IP Lookup", "Looking up IP address...")

def port_scanner():
    messagebox.showinfo("Port Scanner", "Scanning ports...")

def ping():
    messagebox.showinfo("Ping", "Pinging IP address...")

def traceroute():
    messagebox.showinfo("Traceroute", "Performing traceroute...")

def service_version_detection():
    messagebox.showinfo("Service Version Detection", "Detecting service versions...")

def os_detection():
    messagebox.showinfo("OS Detection", "Detecting OS...")

def vulnerability_scanning():
    messagebox.showinfo("Vulnerability Scanning", "Scanning for vulnerabilities...")

def network_inventory():
    messagebox.showinfo("Network Inventory", "Creating network inventory...")

def scripting_engine():
    messagebox.showinfo("Scripting Engine", "Using Nmap Scripting Engine (NSE)...")

def firewall_evasion():
    messagebox.showinfo("Firewall Evasion", "Applying firewall evasion techniques...")

def preferences():
    messagebox.showinfo("Preferences", "Opening preferences...")

def network_settings():
    messagebox.showinfo("Network Settings", "Configuring network settings...")

def update():
    messagebox.showinfo("Update", "Checking for updates...")
#fucntion for documentation button
def documentation():
    hide_all_frames()
    documentation_frame.pack(fill="both",expand=1)

    text_widget = Text(documentation_frame,wrap = WORD , height= 10 , width=50)
    text_widget.pack(fill = BOTH , expand = 1)

    #read the text from documentation file
    try:
        with open("documentation.txt","r") as file:
            documentation_text = file.read()
    except FileNotFoundError:
        messagebox.showerror("No Documentation")
    text_widget.insert(END,documentation_text)
    text_widget.config(state = DISABLED)
#function for the about function
def about():
    hide_all_frames()
    about_frame.pack(fill="both",expand=1)

    text_widget = Text(about_frame,wrap = WORD , height= 10 , width=50)
    text_widget.pack(fill = BOTH , expand = 1)

    #read the text from README.md file
    try:
        with open("README.md","r") as file:
            about_me = file.read()
    except FileNotFoundError:
        messagebox.showerror("No Documentation")
    text_widget.insert(END,about_me)
    text_widget.config(state = DISABLED)

def support():
    messagebox.showinfo("Support", "Contacting support...")




# Create a menu bar
menu_bar = Menu(root)
root.config(menu=menu_bar)

# File Menu
file_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="New Scan", command=new_scan)
file_menu.add_command(label="Open Scan Results", command=open_scan_results)
# file_menu.add_command(label="Save Scan Results", command=save_scan_results)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=exit_app)

# # Scan Menu
# scan_menu = Menu(menu_bar, tearoff=0)
# menu_bar.add_cascade(label="Scan", menu=scan_menu)
# scan_menu.add_command(label="Quick Scan", command=quick_scan)
# scan_menu.add_command(label="Intense Scan", command=intense_scan)
# scan_menu.add_command(label="Ping Scan", command=ping_scan)
# scan_menu.add_command(label="Port Scan", command=port_scan)
# scan_menu.add_command(label="UDP Scan", command=udp_scan)
# scan_menu.add_command(label="SYN Scan", command=syn_scan)
# scan_menu.add_command(label="Custom Scan", command=custom_scan)
# scan_menu.add_command(label="Stop Scan", command=stop_scan)

# # View Menu
# view_menu = Menu(menu_bar, tearoff=0)
# menu_bar.add_cascade(label="View", menu=view_menu)
# view_menu.add_command(label="Scan Results")
# view_menu.add_command(label="Network Map")
# view_menu.add_command(label="Logs")

# # Tools Menu
# tools_menu = Menu(menu_bar, tearoff=0)
# menu_bar.add_cascade(label="Tools", menu=tools_menu)
# tools_menu.add_command(label="IP Lookup", command=ip_lookup)
# tools_menu.add_command(label="Port Scanner", command=port_scanner)
# tools_menu.add_command(label="Ping", command=ping)
# tools_menu.add_command(label="Traceroute", command=traceroute)
# tools_menu.add_command(label="Service Version Detection", command=service_version_detection)
# tools_menu.add_command(label="OS Detection", command=os_detection)
# tools_menu.add_command(label="Vulnerability Scanning", command=vulnerability_scanning)
# tools_menu.add_command(label="Network Inventory", command=network_inventory)
# tools_menu.add_command(label="Scripting Engine", command=scripting_engine)
# tools_menu.add_command(label="Firewall Evasion", command=firewall_evasion)

# Settings Menu
settings_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
settings_menu.add_command(label="Preferences", command=preferences)
settings_menu.add_command(label="Network Settings", command=network_settings)
settings_menu.add_command(label="Update", command=update)

# Help Menu
help_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="Documentation", command=documentation)
help_menu.add_command(label="About", command=about)
help_menu.add_command(label="Support", command=support)

#creating some frames
#frame for new scan
new_scan_frame = Frame(root,width = 600 , height = 600 )
#frame for  open scan
open_scan_frame = Frame(root,width = 600 , height = 600 )
#frame for save scan result menu
save_scan_frame = Frame(root,width = 600 , height = 600 )
#frame for documentation
documentation_frame = Frame(root, width = 600 , height = 600)
#frame for about 
about_frame = Frame(root, width = 600 , height = 600 )

#creating a list of frames.
frame_list = [new_scan_frame,open_scan_frame,save_scan_frame,documentation_frame,about_frame]

# frame_list = [new_scan_frame,open_scan_frame]

#functions to hide other frames and deleting widgets
def hide_all_frames():

    for frame in frame_list:
        frame.pack_forget()
        for widget in frame.winfo_children():
            widget.destroy()
        
        # for widget in new_scan_frame.winfo_children():
        #     widget.destroy()
    
    # new_scan_frame.pack_forget()
    # open_scan_frame.pack_forget()
    # save_scan_frame.pack_forget()



#creating mainloop for window existing.
root.mainloop()

