import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, wrpcap

class PacketSniffer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Packet Sniffer")
        self.root.attributes('-fullscreen', True)
        self.dark_mode = True 
        
        self.packet_display_frame = tk.Frame(self.root, bg="#333333")
        self.packet_display_frame.pack(fill=tk.BOTH, expand=True)
        
        self.packet_tree = ttk.Treeview(self.packet_display_frame, columns=("No.", "Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Length", "Flags", "Payload"), show="headings", selectmode="browse", style="Custom.Treeview")
        self.packet_tree.heading("#1", text="No.")
        self.packet_tree.heading("#2", text="Timestamp")
        self.packet_tree.heading("#3", text="Source IP")
        self.packet_tree.heading("#4", text="Source Port")
        self.packet_tree.heading("#5", text="Destination IP")
        self.packet_tree.heading("#6", text="Destination Port")
        self.packet_tree.heading("#7", text="Protocol")
        self.packet_tree.heading("#8", text="Length")
        self.packet_tree.heading("#9", text="Flags")
        self.packet_tree.heading("#10", text="Payload Data")
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
        
        self.packet_tree.bind("<Double-1>", self.show_selected_packet)
        
     
        self.xscrollbar = ttk.Scrollbar(self.packet_display_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_tree.configure(xscrollcommand=self.xscrollbar.set)
        
        buttons_frame = tk.Frame(self.root, bg="#333333")
        buttons_frame.pack()
        
        self.start_button = tk.Button(buttons_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        self.stop_button = tk.Button(buttons_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, bg="#f44336", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        self.save_button = tk.Button(buttons_frame, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=10)

        self.clear_button = tk.Button(buttons_frame, text="Clear Packets", command=self.clear_packets, state=tk.DISABLED)
        self.clear_button.pack(side=tk.LEFT, padx=10)

        self.packet_count_label = tk.Label(buttons_frame, text="Packet Count: 0", bg="#333333", fg="white")
        self.packet_count_label.pack(side=tk.RIGHT, padx=10)

        ip_filter_label = tk.Label(buttons_frame, text="Filter by IP Address:", bg="#333333", fg="white")
        ip_filter_label.pack(pady=10, side=tk.LEFT)

        self.ip_filter_entry = tk.Entry(buttons_frame)
        self.ip_filter_entry.pack(pady=10, side=tk.LEFT)

       
        self.highlight_flag = False
        self.highlight_button = tk.Button(buttons_frame, text="Highlight Packets", command=self.toggle_highlight, bg="#2196F3", fg="white")
        self.highlight_button.pack(side=tk.LEFT, padx=10)

        self.root.bind("<Escape>", self.quit_application)
        
        self.root.style = ttk.Style()
        self.root.style.theme_use("default")
        self.root.style.configure("Custom.Treeview", background="#E0E0E0")

        
        protocol_label = tk.Label(buttons_frame, text="Filter Protocol:", bg="#333333", fg="white")
        protocol_label.pack(pady=10, side=tk.LEFT)

        self.selected_protocol = tk.StringVar()
        self.selected_protocol.set("All")

        self.protocol_combobox = ttk.Combobox(buttons_frame, textvariable=self.selected_protocol, values=["All", "TCP", "UDP"])
        self.protocol_combobox.pack(pady=10, side=tk.LEFT)

       
        self.filter_entry = tk.Entry(buttons_frame, state="readonly", disabledforeground="black")
        self.filter_entry.pack(pady=10, side=tk.LEFT)

        
        self.file_path = ""

        self.packet_count = 0

    def packet_handler(self, packet):
        try:
            self.packet_count += 1
            self.packet_count_label.config(text=f"Packet Count: {self.packet_count}")

            if self.selected_protocol.get() == "All" or (self.selected_protocol.get() == "TCP" and TCP in packet) or (self.selected_protocol.get() == "UDP" and UDP in packet):
                timestamp = str(packet.time)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst 
                
                protocol = packet.sprintf("%IP.proto%")
                length = len(packet)
                flags = packet.sprintf("%TCP.flags%") if TCP in packet else "N/A"
                payload = self.extract_payload(packet)

               
                syn_ack_flags = {'S': 'SYN', 'A': 'ACK', 'SA': 'SYN+ACK'}
                packet_flags = [syn_ack_flags[flag] for flag in syn_ack_flags.keys() if flag in flags]

                self.packet_tree.insert("", "end", values=(
                    len(self.packet_tree.get_children()) + 1, timestamp, src_ip, packet.sport, dst_ip, packet.dport,
                    protocol, length, flags, payload))

              
                if any(flag in syn_ack_flags.keys() for flag in flags.split(',')):
                    self.packet_tree.item(self.packet_count, tags=("highlight",))
        except Exception as e:
            print("Error handling packet:", e)

    def extract_payload(self, packet):
        payload = "N/A"
        if packet.haslayer(Raw):
            raw_layer = packet.getlayer(Raw)
            payload = raw_layer.load.hex()
        return payload

    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.sniffing = True
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_count = 0
        self.packet_count_label.config(text="Packet Count: 0")
        self.sniff_thread = threading.Thread(target=self.start_sniffing_thread)
        self.sniff_thread.start()

    def start_sniffing_thread(self):
        try:
            print("Starting packet sniffing...")
            sniff(prn=self.packet_handler, stop_filter=self.stop_filter)
            self.save_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)
            print("Packet sniffing stopped.")
        except Exception as e:
            print("Error sniffing packets:", e)

    def stop_filter(self, packet):
        return not self.sniffing

    def stop_sniffing(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.NORMAL)
        self.sniffing = False

    def quit_application(self, event):
        self.root.destroy()

    def show_selected_packet(self, event):
        item = self.packet_tree.selection()[0]
        packet_info = self.packet_tree.item(item, 'values')
        
        top = tk.Toplevel()
        top.title("Selected Packet Information")
        
        packet_text = "No.: {}\nTimestamp: {}\nSource IP: {}\nSource Port: {}\nDestination IP: {}\nDestination Port: {}\nProtocol: {}\nLength: {}\nFlags: {}\nPayload:\n{}".format(*packet_info)
        
        text_area = scrolledtext.ScrolledText(top, wrap=tk.WORD, width=80, height=20)
        text_area.insert(tk.INSERT, packet_text)
        text_area.pack(fill=tk.BOTH, expand=True)

    def save_packets(self):
        if not self.packet_tree.get_children():
            return

        self.file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if self.file_path:
            packets = [packet for packet in self.packet_tree.get_children()]
            captured_packets = []
            for packet_id in packets:
                packet_info = self.packet_tree.item(packet_id, 'values')
               
                ether_frame = Ether()
                ether_frame.type = 0x800  
                ether_frame.src = "00:00:00:00:00:00"  
                ether_frame.dst = "00:00:00:00:00:00"  

                
                ip_packet = IP(src=packet_info[2], dst=packet_info[4])
                ip_packet.tos = 0  
                ip_packet.id = 1  
                ip_packet.flags = 0  
                ip_packet.frag = 0  
                ip_packet.ttl = 64 
                
                if packet_info[6] == "TCP":
                    transport_packet = TCP(sport=int(packet_info[3]), dport=int(packet_info[5]))
                elif packet_info[6] == "UDP":
                    transport_packet = UDP(sport=int(packet_info[3]), dport=int(packet_info[5]))
                else:
                    continue

                
                payload_data = bytes.fromhex(packet_info[9]) if packet_info[9] != "N/A" else b""

                
                final_packet = ether_frame / ip_packet / transport_packet / payload_data
                captured_packets.append(final_packet)

            wrpcap(self.file_path, captured_packets)

    def clear_packets(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_count = 0
        self.packet_count_label.config(text="Packet Count: 0")

    def toggle_highlight(self):
        if self.highlight_flag:
            self.highlight_button.config(text="Highlight Packets", bg="#2196F3")
            self.highlight_flag = False
            self.clear_highlight()
        else:
            self.highlight_button.config(text="Stop Highlighting", bg="#f44336")
            self.highlight_flag = True
            self.highlight_packets()

    def highlight_packets(self):
        self.packet_tree.tag_configure("highlight", background="yellow")
        for item in self.packet_tree.get_children():
            packet_info = self.packet_tree.item(item, 'values')
            payload = packet_info[9]
            if payload != "N/A":
                self.packet_tree.item(item, tags=("highlight",))

    def clear_highlight(self):
        for item in self.packet_tree.get_children():
            self.packet_tree.item(item, tags=())

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.run()
