import customtkinter as ctk
import threading
import sys
import csv
import os
from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter
from datetime import datetime

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("PacketScope Pro 2025 (CSV Edition)")
        self.geometry("700x550")
        self.resizable(False, False)

        # 1. Header
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        
        self.label_title = ctk.CTkLabel(self.header_frame, text="PacketScope Pro - CSV Exporter", font=("Roboto", 20, "bold"))
        self.label_title.pack(pady=10)

        # 2. File Selection
        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(fill="x", padx=10, pady=5)

        self.entry_file = ctk.CTkEntry(self.file_frame, placeholder_text="Select a .pcap file...", width=450)
        self.entry_file.pack(side="left", padx=10, pady=10)

        self.btn_browse = ctk.CTkButton(self.file_frame, text="Browse File", command=self.browse_file)
        self.btn_browse.pack(side="right", padx=10, pady=10)

        # 3. Action Button
        self.btn_analyze = ctk.CTkButton(self, text="ANALYZE & EXPORT TO CSV", fg_color="#2CC985", hover_color="#229C68", text_color="black", width=680, command=self.start_thread)
        self.btn_analyze.pack(pady=5)

        # 4. Logs
        self.textbox = ctk.CTkTextbox(self, width=680, height=300)
        self.textbox.pack(pady=10)
        self.textbox.insert("0.0", "Ready. Reports will be saved to the same folder as this app.\n")
        self.textbox.configure(state="disabled")

    def log(self, message):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", message + "\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def browse_file(self):
        file_path = ctk.filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, file_path)
            self.log(f"Selected: {os.path.basename(file_path)}")

    def start_thread(self):
        target = self.entry_file.get()
        if not target:
            self.log("Error: Please select a file first.")
            return
        
        self.btn_analyze.configure(state="disabled", text="PROCESSING...")
        threading.Thread(target=self.run_analysis, args=(target,), daemon=True).start()

    def run_analysis(self, target_file):
        self.log(f"\n--- Starting Analysis ---")
        try:
            packets = rdpcap(target_file)
            self.log(f"Loaded {len(packets)} packets.")
            
            # --- Feature Extraction ---
            data_rows = []
            ip_counter = Counter()
            
            for i, pkt in enumerate(packets):
                # We extract specific details for the CSV
                row = {
                    "Packet No": i + 1,
                    "Time": float(pkt.time),
                    "Length": len(pkt),
                    "Protocol": "Other",
                    "Source IP": "",
                    "Dest IP": ""
                }

                if IP in pkt:
                    row["Source IP"] = pkt[IP].src
                    row["Dest IP"] = pkt[IP].dst
                    row["Protocol"] = "IP"
                    ip_counter[pkt[IP].src] += 1
                
                if TCP in pkt:
                    row["Protocol"] = "TCP"
                elif UDP in pkt:
                    row["Protocol"] = "UDP"

                data_rows.append(row)

            # --- Save to CSV ---
            # Create a filename based on the current time
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"report_{timestamp}.csv"
            
            # Write the file
            with open(csv_filename, mode='w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=["Packet No", "Time", "Length", "Protocol", "Source IP", "Dest IP"])
                writer.writeheader()
                writer.writerows(data_rows)
            
            # --- Summary Report on Screen ---
            self.log(f"\n[SUCCESS] Data saved to: {csv_filename}")
            self.log("You can open this file in Excel.")
            
            top_ips = ip_counter.most_common(5)
            self.log("\nQuick Summary (Top Source IPs):")
            for ip, count in top_ips:
                self.log(f"  - {ip}: {count}")

        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}")
        
        self.log("\nReady for next file.")
        self.btn_analyze.configure(state="normal", text="ANALYZE & EXPORT TO CSV")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
