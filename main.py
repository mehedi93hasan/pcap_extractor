import customtkinter as ctk
import threading
import sys
from scapy.all import rdpcap, IP
from collections import Counter
import os

# --- Configuration ---
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("PacketScope Pro 2025")
        self.geometry("700x500")
        self.resizable(False, False)

        # 1. Header Section
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        
        self.label_title = ctk.CTkLabel(self.header_frame, text="PacketScope Pro", font=("Roboto", 20, "bold"))
        self.label_title.pack(pady=10)

        # 2. File Selection Section
        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(fill="x", padx=10, pady=5)

        self.entry_file = ctk.CTkEntry(self.file_frame, placeholder_text="Select a .pcap file...", width=450)
        self.entry_file.pack(side="left", padx=10, pady=10)

        self.btn_browse = ctk.CTkButton(self.file_frame, text="Browse File", command=self.browse_file)
        self.btn_browse.pack(side="right", padx=10, pady=10)

        # 3. Action Section
        self.btn_analyze = ctk.CTkButton(self, text="START ANALYSIS", fg_color="#E04F5F", hover_color="#B03E4E", width=680, command=self.start_thread)
        self.btn_analyze.pack(pady=5)

        # 4. Results Area (Log)
        self.textbox = ctk.CTkTextbox(self, width=680, height=300)
        self.textbox.pack(pady=10)
        self.textbox.insert("0.0", "Ready to analyze. Please select a file.\n")
        self.textbox.configure(state="disabled") # Read-only initially

    def log(self, message):
        """Adds text to the main window safely."""
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
        """Runs analysis in background so window doesn't freeze."""
        target = self.entry_file.get()
        if not target:
            self.log("Error: Please select a file first.")
            return
        
        self.btn_analyze.configure(state="disabled", text="PROCESSING...")
        threading.Thread(target=self.run_analysis, args=(target,), daemon=True).start()

    def run_analysis(self, target_file):
        self.log(f"\n--- Starting Analysis on {os.path.basename(target_file)} ---")
        try:
            packets = rdpcap(target_file)
            self.log(f"Loaded {len(packets)} packets successfully.")
            
            src_ips = []
            for pkt in packets:
                if IP in pkt:
                    src_ips.append(pkt[IP].src)
            
            # Results
            top_ips = Counter(src_ips).most_common(5)
            self.log("\n[REPORT GENERATED]")
            self.log(f"Total Packets: {len(packets)}")
            self.log("Top Source IPs:")
            for ip, count in top_ips:
                self.log(f"  - {ip}: {count} packets")
                
        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}")
        
        self.log("\nDone.")
        self.btn_analyze.configure(state="normal", text="START ANALYSIS")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
