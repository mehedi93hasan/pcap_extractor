import customtkinter as ctk
import threading
import sys
import pandas as pd
import numpy as np
import os
from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict, Counter
from datetime import datetime

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("PacketScope Research Edition")
        self.geometry("750x650")
        self.resizable(False, False)

        # 1. Header
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        self.label_title = ctk.CTkLabel(self.header_frame, text="PhD Feature Extractor (UNSW-NB15 Compatible)", font=("Roboto", 18, "bold"))
        self.label_title.pack(pady=10)

        # 2. Input: PCAP File
        self.frame_pcap = ctk.CTkFrame(self)
        self.frame_pcap.pack(fill="x", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(self.frame_pcap, placeholder_text="Select PCAP file...", width=500)
        self.entry_pcap.pack(side="left", padx=10, pady=10)
        self.btn_pcap = ctk.CTkButton(self.frame_pcap, text="Browse PCAP", command=lambda: self.browse_file(self.entry_pcap, "pcap"))
        self.btn_pcap.pack(side="right", padx=10, pady=10)

        # 3. Input: Ground Truth CSV (Optional)
        self.frame_gt = ctk.CTkFrame(self)
        self.frame_gt.pack(fill="x", padx=10, pady=5)
        self.entry_gt = ctk.CTkEntry(self.frame_gt, placeholder_text="Select Ground Truth CSV (Optional)...", width=500)
        self.entry_gt.pack(side="left", padx=10, pady=10)
        self.btn_gt = ctk.CTkButton(self.frame_gt, text="Browse GT CSV", fg_color="#555", hover_color="#444", command=lambda: self.browse_file(self.entry_gt, "csv"))
        self.btn_gt.pack(side="right", padx=10, pady=10)

        # 4. Action Button
        self.btn_analyze = ctk.CTkButton(self, text="EXTRACT 30 FEATURES & SAVE", fg_color="#2CC985", hover_color="#229C68", text_color="black", width=730, height=40, command=self.start_thread)
        self.btn_analyze.pack(pady=10)

        # 5. Logs
        self.textbox = ctk.CTkTextbox(self, width=730, height=300)
        self.textbox.pack(pady=5)
        self.textbox.insert("0.0", "Ready. Please select a PCAP file.\n")
        self.textbox.configure(state="disabled")

    def log(self, message):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", message + "\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def browse_file(self, entry_widget, file_type):
        if file_type == "pcap":
            ftypes = [("PCAP Files", "*.pcap"), ("PCAPNG Files", "*.pcapng")]
        else:
            ftypes = [("CSV Files", "*.csv")]
            
        file_path = ctk.filedialog.askopenfilename(filetypes=ftypes)
        if file_path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, file_path)

    def start_thread(self):
        pcap = self.entry_pcap.get()
        gt = self.entry_gt.get()
        
        if not pcap:
            self.log("Error: PCAP file is required.")
            return
        
        self.btn_analyze.configure(state="disabled", text="PROCESSING (This may take a while)...")
        threading.Thread(target=self.run_analysis, args=(pcap, gt), daemon=True).start()

    # ==============================================================================
    # LOGIC INTEGRATION
    # ==============================================================================
    def calculate_flow_features(self, flow_packets, src_ip):
        """Calculates the 30 Lightweight Features."""
        fwd_times, bwd_times = [], []
        fwd_lens, bwd_lens = [], []
        ttls, wins = [], []
        flags = {'S': 0, 'F': 0, 'U': 0, 'R': 0}

        for ts, size, ip_src, ttl, win, tcp_flags in flow_packets:
            if ip_src == src_ip:
                fwd_times.append(ts)
                fwd_lens.append(size)
            else:
                bwd_times.append(ts)
                bwd_lens.append(size)

            if ttl: ttls.append(ttl)
            if win: wins.append(win)
            
            if tcp_flags:
                if 'S' in tcp_flags: flags['S'] += 1
                if 'F' in tcp_flags: flags['F'] += 1
                if 'U' in tcp_flags: flags['U'] += 1
                if 'R' in tcp_flags: flags['R'] += 1

        # --- Feature Calcs ---
        all_times = sorted(fwd_times + bwd_times)
        iat = np.diff(all_times) if len(all_times) > 1 else [0]
        duration = all_times[-1] - all_times[0] if len(all_times) > 0 else 0
        all_lens = fwd_lens + bwd_lens
        safe_dur = duration if duration > 0 else 0.00001

        feats = {
            'iat_mean': np.mean(iat) if len(iat) > 0 else 0,
            'iat_std': np.std(iat) if len(iat) > 0 else 0,
            'iat_min': np.min(iat) if len(iat) > 0 else 0,
            'iat_max': np.max(iat) if len(iat) > 0 else 0,
            'flow_duration': duration,
            'ttl_mean': np.mean(ttls) if ttls else 0,
            'ttl_std': np.std(ttls) if ttls else 0,
            'win_mean': np.mean(wins) if wins else 0,
            'win_std': np.std(wins) if wins else 0,
            'pkt_ratio': len(fwd_times) / (len(bwd_times) + 1),
            'byte_ratio': sum(fwd_lens) / (sum(bwd_lens) + 1),
            'pkt_len_mean': np.mean(all_lens) if all_lens else 0,
            'pkt_len_std': np.std(all_lens) if all_lens else 0,
            'syn_count': flags['S'],
            'fin_count': flags['F'],
            'urg_count': flags['U'],
            'flow_pps': len(all_times) / safe_dur,
            'flow_bps': sum(all_lens) / safe_dur
        }
        return feats

    def run_analysis(self, pcap_file, gt_file):
        # 1. Load Ground Truth if provided
        gt_lookup = {}
        if gt_file and os.path.exists(gt_file):
            self.log(f"Loading Ground Truth: {os.path.basename(gt_file)}...")
            try:
                cols = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Start time', 'Last time', 'Label', 'Attack category']
                df = pd.read_csv(gt_file, usecols=cols, encoding='latin-1')
                df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
                
                gt_lookup = defaultdict(list)
                for _, row in df.iterrows():
                    key = (row['source_ip'], row['source_port'], row['destination_ip'], row['destination_port'], str(row['protocol']).lower())
                    gt_lookup[key].append({
                        'start': row['start_time'],
                        'end': row['last_time'],
                        'label': row['label'],
                        'cat': row['attack_category']
                    })
                self.log(f"Matched {len(df)} records in GT.")
            except Exception as e:
                self.log(f"Warning: Could not load GT ({e}). Proceeding without labels.")

        # 2. Process PCAP
        self.log(f"Reading PCAP: {os.path.basename(pcap_file)}...")
        current_flows = defaultdict(list)
        proto_map = {6: 'tcp', 17: 'udp'}
        processed_count = 0

        try:
            for pkt in PcapReader(pcap_file):
                processed_count += 1
                if processed_count % 10000 == 0:
                    self.log(f"Processed {processed_count} packets...")

                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                    proto_name = proto_map.get(pkt[IP].proto, 'other')
                    ts = float(pkt.time)
                    size = len(pkt)
                    ttl = pkt[IP].ttl
                    
                    sport, dport, win, flags = 0, 0, 0, ''
                    if TCP in pkt:
                        sport, dport = pkt[TCP].sport, pkt[TCP].dport
                        win, flags = pkt[TCP].window, str(pkt[TCP].flags)
                    elif UDP in pkt:
                        sport, dport = pkt[UDP].sport, pkt[UDP].dport

                    flow_key = (src, sport, dst, dport, proto_name)
                    current_flows[flow_key].append((ts, size, src, ttl, win, flags))
        
        except Exception as e:
            self.log(f"Error reading PCAP: {e}")
            self.btn_analyze.configure(state="normal", text="EXTRACT & SAVE")
            return

        # 3. Aggregate & Save
        self.log(f"Aggregating {len(current_flows)} flows...")
        extracted_rows = []
        
        for key, packets in current_flows.items():
            src, sport, dst, dport, proto = key
            feats = self.calculate_flow_features(packets, src)
            
            # Labeling
            label, category = 0, "Normal"
            if key in gt_lookup:
                flow_start = packets[0][0]
                for gt_flow in gt_lookup[key]:
                    # 1.5 second tolerance window
                    if (flow_start >= gt_flow['start'] - 1.5) and (flow_start <= gt_flow['end'] + 1.5):
                        label = gt_flow['label']
                        category = gt_flow['cat']
                        break
            
            feats['src_ip'] = src
            feats['dst_ip'] = dst
            feats['proto'] = proto
            feats['label'] = label
            feats['attack_cat'] = category
            extracted_rows.append(feats)

        # Output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"Features_{timestamp}.csv"
        pd.DataFrame(extracted_rows).to_csv(output_file, index=False)
        
        self.log(f"\n[SUCCESS] Saved {len(extracted_rows)} flows to:")
        self.log(output_file)
        self.btn_analyze.configure(state="normal", text="EXTRACT 30 FEATURES & SAVE")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
