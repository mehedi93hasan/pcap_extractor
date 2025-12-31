import customtkinter as ctk
import threading
import sys
import pandas as pd
import numpy as np
import os
from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("PacketScope Research Edition - 30 Features")
        self.geometry("750x650")
        self.resizable(False, False)

        # 1. Header
        self.header_frame = ctk.CTkFrame(self, height=50, corner_radius=10)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        self.label_title = ctk.CTkLabel(self.header_frame, text="30 Lightweight Features", font=("Roboto", 18, "bold"))
        self.label_title.pack(pady=10)

        # 2. Input: PCAP File
        self.frame_pcap = ctk.CTkFrame(self)
        self.frame_pcap.pack(fill="x", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(self.frame_pcap, placeholder_text="Select PCAP file...", width=500)
        self.entry_pcap.pack(side="left", padx=10, pady=10)
        self.btn_pcap = ctk.CTkButton(self.frame_pcap, text="Browse PCAP", command=lambda: self.browse_file(self.entry_pcap, "pcap"))
        self.btn_pcap.pack(side="right", padx=10, pady=10)

        # 3. Input: Ground Truth CSV
        self.frame_gt = ctk.CTkFrame(self)
        self.frame_gt.pack(fill="x", padx=10, pady=5)
        self.entry_gt = ctk.CTkEntry(self.frame_gt, placeholder_text="Select Ground Truth CSV...", width=500)
        self.entry_gt.pack(side="left", padx=10, pady=10)
        self.btn_gt = ctk.CTkButton(self.frame_gt, text="Browse GT CSV", fg_color="#555", hover_color="#444", command=lambda: self.browse_file(self.entry_gt, "csv"))
        self.btn_gt.pack(side="right", padx=10, pady=10)

        # 4. Action Button
        self.btn_analyze = ctk.CTkButton(self, text="EXTRACT 30 FEATURES & GENERATE DATASET", fg_color="#2CC985", hover_color="#229C68", text_color="black", width=730, height=40, command=self.start_thread)
        self.btn_analyze.pack(pady=10)

        # 5. Logs
        self.textbox = ctk.CTkTextbox(self, width=730, height=300)
        self.textbox.pack(pady=5)
        self.textbox.insert("0.0", "Ready. Please select your PCAP and Ground Truth file.\n")
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
        
        if not pcap or not gt:
            self.log("Error: Both PCAP and Ground Truth files are required.")
            return
        
        self.btn_analyze.configure(state="disabled", text="PROCESSING...")
        threading.Thread(target=self.run_analysis, args=(pcap, gt), daemon=True).start()

    # --- Feature Calculation Engine (30 Features) ---
    def calculate_flow_features(self, flow_packets, src_ip):
        fwd_times, bwd_times = [], []
        fwd_lens, bwd_lens = [], []
        fwd_header_lens, bwd_header_lens = [], []
        ttls, wins = [], []
        flags = {'S': 0, 'F': 0, 'U': 0, 'R': 0}

        for ts, size, ip_src, ttl, win, tcp_flags, header_len in flow_packets:
            if ip_src == src_ip:
                fwd_times.append(ts)
                fwd_lens.append(size)
                fwd_header_lens.append(header_len)
            else:
                bwd_times.append(ts)
                bwd_lens.append(size)
                bwd_header_lens.append(header_len)
            
            if ttl: ttls.append(ttl)
            if win: wins.append(win)
            if tcp_flags:
                if 'S' in tcp_flags: flags['S'] += 1
                if 'F' in tcp_flags: flags['F'] += 1
                if 'U' in tcp_flags: flags['U'] += 1
                if 'R' in tcp_flags: flags['R'] += 1

        # === TIME CALCULATIONS ===
        all_times = sorted(fwd_times + bwd_times)
        iat = np.diff(all_times) if len(all_times) > 1 else [0]
        fwd_iat = np.diff(fwd_times) if len(fwd_times) > 1 else [0]
        
        duration = all_times[-1] - all_times[0] if len(all_times) > 1 else 0
        safe_dur = duration if duration > 0 else 0.00001
        
        # Active/Idle Time Detection (Basic Implementation)
        active_periods, idle_periods = [], []
        if len(all_times) > 1:
            for i in range(len(all_times) - 1):
                gap = all_times[i+1] - all_times[i]
                if gap > 1.0:  # 1 second threshold for "idle"
                    idle_periods.append(gap)
                else:
                    active_periods.append(gap)
        
        # === SIZE CALCULATIONS ===
        all_lens = fwd_lens + bwd_lens
        total_fwd_bytes = sum(fwd_lens)
        total_bwd_bytes = sum(bwd_lens)
        total_fwd_headers = sum(fwd_header_lens)
        total_bwd_headers = sum(bwd_header_lens)
        total_payload = (total_fwd_bytes + total_bwd_bytes) - (total_fwd_headers + total_bwd_headers)
        
        # Small/Large packet ratios
        small_pkts = sum(1 for l in all_lens if l < 64)
        large_pkts = sum(1 for l in all_lens if l > 1200)
        total_pkts = len(all_lens)
        
        # Coefficient of Variation
        pkt_len_mean_val = np.mean(all_lens) if all_lens else 0
        pkt_len_std_val = np.std(all_lens) if all_lens else 0
        pkt_len_var_coeff = pkt_len_std_val / pkt_len_mean_val if pkt_len_mean_val > 0 else 0
        
        # === SYMMETRY CALCULATIONS ===
        fwd_size_sum = sum(fwd_lens)
        bwd_size_sum = sum(bwd_lens)
        size_asymmetry = (fwd_size_sum - bwd_size_sum) / (fwd_size_sum + bwd_size_sum + 1)
        response_rate = len(bwd_times) / safe_dur
        
        # === VELOCITY CALCULATIONS ===
        fwd_bps = total_fwd_bytes / safe_dur
        bwd_pps = len(bwd_times) / safe_dur

        return {
            # Time Dynamics (8 features)
            'iat_mean': np.mean(iat) if len(iat) > 0 else 0,
            'iat_std': np.std(iat) if len(iat) > 0 else 0,
            'iat_min': np.min(iat) if len(iat) > 0 else 0,
            'iat_max': np.max(iat) if len(iat) > 0 else 0,
            'flow_duration': duration,
            'active_time_mean': np.mean(active_periods) if active_periods else 0,
            'idle_time_mean': np.mean(idle_periods) if idle_periods else 0,
            'fwd_iat_mean': np.mean(fwd_iat) if len(fwd_iat) > 0 else 0,
            
            # Header Invariants (8 features)
            'ttl_mean': np.mean(ttls) if ttls else 0,
            'ttl_std': np.std(ttls) if ttls else 0,
            'win_size_mean': np.mean(wins) if wins else 0,
            'win_size_std': np.std(wins) if wins else 0,
            'syn_count': flags['S'],
            'urg_count': flags['U'],
            'fin_ratio': flags['F'] / total_pkts if total_pkts > 0 else 0,
            'header_len_mean': np.mean(fwd_header_lens + bwd_header_lens) if (fwd_header_lens + bwd_header_lens) else 0,
            
            # Traffic Symmetry (4 features)
            'pkt_ratio': len(fwd_times) / (len(bwd_times) + 1),
            'byte_ratio': total_fwd_bytes / (total_bwd_bytes + 1),
            'size_asymmetry': size_asymmetry,
            'response_rate': response_rate,
            
            # Payload Dynamics (6 features)
            'pkt_len_mean': pkt_len_mean_val,
            'pkt_len_std': pkt_len_std_val,
            'pkt_len_var_coeff': pkt_len_var_coeff,
            'small_pkt_ratio': small_pkts / total_pkts if total_pkts > 0 else 0,
            'large_pkt_ratio': large_pkts / total_pkts if total_pkts > 0 else 0,
            'header_payload_ratio': (total_fwd_headers + total_bwd_headers) / (total_payload + 1),
            
            # Velocity (4 features)
            'flow_pps': total_pkts / safe_dur,
            'flow_bps': (total_fwd_bytes + total_bwd_bytes) / safe_dur,
            'fwd_bps': fwd_bps,
            'bwd_pps': bwd_pps
        }

    def run_analysis(self, pcap_file, gt_file):
        # 1. Load Ground Truth into Fast Lookup
        gt_lookup = {}
        self.log(f"Loading GT: {os.path.basename(gt_file)}...")
        
        try:
            # We strictly read ONLY the columns you specified + Start time for disambiguation if needed
            required_cols = ['Attack category', 'Protocol', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Start time', 'Last time']
            df = pd.read_csv(gt_file, usecols=required_cols, encoding='latin-1')
            
            # Normalize Headers
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

            # Build Dictionary: Key = (SrcIP, Sport, DstIP, Dport, Proto) -> Value = Attack Name
            for _, row in df.iterrows():
                # Clean Protocol (remove spaces, lower case)
                proto = str(row['protocol']).lower().strip()
                
                # Create the 5-Tuple Key
                key = (
                    str(row['source_ip']).strip(), 
                    int(row['source_port']), 
                    str(row['destination_ip']).strip(), 
                    int(row['destination_port']), 
                    proto
                )
                
                # Store the actual Attack Category Name
                attack_name = str(row['attack_category']).strip()
                if attack_name.lower() == 'nan' or attack_name == '':
                    attack_name = 'Normal'
                
                # Store label and time window for matching
                gt_lookup[key] = {
                    'label': attack_name,
                    'start': row['start_time'],
                    'end': row['last_time']
                }
                
            self.log(f"Loaded {len(gt_lookup)} unique flows from GT.")

        except Exception as e:
            self.log(f"CRITICAL GT ERROR: {e}")
            self.btn_analyze.configure(state="normal", text="EXTRACT 30 FEATURES & GENERATE DATASET")
            return

        # 2. Process PCAP
        self.log(f"Scanning PCAP...")
        current_flows = defaultdict(list)
        proto_map = {6: 'tcp', 17: 'udp'}
        processed_count = 0

        try:
            for pkt in PcapReader(pcap_file):
                processed_count += 1
                if processed_count % 20000 == 0:
                    self.log(f"Scanned {processed_count} packets...")

                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    proto_num = pkt[IP].proto
                    proto_name = proto_map.get(proto_num, 'other') # 'tcp' or 'udp'
                    
                    sport, dport, win, flags, header_len = 0, 0, 0, '', 0
                    
                    if TCP in pkt:
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        win = pkt[TCP].window
                        flags = str(pkt[TCP].flags)
                        header_len = len(pkt[IP]) + len(pkt[TCP])  # IP + TCP header
                    elif UDP in pkt:
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        header_len = len(pkt[IP]) + 8  # IP + UDP header (fixed 8 bytes)

                    # Only process TCP/UDP for now as per GT structure
                    if proto_name in ['tcp', 'udp']:
                        ts = float(pkt.time)
                        size = len(pkt)
                        ttl = pkt[IP].ttl
                        
                        # Create Key matching GT structure
                        flow_key = (str(src), int(sport), str(dst), int(dport), proto_name)
                        current_flows[flow_key].append((ts, size, src, ttl, win, flags, header_len))
        
        except Exception as e:
            self.log(f"PCAP Error: {e}")

        # 3. Match and Export
        self.log(f"Aggregating 30 features for {len(current_flows)} flows...")
        extracted_rows = []
        
        for key, packets in current_flows.items():
            src, sport, dst, dport, proto = key
            
            # Extract Features
            feats = self.calculate_flow_features(packets, src)
            
            # --- LABELING LOGIC ---
            # Default is Normal
            final_label = "Normal" 
            
            if key in gt_lookup:
                gt_data = gt_lookup[key]
                # Optional: Check time to be 100% sure it's the same flow
                # A 2.0 second buffer deals with slight clock differences
                flow_start = packets[0][0]
                if (flow_start >= gt_data['start'] - 2.0) and (flow_start <= gt_data['end'] + 2.0):
                    final_label = gt_data['label']
            
            # Attach Identity Columns
            feats['src_ip'] = src
            feats['sport'] = sport
            feats['dst_ip'] = dst
            feats['dport'] = dport
            feats['proto'] = proto
            
            # Attach Final Label (Last Column)
            feats['label'] = final_label
            
            extracted_rows.append(feats)

        # 4. Save to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"Dataset_30Features_{timestamp}.csv"
        
        # Reorder columns to put Label last
        df_out = pd.DataFrame(extracted_rows)
        cols = list(df_out.columns)
        if 'label' in cols:
            cols.remove('label')
            cols.append('label')
        df_out = df_out[cols]
        
        df_out.to_csv(output_file, index=False)
        
        self.log(f"\n[SUCCESS] Generated dataset: {output_file}")
        self.log(f"Total Rows: {len(df_out)}")
        self.log(f"Total Features: {len(df_out.columns) - 6}")  # Minus identity columns + label
        self.log("Label Distribution:")
        self.log(str(df_out['label'].value_counts()))
        self.btn_analyze.configure(state="normal", text="EXTRACT 30 FEATURES & GENERATE DATASET")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
