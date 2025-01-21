import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import csv
from collections import Counter, defaultdict
import webbrowser
from datetime import datetime
import matplotlib.pyplot as plt

def analyze_packets(packets):
    src_ips = Counter(p['src_ip'] for p in packets)
    dst_ips = Counter(p['dst_ip'] for p in packets)
    connections = Counter((p['src_ip'], p['dst_ip']) for p in packets)

    port_scans = defaultdict(set)
    for p in packets:
        port_scans[(p['src_ip'], p['dst_ip'])].add(p['dst_port'])

    udp_traffic = Counter((p['src_ip'], p['dst_ip']) for p in packets if p['protocol'] == 'UDP')
    ssh_attempts = Counter((p['src_ip'], p['dst_ip']) for p in packets if p['dst_port'] == 22)

    hourly_activity = defaultdict(int)
    for p in packets:
        hour = datetime.strptime(p['timestamp'], '%H:%M:%S.%f').hour
        hourly_activity[hour] += 1

    return src_ips, dst_ips, connections, port_scans, udp_traffic, ssh_attempts, hourly_activity

def generate_pie_chart(src_ips):
    plt.figure(figsize=(10, 8))
    
    # Prendre les 5 IP les plus fréquentes
    top_ips = src_ips.most_common(5)
    labels = [ip for ip, _ in top_ips]
    sizes = [count for _, count in top_ips]
    
    # Ajouter une catégorie "Autres" pour le reste
    other_ips = sum(src_ips.values()) - sum(sizes)
    if other_ips > 0:
        labels.append('Autres')
        sizes.append(other_ips)

    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.title("Distribution des IP sources les plus fréquentes")
    plt.axis('equal')
    
    plt.savefig("ip_distribution.png")
    plt.show()

class TcpdumpAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Analyseur de Trafic Réseau")
        self.geometry("800x600")
        
        # Configuration principale
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        
        # Frame supérieur pour le fichier
        file_frame = ttk.LabelFrame(self, text="Sélection du fichier", padding="10")
        file_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        file_frame.columnconfigure(1, weight=1)
        
        self.file_path = tk.StringVar()
        ttk.Label(file_frame, text="Fichier tcpdump:").grid(row=0, column=0, padx=5)
        ttk.Entry(file_frame, textvariable=self.file_path).grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(file_frame, text="Parcourir", command=self.browse_file).grid(row=0, column=2, padx=5)
        
        # Boutons d'action
        action_frame = ttk.Frame(self)
        action_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        
        ttk.Button(action_frame, text="Analyser", command=self.analyze).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Voir le rapport", command=self.view_report).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Ouvrir CSV", command=self.open_csv).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Générer graphique", command=self.generate_chart).pack(side="left", padx=5)
        
        # Zone de résultats
        self.result_text = tk.Text(self, wrap="word", height=20)
        self.result_text.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.rowconfigure(2, weight=1)

    def generate_report(self, src_ips, dst_ips, connections, port_scans, udp_traffic, ssh_attempts, hourly_activity):
        report = "# Rapport d'analyse réseau\n\n"

        report += "## IP sources les plus fréquentes\n"
        for ip, count in src_ips.most_common(10):
            report += f"- {ip}: {count}\n"

        report += "\n## IP destinations les plus fréquentes\n"
        for ip, count in dst_ips.most_common(10):
            report += f"- {ip}: {count}\n"

        report += "\n## Connexions les plus fréquentes\n"
        for (src, dst), count in connections.most_common(10):
            report += f"- {src} -> {dst}: {count}\n"

        report += "\n## Scans de ports potentiels\n"
        for (src, dst), ports in port_scans.items():
            if len(ports) > 10:
                report += f"- {src} a scanné {len(ports)} ports sur {dst}\n"

        report += "\n## Trafic UDP suspect\n"
        for (src, dst), count in udp_traffic.most_common(5):
            report += f"- {src} -> {dst}: {count} paquets UDP\n"

        report += "\n## Tentatives de connexion SSH\n"
        for (src, dst), count in ssh_attempts.most_common(5):
            report += f"- {src} -> {dst}: {count} tentatives\n"

        return report

    def parse_tcpdump(self, filename):
        packets = []
        with open(filename, 'r') as file:
            for line_num, line in enumerate(file, 1):
                try:
                    match = re.search(r'(?P<timestamp>\S+) IP (?P<src_ip>\S+)[.:](?P<src_port>\d+) [>-] (?P<dst_ip>\S+)[.:](?P<dst_port>\d+).*', line)
                    if match:
                        protocol = 'TCP' if 'TCP' in line else 'UDP' if 'UDP' in line else 'Unknown'
                        packets.append({
                            'line_num': line_num,
                            'timestamp': match.group('timestamp'),
                            'src_ip': match.group('src_ip'),
                            'src_port': int(match.group('src_port')),
                            'dst_ip': match.group('dst_ip'),
                            'dst_port': int(match.group('dst_port')),
                            'protocol': protocol,
                            'raw_data': line.strip()
                        })
                except Exception as e:
                    print(f"Erreur à la ligne {line_num}: {str(e)}")
        return packets

    def generate_csv(self, packets, output_file):
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['line_num', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 
                         'dst_port', 'protocol', 'raw_data']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            for packet in packets:
                writer.writerow(packet)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier tcpdump",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
        )
        if filename:
            self.file_path.set(filename)

    def analyze(self):
        if not self.file_path.get():
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier tcpdump")
            return

        try:
            self.packets = self.parse_tcpdump(self.file_path.get())
            if not self.packets:
                messagebox.showerror("Erreur", "Aucun paquet n'a été trouvé dans le fichier")
                return
                
            self.src_ips, self.dst_ips, self.connections, self.port_scans, self.udp_traffic, self.ssh_attempts, self.hourly_activity = analyze_packets(self.packets)
            
            report = self.generate_report(self.src_ips, self.dst_ips, self.connections, 
                                        self.port_scans, self.udp_traffic, 
                                        self.ssh_attempts, self.hourly_activity)
            
            with open('rapport.md', 'w', encoding='utf-8') as f:
                f.write(report)
            
            self.generate_csv(self.packets, 'packets.csv')
            
            # Afficher un aperçu dans la zone de texte
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', f"Analyse terminée !\n\nAperçu du rapport:\n{report[:500]}...\n\n")
            
            messagebox.showinfo("Succès", "Analyse terminée. Rapport et CSV générés.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue: {str(e)}")

    def view_report(self):
        try:
            webbrowser.open('rapport.md')
        except:
            messagebox.showerror("Erreur", "Impossible d'ouvrir le rapport")

    def open_csv(self):
        try:
            webbrowser.open('packets.csv')
        except:
            messagebox.showerror("Erreur", "Impossible d'ouvrir le fichier CSV")

    def generate_chart(self):
        if hasattr(self, 'src_ips'):
            generate_pie_chart(self.src_ips)
        else:
            messagebox.showerror("Erreur", "Veuillez d'abord analyser un fichier tcpdump")

if __name__ == "__main__":
    app = TcpdumpAnalyzer()
    app.mainloop()