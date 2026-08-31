# EduSniff - basically a mini Wireshark but it explains stuff as you go
#
# idea: capture packets and show what's actually happening on the network in plain english
# instead of just dumping raw hex like real wireshark does.
#
# stuff it can do:
# - capture real traffic with scapy, or just run demo/fake traffic if scapy
#   or admin/root isn't available
# - click a packet and it explains every layer (mac, ip, tcp/udp, ports, flags)
# - tutorial mode - hover over the column headers for a quick explanation
# - glossary window with basic networking terms
# - guided walkthrough of a tcp handshake
# - achievements so it's not boring to test everything
# - little quiz game to test yourself on protocols
# - filter bar like wireshark (tcp, udp, ip.src==..., port==443, etc)
# - hex/ascii viewer at the bottom like the real thing
# - "follow this conversation" - right click a packet to see the whole
#   back and forth between two computers
# - can bookmark/note a packet
# - stats page with charts (protocol counts, packets over time)
# - dark mode toggle
# - export to csv or a text report you could actually hand in
#
# to run:
#   pip install scapy matplotlib
#   python edu_wireshark.py
# on windows you need to run as admin for live capture (and have npcap
# installed), on mac/linux use sudo. if you don't do that it just switches
# to demo mode automatically

import os
import json
import time
import random
import textwrap
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
from datetime import datetime

SCAPY_AVAILABLE = True
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
except Exception:
    SCAPY_AVAILABLE = False

MATPLOTLIB_AVAILABLE = True
try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    MATPLOTLIB_AVAILABLE = False

HIGHSCORE_FILE = os.path.join(os.path.expanduser("~"), ".edusniff_highscore.json")

# quick definitions for the glossary window
GLOSSARY = {
    "MAC Address": "A unique hardware ID (like 3C:5A:B4:9C:11:02) burned into "
                    "every network card. Used for delivery on the LOCAL network "
                    "only - routers strip and replace it at every hop.",
    "IP Address": "A logical address (like 192.168.1.5) used to route packets "
                   "across networks, including the internet. Unlike a MAC "
                   "address, it can change (DHCP) and is used end-to-end.",
    "TCP": "Transmission Control Protocol. A 'reliable' protocol - it "
           "confirms every packet arrives (via ACKs) and resends lost data. "
           "Used for web browsing, email, file transfer.",
    "UDP": "User Datagram Protocol. A 'fire and forget' protocol - faster "
           "than TCP but no delivery guarantee. Used for video calls, "
           "games, and DNS lookups where speed matters more than certainty.",
    "Port": "A number (0-65535) that identifies WHICH APPLICATION on a "
            "device should receive the data. Port 443 = HTTPS, 80 = HTTP, "
            "53 = DNS, 22 = SSH.",
    "TCP Handshake": "The 3-step 'hello' TCP does before sending real data: "
                      "SYN (I want to talk) -> SYN-ACK (okay, and I hear you) "
                      "-> ACK (great, let's go). This happens before every "
                      "normal web connection.",
    "TTL (Time To Live)": "A countdown number that starts high and drops by 1 "
                           "at every router hop. When it hits 0 the packet is "
                           "discarded - this prevents packets from looping "
                           "forever if routing is broken.",
    "Checksum": "A small mathematical fingerprint of the packet's data. The "
                "receiver recalculates it; if it doesn't match, the packet "
                "was corrupted in transit and gets dropped/retransmitted.",
    "Flags (TCP)": "Single-bit switches in the TCP header that signal intent: "
                    "SYN=start connection, ACK=acknowledge, FIN=close nicely, "
                    "RST=abort immediately, PSH=push data to app now.",
    "DNS": "Domain Name System - the 'phonebook of the internet.' Translates "
           "human-readable names (google.com) into IP addresses computers "
           "actually use to connect.",
    "Display Filter": "A search rule (like Wireshark's) that hides every "
                       "packet that doesn't match, so you can focus on just "
                       "'tcp' or one host's traffic.",
}

PROTOCOL_COLORS = {
    "TCP": "#cfe8ff", "UDP": "#e3d0ff", "DNS": "#fff2b2",
    "ICMP": "#ffd0d0", "OTHER": "#e6e6e6",
}

COLUMN_TOOLTIPS = {
    "No.": "The order the packet was captured in, starting at 1.",
    "Time": "Seconds since capture started. Helps you see timing/delays.",
    "Source": "Where the packet came FROM (IP address).",
    "Destination": "Where the packet is going TO (IP address).",
    "Protocol": "Which rulebook (TCP/UDP/DNS/ICMP) this packet follows.",
    "Length": "Total size of the packet in bytes, including headers.",
    "Info": "A quick human-readable summary, like Wireshark's Info column.",
}

QUIZ_QUESTIONS_BANK = [
    {"clue": "Uses ports, guarantees delivery, has SYN/ACK flags.",
     "answer": "TCP", "choices": ["TCP", "UDP", "ICMP", "DNS"]},
    {"clue": "Fast, no handshake, used for video calls and DNS lookups.",
     "answer": "UDP", "choices": ["TCP", "UDP", "DNS", "ICMP"]},
    {"clue": "Carries no ports at all - used for ping/traceroute diagnostics.",
     "answer": "ICMP", "choices": ["ICMP", "TCP", "UDP", "DNS"]},
    {"clue": "Port 53 - translates domain names into IP addresses.",
     "answer": "DNS", "choices": ["DNS", "TCP", "ICMP", "UDP"]},
    {"clue": "The flag combination that STARTS a new TCP connection.",
     "answer": "SYN", "choices": ["SYN", "FIN", "ACK", "RST"]},
    {"clue": "The flag that gracefully CLOSES a TCP connection.",
     "answer": "FIN", "choices": ["FIN", "SYN", "PSH", "RST"]},
]

# badges you unlock just by clicking around and using the features
ACHIEVEMENTS_DEF = [
    ("first_capture", "First Contact", "Start your first capture."),
    ("ten_packets", "Data Collector", "Capture 10+ packets."),
    ("used_filter", "Detective", "Apply a display filter."),
    ("viewed_handshake", "Handshake Hunter", "Inspect a TCP SYN packet."),
    ("used_glossary", "Bookworm", "Open the Glossary."),
    ("followed_convo", "Stream Tracker", "Use Follow This Conversation."),
    ("added_note", "Annotator", "Bookmark a packet with a note."),
    ("quiz_passed", "Quiz Whiz", "Score 4+ in Quiz Mode."),
    ("dark_mode", "Night Owl", "Turn on Dark Mode."),
    ("exported", "Reporter", "Export a session report."),
]


def explain_packet(pkt_summary):
    # builds the text that shows up in the right-hand "explain this packet" box
    lines = [f"PACKET #{pkt_summary['no']} - {pkt_summary['proto']}\n", "=" * 46]
    lines.append("\n[ ETHERNET / LINK LAYER ]")
    lines.append(f"  Src MAC: {pkt_summary['src_mac']}")
    lines.append(f"  Dst MAC: {pkt_summary['dst_mac']}")
    lines.append("  -> " + textwrap.fill(GLOSSARY["MAC Address"], 58))

    lines.append("\n[ IP / NETWORK LAYER ]")
    lines.append(f"  Src IP:  {pkt_summary['src_ip']}")
    lines.append(f"  Dst IP:  {pkt_summary['dst_ip']}")
    lines.append(f"  TTL:     {pkt_summary['ttl']}")
    lines.append("  -> " + textwrap.fill(GLOSSARY["IP Address"], 58))
    lines.append("  -> " + textwrap.fill(GLOSSARY["TTL (Time To Live)"], 58))

    lines.append(f"\n[ {pkt_summary['proto']} / TRANSPORT LAYER ]")
    if pkt_summary["proto"] in ("TCP", "UDP"):
        lines.append(f"  Src Port: {pkt_summary['sport']}")
        lines.append(f"  Dst Port: {pkt_summary['dport']}")
        lines.append("  -> " + textwrap.fill(GLOSSARY["Port"], 58))
        lines.append("  -> " + textwrap.fill(GLOSSARY[pkt_summary["proto"]], 58))
        if pkt_summary["proto"] == "TCP":
            lines.append(f"  Flags: {pkt_summary.get('flags', '-')}")
            lines.append("  -> " + textwrap.fill(GLOSSARY["Flags (TCP)"], 58))
    elif pkt_summary["proto"] == "ICMP":
        lines.append("  ICMP is used for network diagnostics (e.g., 'ping').")
        lines.append("  It has no ports - it talks directly at the IP layer.")
    elif pkt_summary["proto"] == "DNS":
        lines.append("  -> " + textwrap.fill(GLOSSARY["DNS"], 58))

    lines.append("\n[ WHY THIS MATTERS ]")
    tip = pkt_summary.get("teaching_tip", "")
    if tip:
        lines.append("  " + textwrap.fill(tip, 58))
    note = pkt_summary.get("note")
    if note:
        lines.append("\n[ 📌 YOUR NOTE ]")
        lines.append("  " + textwrap.fill(note, 58))
    return "\n".join(lines)


def fake_payload_bytes(summary):
    # demo mode doesn't have real payload bytes, so just make up something
    # consistent (same packet always gives the same "random" bytes)
    seed = summary["no"] * 97 + len(summary["info"])
    rnd = random.Random(seed)
    length = min(max(summary.get("length", 64), 24), 96)
    data = bytes(rnd.randint(0, 255) for _ in range(length))
    return data


def hex_dump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04X}   {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


class PacketEngine:
    # handles either real capture (scapy) or the fake demo traffic
    def __init__(self, on_packet_callback):
        self.on_packet_callback = on_packet_callback
        self.running = False
        self.counter = 0
        self.start_time = None
        self.demo_mode = not SCAPY_AVAILABLE

    def _scapy_handler(self, pkt):
        self.counter += 1
        t = round(time.time() - self.start_time, 4)
        self.on_packet_callback(self._parse_scapy_packet(pkt, self.counter, t))

    def _parse_scapy_packet(self, pkt, no, t):
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "??:??:??:??:??:??"
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "??:??:??:??:??:??"
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "-"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "-"
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else "-"
        proto, sport, dport, flags, info = "OTHER", "-", "-", "-", ""

        if pkt.haslayer(TCP):
            is_dns = pkt[TCP].sport == 53 or pkt[TCP].dport == 53
            proto = "DNS" if is_dns else "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            info = f"{sport} -> {dport} [{flags}]"
        elif pkt.haslayer(UDP):
            is_dns = pkt[UDP].sport == 53 or pkt[UDP].dport == 53
            proto = "DNS" if is_dns else "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            info = f"{sport} -> {dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            info = "Echo request/reply (ping)"

        length = len(pkt) if hasattr(pkt, "__len__") else 0
        raw = bytes(pkt)
        return dict(no=no, time=t, src_mac=src_mac, dst_mac=dst_mac,
                    src_ip=src_ip, dst_ip=dst_ip, ttl=ttl, proto=proto,
                    sport=sport, dport=dport, flags=flags, length=length,
                    info=info or proto, teaching_tip=self._tip_for(proto),
                    raw_bytes=raw[:96], note=None)

    def start_real_capture(self):
        self.running = True
        self.start_time = time.time()
        threading.Thread(target=self._sniff_thread, daemon=True).start()

    def _sniff_thread(self):
        # if this fails (no admin rights, no npcap, whatever) just go to demo
        try:
            sniff(prn=self._scapy_handler, stop_filter=lambda p: not self.running,
                  store=False)
        except Exception:
            self.demo_mode = True
            self.start_demo_capture()

    # scripted sequence for demo mode - dns lookup, tcp handshake, some data,
    # a ping, then closing the connection. tried to make it look realistic
    DEMO_SCRIPT = [
        ("UDP", "192.168.1.20", "8.8.8.8", 5353, 53, "-", "DNS query: example.com A?"),
        ("UDP", "8.8.8.8", "192.168.1.20", 53, 5353, "-", "DNS response: 93.184.216.34"),
        ("TCP", "192.168.1.20", "93.184.216.34", 51422, 443, "SYN", "TCP handshake step 1: SYN"),
        ("TCP", "93.184.216.34", "192.168.1.20", 443, 51422, "SYN, ACK", "TCP handshake step 2: SYN-ACK"),
        ("TCP", "192.168.1.20", "93.184.216.34", 51422, 443, "ACK", "TCP handshake step 3: ACK (connected!)"),
        ("TCP", "192.168.1.20", "93.184.216.34", 51422, 443, "PSH, ACK", "Client sends HTTPS request"),
        ("TCP", "93.184.216.34", "192.168.1.20", 443, 51422, "PSH, ACK", "Server sends HTTPS response data"),
        ("ICMP", "192.168.1.20", "1.1.1.1", "-", "-", "-", "Ping (echo request)"),
        ("ICMP", "1.1.1.1", "192.168.1.20", "-", "-", "-", "Ping reply (echo reply)"),
        ("TCP", "192.168.1.20", "93.184.216.34", 51422, 443, "FIN, ACK", "Client politely closes connection"),
        ("TCP", "93.184.216.34", "192.168.1.20", 443, 51422, "FIN, ACK", "Server acknowledges close"),
        ("UDP", "192.168.1.20", "192.168.1.1", 68, 67, "-", "DHCP-like broadcast traffic"),
    ]

    def _tip_for(self, proto):
        tips = {
            "TCP": "TCP guarantees delivery - notice how it always exchanges "
                   "control flags (SYN/ACK/FIN) before and after real data.",
            "UDP": "UDP has no handshake - data just goes, which is why it's "
                   "faster but less reliable than TCP.",
            "DNS": "Almost everything online starts with a DNS lookup - the "
                   "computer needs an IP address before it can connect.",
            "ICMP": "ICMP carries no application data - it's purely for "
                    "network diagnostics like ping and traceroute.",
            "OTHER": "This packet doesn't match a common protocol pattern.",
        }
        return tips.get(proto, "")

    def start_demo_capture(self):
        self.running = True
        self.start_time = time.time()
        threading.Thread(target=self._demo_thread, daemon=True).start()

    def _demo_thread(self):
        script = list(self.DEMO_SCRIPT)
        while self.running:
            for proto, src_ip, dst_ip, sport, dport, flags, info in script:
                if not self.running:
                    break
                self.counter += 1
                t = round(time.time() - self.start_time, 3)
                mac = lambda seed: ":".join(f"{(seed + i * 17) % 256:02X}" for i in range(6))
                summary = dict(
                    no=self.counter, time=t, src_mac=mac(self.counter),
                    dst_mac=mac(self.counter + 99), src_ip=src_ip, dst_ip=dst_ip,
                    ttl=random.choice([64, 128, 255]), proto=proto, sport=sport,
                    dport=dport, flags=flags, length=random.randint(54, 1420),
                    info=info, teaching_tip=self._tip_for(proto),
                    raw_bytes=None, note=None,
                )
                self.on_packet_callback(summary)
                time.sleep(random.uniform(0.4, 1.0))
            time.sleep(1.5)  # loop the story again after a short pause

    def stop(self):
        self.running = False


def packet_matches_filter(pkt, expr):
    # basic filter syntax, nowhere near as powerful as real wireshark
    # filters but covers the common cases
    expr = expr.strip().lower()
    if not expr:
        return True
    try:
        if expr in ("tcp", "udp", "icmp", "dns"):
            return pkt["proto"].lower() == expr
        if expr.startswith("ip.src=="):
            return pkt["src_ip"] == expr.split("==", 1)[1]
        if expr.startswith("ip.dst=="):
            return pkt["dst_ip"] == expr.split("==", 1)[1]
        if expr.startswith("port=="):
            val = expr.split("==", 1)[1]
            return str(pkt.get("sport")) == val or str(pkt.get("dport")) == val
        if expr.startswith("host=="):
            val = expr.split("==", 1)[1]
            return pkt["src_ip"] == val or pkt["dst_ip"] == val
        # fallback - just search the info/protocol text
        return expr in pkt["info"].lower() or expr in pkt["proto"].lower()
    except Exception:
        return True


class EduSniffApp:
    THEMES = {
        "light": dict(bg="#f2f2f2", fg="#000000", panel="#ffffff"),
        "dark": dict(bg="#1e1e1e", fg="#e6e6e6", panel="#2b2b2b"),
    }

    def __init__(self, root):
        self.root = root
        self.root.title("EduSniff PRO - Educational Packet Analyzer")
        self.root.geometry("1300x760")

        self.packets = []
        self.tutorial_mode = tk.BooleanVar(value=True)
        self.dark_mode = tk.BooleanVar(value=False)
        self.filter_var = tk.StringVar()
        self.engine = PacketEngine(self.on_new_packet)

        self.achievements = {k: False for k, _, _ in ACHIEVEMENTS_DEF}
        self.quiz_score = 0
        self.quiz_asked = 0
        self.highscore = self._load_highscore()

        self._build_menu()
        self._build_toolbar()
        self._build_filterbar()
        self._build_main_layout()
        self._build_statusbar()

        mode_txt = "LIVE capture ready" if SCAPY_AVAILABLE else \
                   "DEMO MODE (scapy/admin not detected - using simulated traffic)"
        self.status.set(mode_txt)

    def _load_highscore(self):
        try:
            with open(HIGHSCORE_FILE, "r") as f:
                return json.load(f).get("highscore", 0)
        except Exception:
            return 0

    def _save_highscore(self):
        try:
            with open(HIGHSCORE_FILE, "w") as f:
                json.dump({"highscore": self.highscore}, f)
        except Exception:
            pass

    def unlock(self, key):
        if not self.achievements.get(key):
            self.achievements[key] = True
            label = next((n for k, n, _ in ACHIEVEMENTS_DEF if k == key), key)
            self.status.set(f"🏆 Achievement unlocked: {label}!")

    def open_achievements(self):
        win = tk.Toplevel(self.root)
        win.title("Achievements")
        win.geometry("420x420")
        box = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Segoe UI", 10))
        box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        earned = sum(1 for v in self.achievements.values() if v)
        box.insert(tk.END, f"Progress: {earned}/{len(ACHIEVEMENTS_DEF)}\n\n", "hdr")
        for key, name, desc in ACHIEVEMENTS_DEF:
            mark = "✅" if self.achievements[key] else "🔒"
            box.insert(tk.END, f"{mark} {name}\n", "term")
            box.insert(tk.END, f"   {desc}\n\n")
        box.tag_configure("term", font=("Segoe UI", 11, "bold"))
        box.tag_configure("hdr", font=("Segoe UI", 12, "bold"))
        box.config(state=tk.DISABLED)

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Export Capture to CSV", command=self.export_csv)
        filemenu.add_command(label="Export Session Report (.txt)", command=self.export_report)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        toolsmenu = tk.Menu(menubar, tearoff=0)
        toolsmenu.add_command(label="Statistics Dashboard", command=self.open_stats)
        toolsmenu.add_command(label="Quiz Mode", command=self.open_quiz)
        toolsmenu.add_command(label="Achievements", command=self.open_achievements)
        menubar.add_cascade(label="Tools", menu=toolsmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Open Glossary", command=self.open_glossary)
        helpmenu.add_command(label="About EduSniff", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.config(menu=menubar)

    def _build_toolbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=4)

        self.start_btn = ttk.Button(bar, text="▶ Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=3)
        self.stop_btn = ttk.Button(bar, text="■ Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Clear", command=self.clear_capture).pack(side=tk.LEFT, padx=3)

        ttk.Checkbutton(bar, text="Tutorial Mode", variable=self.tutorial_mode).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(bar, text="Dark Mode", variable=self.dark_mode,
                         command=self.toggle_dark_mode).pack(side=tk.LEFT, padx=3)

        ttk.Button(bar, text="Guided Lesson", command=self.guided_lesson).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Glossary", command=self.open_glossary).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Statistics", command=self.open_stats).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Quiz", command=self.open_quiz).pack(side=tk.LEFT, padx=3)
        ttk.Button(bar, text="Achievements", command=self.open_achievements).pack(side=tk.LEFT, padx=3)

        legend = ttk.Frame(bar)
        legend.pack(side=tk.RIGHT)
        for proto, color in PROTOCOL_COLORS.items():
            tk.Label(legend, text=proto, bg=color, width=6, relief=tk.RIDGE).pack(side=tk.LEFT, padx=2)

    def _build_filterbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(0, 4))
        ttk.Label(bar, text="Display Filter:").pack(side=tk.LEFT, padx=(0, 4))
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=40)
        entry.pack(side=tk.LEFT)
        entry.bind("<Return>", lambda e: self.apply_filter())
        ttk.Button(bar, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=2)
        ttk.Label(bar, text="  e.g. tcp | udp | dns | icmp | ip.src==1.2.3.4 | port==443 | host==8.8.8.8",
                  foreground="#666666").pack(side=tk.LEFT, padx=10)

    def _build_main_layout(self):
        container = ttk.Frame(self.root)
        container.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        left = ttk.Frame(container)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        cols = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            width = 60 if c in ("No.", "Time", "Length", "Protocol") else 140
            self.tree.column(c, width=width, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_packet)
        self.tree.bind("<Motion>", self.on_hover_header)
        self.tree.bind("<Button-3>", self.on_right_click)

        for proto, color in PROTOCOL_COLORS.items():
            self.tree.tag_configure(proto, background=color)

        hexframe = ttk.LabelFrame(left, text="Byte-Level View (Hex + ASCII)")
        hexframe.pack(fill=tk.BOTH, expand=False, pady=(6, 0), side=tk.BOTTOM)
        self.hex_box = scrolledtext.ScrolledText(hexframe, height=8, font=("Consolas", 9), wrap=tk.NONE)
        self.hex_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.hex_box.insert(tk.END, "Select a packet to see its raw bytes here.")
        self.hex_box.config(state=tk.DISABLED)

        right = ttk.LabelFrame(container, text="Explain This Packet")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(8, 0))
        right.configure(width=430)

        self.explain_box = scrolledtext.ScrolledText(right, width=54, height=30,
                                                       wrap=tk.WORD, font=("Consolas", 10))
        self.explain_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.explain_box.insert(tk.END, "Click any packet on the left to see a plain-English "
                                 "breakdown of every layer here.\n\nRight-click a packet for "
                                 "more options: Follow This Conversation, Add Note.")
        self.explain_box.config(state=tk.DISABLED)

    def _build_statusbar(self):
        self.status = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status, relief=tk.SUNKEN, anchor=tk.W).pack(
            side=tk.BOTTOM, fill=tk.X)

    def start_capture(self):
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.unlock("first_capture")
        if SCAPY_AVAILABLE:
            try:
                self.engine.start_real_capture()
                self.status.set("Live capture running... (falls back to demo automatically if it fails)")
            except Exception:
                self.engine.start_demo_capture()
                self.status.set("Falling back to Demo Mode.")
        else:
            self.engine.start_demo_capture()
            self.status.set("Demo Mode running - simulated realistic traffic.")

    def stop_capture(self):
        self.engine.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.set("Capture stopped.")

    def clear_capture(self):
        self.packets.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)

    def on_new_packet(self, summary):
        # capture runs on a background thread, gotta hand this back to
        # the main tkinter thread or it'll crash
        self.root.after(0, self._insert_packet_row, summary)

    def _insert_packet_row(self, summary):
        self.packets.append(summary)
        if len(self.packets) >= 10:
            self.unlock("ten_packets")
        if summary["proto"] == "TCP" and "SYN" in str(summary.get("flags", "")):
            self.unlock("viewed_handshake")
        proto = summary["proto"] if summary["proto"] in PROTOCOL_COLORS else "OTHER"
        if packet_matches_filter(summary, self.filter_var.get()):
            self.tree.insert("", tk.END, iid=str(summary["no"]), values=(
                summary["no"], summary["time"], summary["src_ip"],
                summary["dst_ip"], summary["proto"], summary["length"],
                summary["info"]), tags=(proto,))
            self.tree.see(str(summary["no"]))

    def apply_filter(self):
        expr = self.filter_var.get()
        if expr.strip():
            self.unlock("used_filter")
        for row in self.tree.get_children():
            self.tree.delete(row)
        for summary in self.packets:
            if packet_matches_filter(summary, expr):
                proto = summary["proto"] if summary["proto"] in PROTOCOL_COLORS else "OTHER"
                self.tree.insert("", tk.END, iid=str(summary["no"]), values=(
                    summary["no"], summary["time"], summary["src_ip"],
                    summary["dst_ip"], summary["proto"], summary["length"],
                    summary["info"]), tags=(proto,))
        self.status.set(f"Filter applied: '{expr}' -> {len(self.tree.get_children())} packet(s) shown.")

    def clear_filter(self):
        self.filter_var.set("")
        self.apply_filter()

    def on_hover_header(self, event):
        if not self.tutorial_mode.get():
            return
        if self.tree.identify_region(event.x, event.y) == "heading":
            col_id = self.tree.identify_column(event.x)
            col_name = self.tree.heading(col_id)["text"]
            tip = COLUMN_TOOLTIPS.get(col_name, "")
            if tip:
                self.status.set(f"[Tutorial] '{col_name}' column: {tip}")

    def _get_selected_packet(self):
        sel = self.tree.selection()
        if not sel:
            return None
        no = int(sel[0])
        return next((p for p in self.packets if p["no"] == no), None)

    def on_select_packet(self, event):
        pkt = self._get_selected_packet()
        if not pkt:
            return
        text = explain_packet(pkt)
        self.explain_box.config(state=tk.NORMAL)
        self.explain_box.delete("1.0", tk.END)
        self.explain_box.insert(tk.END, text)
        self.explain_box.config(state=tk.DISABLED)

        raw = pkt.get("raw_bytes") or fake_payload_bytes(pkt)
        dump = hex_dump(raw)
        self.hex_box.config(state=tk.NORMAL)
        self.hex_box.delete("1.0", tk.END)
        self.hex_box.insert(tk.END, dump + "\n\n(Bytes shown are simulated for teaching purposes "
                             "in Demo Mode; in live capture they are the real packet payload.)")
        self.hex_box.config(state=tk.DISABLED)

    def on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Follow This Conversation", command=self.follow_conversation)
        menu.add_command(label="Add Note / Bookmark", command=self.add_note)
        menu.tk_popup(event.x_root, event.y_root)

    def add_note(self):
        pkt = self._get_selected_packet()
        if not pkt:
            return
        note = simpledialog.askstring("Add Note", f"Note for packet #{pkt['no']}:")
        if note:
            pkt["note"] = note
            self.unlock("added_note")
            row_vals = list(self.tree.item(str(pkt["no"]))["values"])
            row_vals[-1] = "📌 " + str(row_vals[-1])
            self.tree.item(str(pkt["no"]), values=row_vals)
            self.status.set(f"Note added to packet #{pkt['no']}.")

    def follow_conversation(self):
        pkt = self._get_selected_packet()
        if not pkt:
            return
        a, b = pkt["src_ip"], pkt["dst_ip"]
        convo = [p for p in self.packets if {p["src_ip"], p["dst_ip"]} == {a, b}]
        convo.sort(key=lambda p: p["no"])
        self.unlock("followed_convo")

        win = tk.Toplevel(self.root)
        win.title(f"Follow This Conversation: {a} <-> {b}")
        win.geometry("640x460")
        box = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        box.insert(tk.END, f"Conversation between {a} and {b}\n")
        box.insert(tk.END, f"{len(convo)} packet(s) found - shown in order below.\n")
        box.insert(tk.END, "=" * 60 + "\n\n")
        for p in convo:
            direction = "->" if p["src_ip"] == a else "<-"
            box.insert(tk.END, f"#{p['no']:>3} [{p['time']:>7}s] {p['src_ip']} {direction} "
                                f"{p['dst_ip']}  ({p['proto']})  {p['info']}\n")
        box.insert(tk.END, "\nNotice the pattern: this is exactly how two computers 'talk' - "
                            "requests, responses, and (for TCP) a handshake at the start and a "
                            "graceful close (FIN/ACK) at the end.")
        box.config(state=tk.DISABLED)

    def guided_lesson(self):
        msg = (
            "GUIDED LESSON: The TCP Three-Way Handshake\n\n"
            "1. SYN     - Your computer says 'I'd like to connect.'\n"
            "2. SYN-ACK - The server replies 'Okay, and I heard you.'\n"
            "3. ACK     - Your computer confirms 'Great, let's talk.'\n\n"
            "After this handshake, real data (like a webpage) can flow.\n"
            "Tip: type 'tcp' in the Display Filter bar, start a capture, "
            "then right-click any TCP packet and choose 'Follow This "
            "Conversation' to watch the whole handshake in order."
        )
        messagebox.showinfo("Guided Lesson", msg)

    def open_glossary(self):
        self.unlock("used_glossary")
        win = tk.Toplevel(self.root)
        win.title("EduSniff Glossary")
        win.geometry("580x500")
        search_var = tk.StringVar()
        top = ttk.Frame(win)
        top.pack(fill=tk.X, padx=8, pady=4)
        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        entry = ttk.Entry(top, textvariable=search_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        box = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Segoe UI", 10))
        box.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        box.tag_configure("term", font=("Segoe UI", 11, "bold"))

        def render(*_):
            q = search_var.get().lower()
            box.config(state=tk.NORMAL)
            box.delete("1.0", tk.END)
            for term, definition in GLOSSARY.items():
                if q and q not in term.lower() and q not in definition.lower():
                    continue
                box.insert(tk.END, f"{term}\n", "term")
                box.insert(tk.END, textwrap.fill(definition, 68) + "\n\n")
            box.config(state=tk.DISABLED)

        search_var.trace_add("write", render)
        render()

    def show_about(self):
        messagebox.showinfo(
            "About EduSniff PRO",
            "EduSniff PRO - a Wireshark-inspired packet analyzer built for "
            "a school networking assignment.\n\n"
            "Uses Python + Tkinter, with optional scapy for live capture "
            "and matplotlib for the stats charts.\n\n"
            "Has demo mode, filters, a hex viewer, follow-conversation, "
            "a quiz mode, achievements, dark mode, and csv/report export."
        )

    def toggle_dark_mode(self):
        dark = self.dark_mode.get()
        theme = self.THEMES["dark"] if dark else self.THEMES["light"]
        if dark:
            self.unlock("dark_mode")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=theme["bg"], foreground=theme["fg"])
        style.configure("Treeview", background=theme["panel"], foreground=theme["fg"],
                         fieldbackground=theme["panel"])
        self.root.configure(bg=theme["bg"])
        self.explain_box.configure(bg=theme["panel"], fg=theme["fg"], insertbackground=theme["fg"])
        self.hex_box.configure(bg=theme["panel"], fg=theme["fg"], insertbackground=theme["fg"])

    def open_stats(self):
        if not MATPLOTLIB_AVAILABLE:
            messagebox.showwarning("Statistics", "matplotlib isn't installed.\n"
                                    "Run: pip install matplotlib")
            return
        win = tk.Toplevel(self.root)
        win.title("Statistics Dashboard")
        win.geometry("760x500")

        fig, axes = plt.subplots(1, 2, figsize=(7.4, 4.2))
        counts = {}
        for p in self.packets:
            counts[p["proto"]] = counts.get(p["proto"], 0) + 1
        protos = list(counts.keys()) or ["No data"]
        vals = list(counts.values()) or [0]
        colors = [PROTOCOL_COLORS.get(p, "#999999") for p in protos]
        axes[0].bar(protos, vals, color=colors, edgecolor="black")
        axes[0].set_title("Protocol Distribution")
        axes[0].set_ylabel("Packet count")

        times = [p["time"] for p in self.packets]
        axes[1].plot(range(1, len(times) + 1), times, marker="o", color="#3366cc")
        axes[1].set_title("Packets Captured Over Time")
        axes[1].set_xlabel("Packet #")
        axes[1].set_ylabel("Seconds since start")
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        ttk.Label(win, text=f"Total packets: {len(self.packets)}   |   "
                             f"Unique protocols: {len(counts)}").pack(pady=4)

    def open_quiz(self):
        win = tk.Toplevel(self.root)
        win.title("EduSniff Quiz Mode")
        win.geometry("480x320")

        state = {"q": None}
        score_lbl = ttk.Label(win, text=f"Score: {self.quiz_score}   High Score: {self.highscore}",
                               font=("Segoe UI", 10, "bold"))
        score_lbl.pack(pady=6)
        clue_lbl = ttk.Label(win, text="", wraplength=420, font=("Segoe UI", 12))
        clue_lbl.pack(pady=14)
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=8)
        feedback_lbl = ttk.Label(win, text="", font=("Segoe UI", 10))
        feedback_lbl.pack(pady=6)

        def next_question():
            for w in btn_frame.winfo_children():
                w.destroy()
            q = random.choice(QUIZ_QUESTIONS_BANK)
            state["q"] = q
            clue_lbl.config(text="Clue: " + q["clue"])
            feedback_lbl.config(text="")
            choices = q["choices"][:]
            random.shuffle(choices)
            for c in choices:
                ttk.Button(btn_frame, text=c, width=10,
                           command=lambda c=c: check_answer(c)).pack(side=tk.LEFT, padx=4)

        def check_answer(choice):
            q = state["q"]
            self.quiz_asked += 1
            if choice == q["answer"]:
                self.quiz_score += 1
                feedback_lbl.config(text="Correct!", foreground="green")
            else:
                feedback_lbl.config(text=f"Nope, it was {q['answer']}.", foreground="red")
            if self.quiz_score > self.highscore:
                self.highscore = self.quiz_score
                self._save_highscore()
            if self.quiz_score >= 4:
                self.unlock("quiz_passed")
            score_lbl.config(text=f"Score: {self.quiz_score}   High Score: {self.highscore}")
            win.after(900, next_question)

        next_question()

    def export_csv(self):
        if not self.packets:
            messagebox.showinfo("Export CSV", "No packets captured yet.")
            return
        path = os.path.join(os.getcwd(), f"edusniff_capture_{int(time.time())}.csv")
        with open(path, "w", encoding="utf-8") as f:
            f.write("No.,Time,SourceIP,DestIP,Protocol,Length,Info,Note\n")
            for p in self.packets:
                note = (p.get("note") or "").replace(",", ";")
                f.write(f'{p["no"]},{p["time"]},{p["src_ip"]},{p["dst_ip"]},'
                        f'{p["proto"]},{p["length"]},"{p["info"]}","{note}"\n')
        self.status.set(f"Exported {len(self.packets)} packets to {path}")
        messagebox.showinfo("Export CSV", f"Saved to:\n{path}")

    def export_report(self):
        path = os.path.join(os.getcwd(), f"edusniff_report_{int(time.time())}.txt")
        counts = {}
        for p in self.packets:
            counts[p["proto"]] = counts.get(p["proto"], 0) + 1
        notes = [p for p in self.packets if p.get("note")]
        earned = [n for k, n, _ in ACHIEVEMENTS_DEF if self.achievements.get(k)]

        with open(path, "w", encoding="utf-8") as f:
            f.write("EduSniff PRO - Session Report\n")
            f.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total packets captured: {len(self.packets)}\n")
            f.write("Protocol breakdown:\n")
            for proto, c in counts.items():
                f.write(f"  {proto}: {c}\n")
            f.write(f"\nQuiz score this session: {self.quiz_score} (high score: {self.highscore})\n")
            f.write(f"\nAchievements unlocked ({len(earned)}/{len(ACHIEVEMENTS_DEF)}):\n")
            for n in earned:
                f.write(f"  - {n}\n")
            if notes:
                f.write("\nYour bookmarked packets:\n")
                for p in notes:
                    f.write(f"  #{p['no']} ({p['proto']} {p['src_ip']} -> {p['dst_ip']}): {p['note']}\n")
            f.write("\n" + "=" * 60 + "\n")
            f.write("Session report generated by EduSniff PRO.\n")
        self.unlock("exported")
        self.status.set(f"Session report saved to {path}")
        messagebox.showinfo("Export Report", f"Saved to:\n{path}")


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = EduSniffApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
