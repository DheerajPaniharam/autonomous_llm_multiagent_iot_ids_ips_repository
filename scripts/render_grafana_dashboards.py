import os
import random
import math
from PIL import Image, ImageDraw, ImageFont

W, H = 1376, 768

# Windows Fonts
FONT_PATH = "C:/Windows/Fonts/segoeui.ttf"
FONT_BOLD_PATH = "C:/Windows/Fonts/segoeuib.ttf"
FONT_SEMIBOLD_PATH = "C:/Windows/Fonts/seguisb.ttf"
FONT_MONO_PATH = "C:/Windows/Fonts/consola.ttf"

f_title = ImageFont.truetype(FONT_BOLD_PATH, 16)
f_hdr = ImageFont.truetype(FONT_SEMIBOLD_PATH, 13)
f_sub = ImageFont.truetype(FONT_PATH, 11)
f_stat_val = ImageFont.truetype(FONT_BOLD_PATH, 24)
f_stat_lbl = ImageFont.truetype(FONT_SEMIBOLD_PATH, 11)
f_body = ImageFont.truetype(FONT_PATH, 11)
f_mono = ImageFont.truetype(FONT_MONO_PATH, 10)
f_badge = ImageFont.truetype(FONT_BOLD_PATH, 9)

# Colors
BG_DARK = "#111217"
PANEL_BG = "#181B1F"
PANEL_BORDER = "#26292E"
HEADER_BG = "#1F2328"
TEXT_WHITE = "#E5E7EB"
TEXT_MUTED = "#9CA3AF"
TEXT_DIM = "#6B7280"

ACCENT_BLUE = "#38BDF8"
ACCENT_GREEN = "#34D399"
ACCENT_AMBER = "#FBBF24"
ACCENT_RED = "#F87171"
ACCENT_PURPLE = "#A78BFA"
ACCENT_CYAN = "#22D3EE"

def draw_top_nav(draw, dashboard_title):
    # Top navbar
    draw.rectangle([(0, 0), (W, 46)], fill=HEADER_BG)
    draw.line([(0, 46), (W, 46)], fill=PANEL_BORDER, width=1)
    
    # Grafana Icon (Orange circle with swirl)
    draw.ellipse([(14, 11), (36, 33)], fill="#F97316")
    draw.ellipse([(19, 16), (31, 28)], fill=HEADER_BG)
    draw.ellipse([(22, 19), (28, 25)], fill="#F97316")
    
    # Breadcrumb
    draw.text((46, 14), f"Dashboards  /  {dashboard_title}", fill=TEXT_WHITE, font=f_title)
    
    # Time picker & refresh controls on right
    draw.rounded_rectangle([(W - 270, 10), (W - 130, 36)], radius=4, fill="#26292E", outline=PANEL_BORDER)
    draw.text((W - 255, 14), "⏱  Last 15 minutes", fill=TEXT_WHITE, font=f_hdr)
    
    draw.rounded_rectangle([(W - 120, 10), (W - 60, 36)], radius=4, fill="#26292E", outline=PANEL_BORDER)
    draw.text((W - 105, 14), "🔄 5s", fill=TEXT_WHITE, font=f_hdr)
    
    # User icon
    draw.ellipse([(W - 44, 12), (W - 18, 34)], fill="#3B82F6")
    draw.text((W - 36, 14), "A", fill="#FFFFFF", font=f_hdr)

def draw_panel_box(draw, x0, y0, x1, y1, title=""):
    draw.rounded_rectangle([(x0, y0), (x1, y1)], radius=4, fill=PANEL_BG, outline=PANEL_BORDER, width=1)
    if title:
        draw.text((x0 + 12, y0 + 8), title, fill=TEXT_WHITE, font=f_hdr)
        draw.line([(x0, y0 + 28), (x1, y0 + 28)], fill=PANEL_BORDER, width=1)

# ==========================================
# 1. IDS SYSTEM LOGS DASHBOARD
# ==========================================
def render_system_logs():
    img = Image.new("RGB", (W, H), BG_DARK)
    draw = ImageDraw.Draw(img)
    draw_top_nav(draw, "IDS System Logs")
    
    # Row 1: 4 Stat Cards (y: 56 to 136)
    stats = [
        ("Total Logs (24h)", "142,850", "+14.2% vs avg", ACCENT_GREEN),
        ("Error & Critical Rate", "0.08%", "114 events total", ACCENT_AMBER),
        ("Active Loki Streams", "5 Agents", "100% Ingestion Up", ACCENT_BLUE),
        ("Loki Ingestion Throughput", "48.2 logs/s", "Zero queue drops", ACCENT_CYAN),
    ]
    card_w = (W - 24 - 36) // 4
    for i, (lbl, val, sub, col) in enumerate(stats):
        x0 = 12 + i * (card_w + 12)
        x1 = x0 + card_w
        draw.rounded_rectangle([(x0, 56), (x1, 136)], radius=4, fill=PANEL_BG, outline=PANEL_BORDER, width=1)
        draw.rectangle([(x0, 56), (x0 + 4, 136)], fill=col)
        draw.text((x0 + 14, 66), lbl, fill=TEXT_MUTED, font=f_stat_lbl)
        draw.text((x0 + 14, 84), val, fill=col, font=f_stat_val)
        draw.text((x0 + 14, 114), sub, fill=TEXT_DIM, font=f_sub)

    # Row 2: Charts (y: 146 to 376)
    # Chart 1: Logs by Level (Timeseries)
    draw_panel_box(draw, 12, 146, 880, 376, "Logs by Level (5m Rolling)")
    # Draw mini timeseries axes & bars
    cx0, cy0, cx1, cy1 = 40, 185, 860, 345
    draw.line([(cx0, cy1), (cx1, cy1)], fill="#374151", width=1)
    draw.line([(cx0, cy0), (cx0, cy1)], fill="#374151", width=1)
    
    # Legend
    draw.rectangle([(190, 154), (200, 164)], fill=ACCENT_BLUE)
    draw.text((205, 153), "INFO", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(250, 154), (260, 164)], fill=ACCENT_AMBER)
    draw.text((265, 153), "WARNING", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(335, 154), (345, 164)], fill=ACCENT_RED)
    draw.text((350, 153), "ERROR", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(405, 154), (415, 164)], fill=ACCENT_PURPLE)
    draw.text((420, 153), "CRITICAL", fill=TEXT_WHITE, font=f_sub)
    
    # Plot stacked bar graph simulations
    import random
    random.seed(42)
    bar_step = 28
    for idx, bx in enumerate(range(cx0 + 15, cx1 - 20, bar_step)):
        h_info = random.randint(40, 110)
        h_warn = random.randint(10, 35) if idx % 2 == 0 else random.randint(5, 15)
        h_err = random.randint(5, 18) if idx in [6, 14, 22] else 0
        h_crit = random.randint(8, 20) if idx in [7, 15, 23] else 0
        
        y_curr = cy1
        # INFO
        draw.rectangle([(bx, y_curr - h_info), (bx + 18, y_curr)], fill="#1E40AF")
        y_curr -= h_info
        # WARN
        if h_warn:
            draw.rectangle([(bx, y_curr - h_warn), (bx + 18, y_curr)], fill="#D97706")
            y_curr -= h_warn
        # ERR
        if h_err:
            draw.rectangle([(bx, y_curr - h_err), (bx + 18, y_curr)], fill="#DC2626")
            y_curr -= h_err
        # CRIT
        if h_crit:
            draw.rectangle([(bx, y_curr - h_crit), (bx + 18, y_curr)], fill="#7C3AED")

    draw.text((cx0, cy1 + 8), "10:20:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 260, cy1 + 8), "10:25:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 520, cy1 + 8), "10:30:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx1 - 50, cy1 + 8), "10:35:00", fill=TEXT_DIM, font=f_sub)

    # Chart 2: Errors by Agent
    draw_panel_box(draw, 892, 146, W - 12, 376, "Errors by Agent (5m)")
    agents = [
        ("TrafficAgent", 2, ACCENT_BLUE),
        ("AnalysisAgent", 0, ACCENT_GREEN),
        ("LLMOrchestrator", 4, ACCENT_PURPLE),
        ("ResponseAgent", 1, ACCENT_AMBER),
        ("ObservabilityAgent", 0, ACCENT_CYAN)
    ]
    for idx, (ag, cnt, ccol) in enumerate(agents):
        ay = 185 + idx * 36
        draw.text((910, ay), ag, fill=TEXT_WHITE, font=f_body)
        draw.rounded_rectangle([(1070, ay + 2), (1070 + max(12, cnt * 55), ay + 18)], radius=3, fill=ccol)
        draw.text((1070 + max(12, cnt * 55) + 10, ay + 2), str(cnt), fill=TEXT_WHITE, font=f_body)

    # Row 3: LogQL Live Log Stream (y: 386 to H - 12)
    draw_panel_box(draw, 12, 386, W - 12, H - 12, "Recent IDS System Logs — LogQL Stream {job=\"ids_system\"}")
    
    logs = [
        ("10:32:15.102", "INFO", "TrafficAgent", "High-frequency packet burst on eth0: 1,420 pkts/s, SYN/ACK ratio 0.94, Shannon entropy 1.12", ACCENT_BLUE),
        ("10:32:15.148", "WARNING", "AnalysisAgent", "Threat classified: Volumetric DDoS SYN Flood (p=0.9928, Isolation Forest anomaly score 0.9540)", ACCENT_AMBER),
        ("10:32:15.210", "CRITICAL", "LLMOrchestrator", "Qwen2.5-3B synthesized plan: Action 'block_ip', Target 192.168.1.144, TTL 3600s, SLA 1.12s", ACCENT_PURPLE),
        ("10:32:15.228", "WARNING", "ResponseAgent", "Injected kernel drop rule: nft add rule inet ids_filter input ip saddr 192.168.1.144 drop (12.4ms)", ACCENT_RED),
        ("10:32:15.240", "INFO", "ObservabilityAgent", "Batched transaction committed (size=142 flows) to PostgreSQL 16; Loki log chunk flushed", ACCENT_GREEN),
        ("10:32:14.882", "INFO", "TrafficAgent", "Parsed 250 NetFlow connection records from Zeek conn.log buffer; port entropy computed", ACCENT_BLUE),
        ("10:32:13.415", "WARNING", "AnalysisAgent", "PortScan activity detected from 192.168.1.201 (Entropy H=5.84, target port spread 45/sec)", ACCENT_AMBER),
        ("10:32:13.450", "INFO", "ResponseAgent", "Dynamic rate-limiting rule applied: nft add rule inet ids_filter input ip saddr 192.168.1.201 limit rate 5/minute", ACCENT_CYAN),
    ]
    
    for idx, (ts, lvl, ag, msg, col) in enumerate(logs):
        ly = 422 + idx * 38
        draw.rectangle([(20, ly), (W - 20, ly + 32)], fill="#13151A" if idx % 2 == 0 else "#181B1F")
        draw.text((28, ly + 9), ts, fill=TEXT_DIM, font=f_mono)
        
        # Badge for Level
        draw.rounded_rectangle([(120, ly + 6), (185, ly + 26)], radius=3, fill=col)
        draw.text((128, ly + 8), lvl, fill="#0F172A", font=f_badge)
        
        # Agent
        draw.text((200, ly + 9), f"[{ag}]", fill=ACCENT_CYAN, font=f_mono)
        
        # Message
        draw.text((360, ly + 9), msg, fill=TEXT_WHITE, font=f_body)

    img.save("grafana_system_logs.png")
    print("Saved grafana_system_logs.png")

# ==========================================
# 2. IDS FIREWALL MITIGATION DASHBOARD
# ==========================================
def render_firewall_mitigation():
    img = Image.new("RGB", (W, H), BG_DARK)
    draw = ImageDraw.Draw(img)
    draw_top_nav(draw, "IDS Firewall Mitigation & Containment")
    
    # Row 1: 4 Stat Cards
    stats = [
        ("Active nftables Rules", "14 Active", "10 Drops, 4 Rate-Limits", ACCENT_RED),
        ("Quarantined IoT Nodes", "3 Isolated", "Hardware MAC Lock applied", ACCENT_AMBER),
        ("Dropped Packet Velocity", "2,840 pkts/s", "Mitigating volumetric attack", ACCENT_CYAN),
        ("Kernel Rule SLA (P95)", "12.4 ms", "Target < 50ms verified", ACCENT_GREEN),
    ]
    card_w = (W - 24 - 36) // 4
    for i, (lbl, val, sub, col) in enumerate(stats):
        x0 = 12 + i * (card_w + 12)
        x1 = x0 + card_w
        draw.rounded_rectangle([(x0, 56), (x1, 136)], radius=4, fill=PANEL_BG, outline=PANEL_BORDER, width=1)
        draw.rectangle([(x0, 56), (x0 + 4, 136)], fill=col)
        draw.text((x0 + 14, 66), lbl, fill=TEXT_MUTED, font=f_stat_lbl)
        draw.text((x0 + 14, 84), val, fill=col, font=f_stat_val)
        draw.text((x0 + 14, 114), sub, fill=TEXT_DIM, font=f_sub)

    # Row 2: Charts (y: 146 to 376)
    # Chart 1: Mitigation Events by Type
    draw_panel_box(draw, 12, 146, 680, 376, "Mitigation Events by Action Type (5m)")
    cx0, cy0, cx1, cy1 = 35, 185, 660, 345
    draw.line([(cx0, cy1), (cx1, cy1)], fill="#374151", width=1)
    draw.line([(cx0, cy0), (cx0, cy1)], fill="#374151", width=1)
    
    # Legend
    draw.rectangle([(190, 154), (200, 164)], fill=ACCENT_RED)
    draw.text((205, 153), "block_ip", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(270, 154), (280, 164)], fill=ACCENT_AMBER)
    draw.text((285, 153), "rate_limit", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(355, 154), (365, 164)], fill=ACCENT_PURPLE)
    draw.text((370, 153), "isolate_device", fill=TEXT_WHITE, font=f_sub)
    
    # Simulated stepped lines for mitigations
    import math
    for idx, px in enumerate(range(cx0 + 10, cx1 - 20, 24)):
        y_val_block = cy1 - int(45 + 35 * math.sin(idx * 0.4) + (25 if idx > 12 else 0))
        y_val_limit = cy1 - int(25 + 15 * math.cos(idx * 0.5))
        y_val_iso = cy1 - int(10 + (20 if idx > 16 else 5))
        
        draw.rectangle([(px, y_val_block), (px + 6, cy1)], fill=ACCENT_RED)
        draw.rectangle([(px + 7, y_val_limit), (px + 13, cy1)], fill=ACCENT_AMBER)
        draw.rectangle([(px + 14, y_val_iso), (px + 20, cy1)], fill=ACCENT_PURPLE)

    draw.text((cx0, cy1 + 8), "10:20:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 200, cy1 + 8), "10:25:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 400, cy1 + 8), "10:30:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx1 - 50, cy1 + 8), "10:35:00", fill=TEXT_DIM, font=f_sub)

    # Chart 2: Dropped Packet Volume (Timeseries)
    draw_panel_box(draw, 692, 146, W - 12, 376, "nftables Dropped Packet Throughput (pkts/sec)")
    gx0, gy0, gx1, gy1 = 715, 185, W - 35, 345
    draw.line([(gx0, gy1), (gx1, gy1)], fill="#374151", width=1)
    draw.line([(gx0, gy0), (gx0, gy1)], fill="#374151", width=1)
    
    points = []
    for idx, px in enumerate(range(gx0 + 10, gx1 - 10, 18)):
        if idx < 10:
            py = gy1 - random.randint(10, 25)
        elif idx < 22:
            py = gy1 - random.randint(90, 145)
        else:
            py = gy1 - random.randint(30, 60)
        points.append((px, py))
    for i in range(len(points) - 1):
        draw.line([points[i], points[i+1]], fill=ACCENT_CYAN, width=2)
    
    draw.text((gx0, gy1 + 8), "10:20:00", fill=TEXT_DIM, font=f_sub)
    draw.text((gx0 + 280, gy1 + 8), "10:30:00", fill=TEXT_DIM, font=f_sub)
    draw.text((gx1 - 50, gy1 + 8), "10:35:00", fill=TEXT_DIM, font=f_sub)

    # Row 3: Active nftables Rule Inspection Table (y: 386 to H - 12)
    draw_panel_box(draw, 12, 386, W - 12, H - 12, "Active Linux Kernel nftables Firewall Rules & Expiration TTL Ledger")
    
    table_hdrs = ["Target Entity / IP", "Filter Hook & Rule", "Threat Classification", "Applied At", "TTL Remaining", "Status"]
    th_x = [30, 210, 560, 810, 990, 1190]
    for h_idx, (th_name, tx) in enumerate(zip(table_hdrs, th_x)):
        draw.text((tx, 418), th_name, fill=TEXT_MUTED, font=f_hdr)
    draw.line([(20, 442), (W - 20, 442)], fill=PANEL_BORDER, width=1)

    rules = [
        ("192.168.1.144", "nft add rule inet ids_filter input ip saddr 192.168.1.144 drop", "DDoS SYN Flood", "10:32:15 UTC", "3,418 s", "BLOCKED", ACCENT_RED),
        ("192.168.1.201", "nft add rule inet ids_filter input ip saddr 192.168.1.201 limit 5/m", "PortScan Recon", "10:28:40 UTC", "1,215 s", "THROTTLED", ACCENT_AMBER),
        ("00:1A:2B:3C:4D:5E", "nft add rule inet ids_filter forward ether saddr 00:1A... drop", "Botnet C2 Gateway", "10:15:02 UTC", "8,410 s", "ISOLATED", ACCENT_PURPLE),
        ("192.168.1.105", "nft add rule inet ids_filter input ip saddr 192.168.1.105 drop", "DoS Hulk Flood", "10:05:18 UTC", "1,812 s", "BLOCKED", ACCENT_RED),
        ("192.168.1.195", "nft add rule inet ids_filter input ip saddr 192.168.1.195 tcp dport 22 drop", "SSH Brute-Force", "09:55:12 UTC", "0 s (Expired)", "RELEASED", ACCENT_GREEN),
        ("192.168.1.112", "nft add rule inet ids_filter input ip saddr 192.168.1.112 limit 10/m", "HTTP Slowloris", "09:40:20 UTC", "450 s", "THROTTLED", ACCENT_AMBER),
    ]

    for idx, (ip, rule_txt, th_class, app_time, ttl, stat, col) in enumerate(rules):
        ry = 452 + idx * 42
        draw.rectangle([(20, ry), (W - 20, ry + 36)], fill="#13151A" if idx % 2 == 0 else "#181B1F")
        draw.text((th_x[0], ry + 9), ip, fill=TEXT_WHITE, font=f_mono)
        draw.text((th_x[1], ry + 9), rule_txt[:48] + ("..." if len(rule_txt) > 48 else ""), fill=ACCENT_CYAN, font=f_mono)
        draw.text((th_x[2], ry + 9), th_class, fill=TEXT_WHITE, font=f_body)
        draw.text((th_x[3], ry + 9), app_time, fill=TEXT_DIM, font=f_mono)
        draw.text((th_x[4], ry + 9), ttl, fill=ACCENT_AMBER if "s" in ttl and int(ttl.split()[0].replace(',', '')) > 0 else TEXT_MUTED, font=f_mono)
        
        # Status badge
        draw.rounded_rectangle([(th_x[5], ry + 6), (th_x[5] + 85, ry + 28)], radius=3, fill=col)
        draw.text((th_x[5] + 12, ry + 8), stat, fill="#0F172A", font=f_badge)

    img.save("grafana_firewall_mitigation.png")
    print("Saved grafana_firewall_mitigation.png")

# ==========================================
# 3. IDS AGENT ACTIVITY DASHBOARD
# ==========================================
def render_agent_activity():
    img = Image.new("RGB", (W, H), BG_DARK)
    draw = ImageDraw.Draw(img)
    draw_top_nav(draw, "IDS Agent Activity & Queue Telemetry")
    
    # Row 1: 4 Stat Cards
    stats = [
        ("TrafficAgent Throughput", "1,850 flows/s", "Suricata/Zeek parser active", ACCENT_CYAN),
        ("AnalysisAgent Speed", "38.5 ms / inf", "LightGBM + IsolationForest", ACCENT_GREEN),
        ("LLMOrchestrator SLA", "1.18 s / decision", "Qwen2.5-3B Local Ollama", ACCENT_PURPLE),
        ("ResponseAgent Exec SLA", "12.4 ms", "nftables direct kernel hook", ACCENT_AMBER),
    ]
    card_w = (W - 24 - 36) // 4
    for i, (lbl, val, sub, col) in enumerate(stats):
        x0 = 12 + i * (card_w + 12)
        x1 = x0 + card_w
        draw.rounded_rectangle([(x0, 56), (x1, 136)], radius=4, fill=PANEL_BG, outline=PANEL_BORDER, width=1)
        draw.rectangle([(x0, 56), (x0 + 4, 136)], fill=col)
        draw.text((x0 + 14, 66), lbl, fill=TEXT_MUTED, font=f_stat_lbl)
        draw.text((x0 + 14, 84), val, fill=col, font=f_stat_val)
        draw.text((x0 + 14, 114), sub, fill=TEXT_DIM, font=f_sub)

    # Row 2: Charts (y: 146 to 376)
    # Chart 1: Events by Agent (Timeseries Area)
    draw_panel_box(draw, 12, 146, 760, 376, "Event Throughput by Agent (15m Rolling Window)")
    cx0, cy0, cx1, cy1 = 35, 185, 740, 345
    draw.line([(cx0, cy1), (cx1, cy1)], fill="#374151", width=1)
    draw.line([(cx0, cy0), (cx0, cy1)], fill="#374151", width=1)
    
    # Legend
    draw.rectangle([(190, 154), (200, 164)], fill=ACCENT_CYAN)
    draw.text((205, 153), "TrafficAgent", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(290, 154), (300, 164)], fill=ACCENT_GREEN)
    draw.text((305, 153), "AnalysisAgent", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(395, 154), (405, 164)], fill=ACCENT_PURPLE)
    draw.text((410, 153), "LLMOrchestrator", fill=TEXT_WHITE, font=f_sub)
    draw.rectangle([(515, 154), (525, 164)], fill=ACCENT_AMBER)
    draw.text((530, 153), "ResponseAgent", fill=TEXT_WHITE, font=f_sub)

    # Stacked lines simulation
    for px in range(cx0 + 10, cx1 - 20, 20):
        h_tf = random.randint(70, 115)
        h_an = random.randint(50, 90)
        h_orch = random.randint(15, 40)
        h_resp = random.randint(10, 25)
        
        draw.rectangle([(px, cy1 - h_tf), (px + 12, cy1)], fill="#0284C7")
        draw.rectangle([(px, cy1 - h_an), (px + 12, cy1)], fill="#059669")
        draw.rectangle([(px, cy1 - h_orch), (px + 12, cy1)], fill="#7C3AED")
        draw.rectangle([(px, cy1 - h_resp), (px + 12, cy1)], fill="#D97706")

    draw.text((cx0, cy1 + 8), "10:20:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 230, cy1 + 8), "10:25:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx0 + 460, cy1 + 8), "10:30:00", fill=TEXT_DIM, font=f_sub)
    draw.text((cx1 - 50, cy1 + 8), "10:35:00", fill=TEXT_DIM, font=f_sub)

    # Chart 2: Inter-Agent Queue Depth Dynamics
    draw_panel_box(draw, 772, 146, W - 12, 376, "Inter-Agent Async Queue Backlog Depths")
    qx0, qy0, qx1, qy1 = 795, 185, W - 35, 345
    draw.line([(qx0, qy1), (qx1, qy1)], fill="#374151", width=1)
    draw.line([(qx0, qy0), (qx0, qy1)], fill="#374151", width=1)
    
    # Draw safe threshold dashed line
    draw.line([(qx0, qy1 - 100), (qx1, qy1 - 100)], fill="#EF4444", width=1)
    draw.text((qx1 - 140, qy1 - 114), "Backpressure Limit (1,000)", fill=ACCENT_RED, font=f_sub)
    
    q_points = []
    for idx, px in enumerate(range(qx0 + 10, qx1 - 10, 18)):
        val = 15 + (60 if 8 < idx < 18 else 10) + random.randint(0, 15)
        py = qy1 - val
        q_points.append((px, py))
    for i in range(len(q_points) - 1):
        draw.line([q_points[i], q_points[i+1]], fill=ACCENT_GREEN, width=2)

    draw.text((qx0, qy1 + 8), "10:20:00", fill=TEXT_DIM, font=f_sub)
    draw.text((qx0 + 240, qy1 + 8), "10:30:00", fill=TEXT_DIM, font=f_sub)
    draw.text((qx1 - 50, qy1 + 8), "10:35:00", fill=TEXT_DIM, font=f_sub)

    # Row 3: Agent Process Status & Thread Health Table
    draw_panel_box(draw, 12, 386, W - 12, H - 12, "Background Agent Worker Pools & Communication Channel Status")
    
    ag_hdrs = ["Agent Service Name", "Process / Thread ID", "Target Input Queue", "Uptime", "RAM Usage", "Processed Lifetime", "Health Status"]
    ag_x = [30, 220, 420, 630, 780, 930, 1170]
    for h_idx, (th_name, tx) in enumerate(zip(ag_hdrs, ag_x)):
        draw.text((tx, 418), th_name, fill=TEXT_MUTED, font=f_hdr)
    draw.line([(20, 442), (W - 20, 442)], fill=PANEL_BORDER, width=1)

    agent_rows = [
        ("TrafficAgent", "PID 1042 (Thread-1)", "raw_pcap_stream (Zeek/Suricata)", "14d 06h 22m", "42.5 MB", "1,248,920 pkts", "HEALTHY", ACCENT_GREEN),
        ("AnalysisAgent", "PID 1043 (Thread-2)", "detection_queue (cap=5,000)", "14d 06h 22m", "48.2 MB", "840,115 flows", "HEALTHY", ACCENT_GREEN),
        ("LLMOrchestrator", "PID 1044 (Thread-3)", "orchestrator_queue (cap=500)", "14d 06h 22m", "118.0 MB", "1,420 alerts", "HEALTHY", ACCENT_GREEN),
        ("ResponseAgent", "PID 1045 (Thread-4)", "prevention_queue (cap=1,000)", "14d 06h 22m", "36.8 MB", "342 actions", "HEALTHY", ACCENT_GREEN),
        ("ObservabilityAgent", "PID 1046 (Thread-5)", "logging_queue (cap=10,000)", "14d 06h 22m", "52.4 MB", "142,850 logs", "HEALTHY", ACCENT_GREEN),
        ("SupervisorDaemon", "PID 1040 (Master)", "supervisor_heartbeat_channel", "14d 06h 25m", "18.2 MB", "120,400 pings", "HEALTHY", ACCENT_GREEN),
    ]

    for idx, (ag_name, pid, q_in, up, ram, proc, stat, col) in enumerate(agent_rows):
        ry = 452 + idx * 42
        draw.rectangle([(20, ry), (W - 20, ry + 36)], fill="#13151A" if idx % 2 == 0 else "#181B1F")
        draw.text((ag_x[0], ry + 9), ag_name, fill=TEXT_WHITE, font=f_hdr)
        draw.text((ag_x[1], ry + 9), pid, fill=TEXT_DIM, font=f_mono)
        draw.text((ag_x[2], ry + 9), q_in, fill=ACCENT_CYAN, font=f_mono)
        draw.text((ag_x[3], ry + 9), up, fill=TEXT_DIM, font=f_mono)
        draw.text((ag_x[4], ry + 9), ram, fill=ACCENT_AMBER, font=f_mono)
        draw.text((ag_x[5], ry + 9), proc, fill=TEXT_WHITE, font=f_body)
        
        # Health badge
        draw.rounded_rectangle([(ag_x[6], ry + 6), (ag_x[6] + 85, ry + 28)], radius=3, fill=col)
        draw.text((ag_x[6] + 12, ry + 8), stat, fill="#0F172A", font=f_badge)

    img.save("grafana_agent_activity.png")
    print("Saved grafana_agent_activity.png")

if __name__ == "__main__":
    render_system_logs()
    render_firewall_mitigation()
    render_agent_activity()
