"""
IP Threat Scanner v1.0
Created by Magdy Elkhouly

Scan IP addresses using VirusTotal and AbuseIPDB APIs
Supports multiple API keys with automatic rotation
Handles IPv4 and IPv6 addresses
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk
import threading
import requests
import json
import webbrowser
import csv
import re
from datetime import datetime
import os
import time

# Appearance settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Country codes to names
COUNTRY_NAMES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola",
    "AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BH": "Bahrain", "BD": "Bangladesh", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize",
    "BJ": "Benin", "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia", "BW": "Botswana",
    "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
    "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "CF": "Central African Rep.",
    "TD": "Chad", "CL": "Chile", "CN": "China", "CO": "Colombia", "KM": "Comoros",
    "CG": "Congo", "CD": "DR Congo", "CR": "Costa Rica", "CI": "Ivory Coast", "HR": "Croatia",
    "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti",
    "DO": "Dominican Rep.", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Eq. Guinea",
    "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FJ": "Fiji", "FI": "Finland",
    "FR": "France", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GR": "Greece", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau",
    "GY": "Guyana", "HT": "Haiti", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary",
    "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan",
    "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau",
    "MK": "North Macedonia", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
    "ML": "Mali", "MT": "Malta", "MR": "Mauritania", "MU": "Mauritius", "MX": "Mexico",
    "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MA": "Morocco",
    "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NP": "Nepal", "NL": "Netherlands",
    "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "KP": "North Korea",
    "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PS": "Palestine", "PA": "Panama",
    "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PL": "Poland",
    "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RO": "Romania", "RU": "Russia",
    "RW": "Rwanda", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia", "SC": "Seychelles",
    "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SO": "Somalia",
    "ZA": "South Africa", "KR": "South Korea", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SZ": "Eswatini", "SE": "Sweden", "CH": "Switzerland",
    "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
    "TL": "Timor-Leste", "TG": "Togo", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan",
    "UG": "Uganda", "UA": "Ukraine", "AE": "UAE", "GB": "United Kingdom", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen",
    "ZM": "Zambia", "ZW": "Zimbabwe", "EU": "Europe", "AP": "Asia Pacific", "A1": "Anonymous Proxy",
    "A2": "Satellite", "O1": "Other", "XX": "Unknown"
}

class IPScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window settings
        self.title("🛡️ IP Threat Scanner v1.0 - By Magdy Elkhouly")
        self.geometry("1300x850")
        self.minsize(1100, 750)
        
        # Colors
        self.colors = {
            'bg_dark': '#0a0e17',
            'bg_card': '#1a2234',
            'bg_input': '#0f1419',
            'accent_cyan': '#00f0ff',
            'accent_green': '#00ff88',
            'accent_red': '#ff4757',
            'accent_yellow': '#ffd93d',
            'accent_purple': '#a855f7',
            'accent_orange': '#ff9f43',
            'text_primary': '#e2e8f0',
            'text_secondary': '#94a3b8',
            'border': '#2d3a4f',
        }
        
        self.configure(fg_color=self.colors['bg_dark'])
        
        # Variables
        self.scan_results = []
        self.is_scanning = False
        self.is_paused = False
        self.stop_scan = False
        
        # API Keys (lists for multiple keys)
        self.vt_api_keys = []
        self.abuse_api_keys = []
        self.current_vt_index = 0
        self.current_abuse_index = 0
        
        # Create UI
        self.create_widgets()
        self.load_api_keys()
        self.update_api_status()
        
    def create_widgets(self):
        # Main frame
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.create_header()
        
        # Content frame
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        
        # Left panel
        self.left_frame = ctk.CTkFrame(self.content_frame, fg_color=self.colors['bg_card'], corner_radius=15, width=450)
        self.left_frame.pack(side="left", fill="both", padx=(0, 10))
        self.left_frame.pack_propagate(False)
        
        # Right panel
        self.right_frame = ctk.CTkFrame(self.content_frame, fg_color=self.colors['bg_card'], corner_radius=15)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))
        
        self.create_input_section()
        self.create_results_section()
        self.create_footer()
    
    def create_footer(self):
        """Create footer with author info"""
        footer_frame = ctk.CTkFrame(self, fg_color=self.colors['bg_card'], height=35, corner_radius=0)
        footer_frame.pack(fill="x", side="bottom")
        footer_frame.pack_propagate(False)
        
        footer_label = ctk.CTkLabel(
            footer_frame,
            text="🛡️ IP Threat Scanner v1.0  •  Created by Magdy Elkhouly  •  Security Tool",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['text_secondary']
        )
        footer_label.pack(expand=True)
        """Create footer with author info"""
        footer_frame = ctk.CTkFrame(self, fg_color=self.colors['bg_card'], height=35, corner_radius=0)
        footer_frame.pack(fill="x", side="bottom")
        footer_frame.pack_propagate(False)
        
        footer_label = ctk.CTkLabel(
            footer_frame,
            text="🛡️ IP Threat Scanner v1.0  •  Created by Magdy Elkhouly  •  Security Tool",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['text_secondary']
        )
        footer_label.pack(expand=True)
        
    def create_header(self):
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=80)
        header_frame.pack(fill="x", pady=(0, 20))
        header_frame.pack_propagate(False)
        
        # Icon and title
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(side="left")
        
        icon_label = ctk.CTkLabel(title_frame, text="🛡️", font=ctk.CTkFont(size=40))
        icon_label.pack(side="left", padx=(0, 15))
        
        text_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        text_frame.pack(side="left")
        
        title_label = ctk.CTkLabel(
            text_frame, text="IP Threat Scanner",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=self.colors['accent_cyan']
        )
        title_label.pack(anchor="w")
        
        subtitle_label = ctk.CTkLabel(
            text_frame, text="Scan IPv4 & IPv6 using VirusTotal & AbuseIPDB",
            font=ctk.CTkFont(size=14),
            text_color=self.colors['text_secondary']
        )
        subtitle_label.pack(anchor="w")
        
        author_label = ctk.CTkLabel(
            text_frame, text="Created by Magdy Elkhouly",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['accent_purple']
        )
        author_label.pack(anchor="w")
        
        # API frame
        api_frame = ctk.CTkFrame(header_frame, fg_color=self.colors['bg_card'], corner_radius=10)
        api_frame.pack(side="right", padx=5, pady=5)
        
        self.api_status_label = ctk.CTkLabel(
            api_frame, text="🔑 No API Keys configured",
            font=ctk.CTkFont(size=12),
            text_color=self.colors['accent_yellow']
        )
        self.api_status_label.pack(pady=(10, 5), padx=15)
        
        settings_btn = ctk.CTkButton(
            api_frame, text="⚙️ Manage API Keys",
            width=160, height=35,
            fg_color=self.colors['accent_purple'],
            hover_color="#9333ea",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.show_api_settings
        )
        settings_btn.pack(pady=(0, 10), padx=15)
        
    def create_input_section(self):
        # Title
        input_title = ctk.CTkLabel(
            self.left_frame, text="📝 Input IP Addresses",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=self.colors['accent_cyan']
        )
        input_title.pack(pady=(20, 15), padx=20, anchor="w")
        
        # Input area
        self.ip_textbox = ctk.CTkTextbox(
            self.left_frame, height=180,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=self.colors['bg_input'],
            border_width=1, border_color=self.colors['border'],
            corner_radius=10
        )
        self.ip_textbox.pack(fill="x", padx=20, pady=(0, 10))
        self.ip_textbox.insert("1.0", "# Enter IPs - IPv4 & IPv6 supported\n# Examples:\n8.8.8.8\n2001:4860:4860::8888\n1.1.1.1\n")
        
        # File buttons
        file_btn_frame = ctk.CTkFrame(self.left_frame, fg_color="transparent")
        file_btn_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        load_btn = ctk.CTkButton(
            file_btn_frame, text="📁 Load File",
            width=110, height=35,
            fg_color=self.colors['bg_input'],
            border_width=1, border_color=self.colors['accent_purple'],
            hover_color=self.colors['accent_purple'],
            command=self.load_file
        )
        load_btn.pack(side="left", padx=(0, 10))
        
        clear_btn = ctk.CTkButton(
            file_btn_frame, text="🗑️ Clear",
            width=80, height=35,
            fg_color=self.colors['bg_input'],
            border_width=1, border_color=self.colors['accent_red'],
            hover_color=self.colors['accent_red'],
            command=self.clear_input
        )
        clear_btn.pack(side="left")
        
        self.ip_count_label = ctk.CTkLabel(
            file_btn_frame, text="IPs: 0",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['text_secondary']
        )
        self.ip_count_label.pack(side="right")
        
        self.ip_textbox.bind("<KeyRelease>", self.update_ip_count)
        
        # Progress bar
        progress_frame = ctk.CTkFrame(self.left_frame, fg_color="transparent")
        progress_frame.pack(fill="x", padx=20, pady=(5, 10))
        
        self.progress_bar = ctk.CTkProgressBar(
            progress_frame, height=12, corner_radius=6,
            fg_color=self.colors['bg_input'],
            progress_color=self.colors['accent_cyan']
        )
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(
            progress_frame, text="",
            font=ctk.CTkFont(size=12),
            text_color=self.colors['text_secondary']
        )
        self.progress_label.pack(pady=(5, 0))
        
        # Scan controls
        scan_controls_frame = ctk.CTkFrame(self.left_frame, fg_color=self.colors['bg_input'], corner_radius=10)
        scan_controls_frame.pack(fill="x", padx=20, pady=(5, 15))
        
        # Main scan button
        self.scan_btn = ctk.CTkButton(
            scan_controls_frame, text="🔍 Start Scan",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=self.colors['accent_cyan'],
            hover_color=self.colors['accent_green'],
            text_color=self.colors['bg_dark'],
            command=self.start_scan
        )
        self.scan_btn.pack(fill="x", padx=15, pady=(15, 10))
        
        # Control buttons
        control_btn_frame = ctk.CTkFrame(scan_controls_frame, fg_color="transparent")
        control_btn_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.pause_btn = ctk.CTkButton(
            control_btn_frame, text="⏸️ Pause",
            width=130, height=40,
            fg_color=self.colors['accent_orange'],
            hover_color="#e08e2b",
            text_color=self.colors['bg_dark'],
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled",
            command=self.toggle_pause
        )
        self.pause_btn.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        self.stop_btn = ctk.CTkButton(
            control_btn_frame, text="⏹️ Stop",
            width=100, height=40,
            fg_color=self.colors['accent_red'],
            hover_color="#cc3a47",
            text_color="white",
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled",
            command=self.stop_scanning
        )
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(5, 5))
        
        self.reset_btn = ctk.CTkButton(
            control_btn_frame, text="🔄 Reset",
            width=100, height=40,
            fg_color=self.colors['bg_card'],
            border_width=1, border_color=self.colors['accent_cyan'],
            hover_color=self.colors['accent_cyan'],
            text_color=self.colors['accent_cyan'],
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.reset_scan
        )
        self.reset_btn.pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        # Statistics
        stats_frame = ctk.CTkFrame(self.left_frame, fg_color=self.colors['bg_input'], corner_radius=10)
        stats_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        stats_title = ctk.CTkLabel(
            stats_frame, text="📊 Statistics",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors['text_primary']
        )
        stats_title.pack(pady=(12, 8))
        
        # Separator line
        sep1 = ctk.CTkFrame(stats_frame, fg_color=self.colors['border'], height=1)
        sep1.pack(fill="x", padx=15)
        
        # Stats list
        stats_list = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_list.pack(fill="x", padx=20, pady=10)
        
        # Safe row
        safe_row = ctk.CTkFrame(stats_list, fg_color="transparent")
        safe_row.pack(fill="x", pady=3)
        ctk.CTkLabel(
            safe_row, text="✓ Safe",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['accent_green']
        ).pack(side="left")
        self.safe_count = ctk.CTkLabel(
            safe_row, text="0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.colors['accent_green']
        )
        self.safe_count.pack(side="right")
        
        # Suspicious row
        warning_row = ctk.CTkFrame(stats_list, fg_color="transparent")
        warning_row.pack(fill="x", pady=3)
        ctk.CTkLabel(
            warning_row, text="⚠ Suspicious",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['accent_yellow']
        ).pack(side="left")
        self.warning_count = ctk.CTkLabel(
            warning_row, text="0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.colors['accent_yellow']
        )
        self.warning_count.pack(side="right")
        
        # Malicious row
        danger_row = ctk.CTkFrame(stats_list, fg_color="transparent")
        danger_row.pack(fill="x", pady=3)
        ctk.CTkLabel(
            danger_row, text="✗ Malicious",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['accent_red']
        ).pack(side="left")
        self.danger_count = ctk.CTkLabel(
            danger_row, text="0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.colors['accent_red']
        )
        self.danger_count.pack(side="right")
        
        # Private row
        private_row = ctk.CTkFrame(stats_list, fg_color="transparent")
        private_row.pack(fill="x", pady=3)
        ctk.CTkLabel(
            private_row, text="🏠 Private",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['text_secondary']
        ).pack(side="left")
        self.private_count = ctk.CTkLabel(
            private_row, text="0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=self.colors['text_secondary']
        )
        self.private_count.pack(side="right")
        
        # Separator line
        sep2 = ctk.CTkFrame(stats_frame, fg_color=self.colors['border'], height=1)
        sep2.pack(fill="x", padx=15, pady=(5, 0))
        
        # Total row
        total_row = ctk.CTkFrame(stats_frame, fg_color="transparent")
        total_row.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(
            total_row, text="Total",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors['text_primary']
        ).pack(side="left")
        self.total_count = ctk.CTkLabel(
            total_row, text="0",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.colors['accent_cyan']
        )
        self.total_count.pack(side="right")
        
        # Current API info
        api_info_frame = ctk.CTkFrame(self.left_frame, fg_color=self.colors['bg_input'], corner_radius=10)
        api_info_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.current_api_label = ctk.CTkLabel(
            api_info_frame, text="🔑 API: Inactive",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['text_secondary']
        )
        self.current_api_label.pack(pady=10)
        
    def create_results_section(self):
        # Header
        header_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        results_title = ctk.CTkLabel(
            header_frame, text="📋 Results",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=self.colors['accent_cyan']
        )
        results_title.pack(side="left")
        
        export_btn = ctk.CTkButton(
            header_frame, text="📥 Export CSV",
            width=120, height=35,
            fg_color=self.colors['accent_purple'],
            hover_color="#9333ea",
            command=self.export_results
        )
        export_btn.pack(side="right")
        
        # Filter section
        filter_frame = ctk.CTkFrame(self.right_frame, fg_color=self.colors['bg_input'], corner_radius=10)
        filter_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        filter_inner = ctk.CTkFrame(filter_frame, fg_color="transparent")
        filter_inner.pack(pady=10)
        
        filter_label = ctk.CTkLabel(
            filter_inner, text="🔍 Filter:",
            font=ctk.CTkFont(size=13),
            text_color=self.colors['text_secondary']
        )
        filter_label.pack(side="left", padx=(10, 15))
        
        self.filter_var = ctk.StringVar(value="all")
        
        filter_buttons = [
            ("All", "all", self.colors['accent_cyan']),
            ("✓ Safe", "safe", self.colors['accent_green']),
            ("⚠ Suspicious", "warning", self.colors['accent_yellow']),
            ("✗ Malicious", "danger", self.colors['accent_red']),
            ("🏠 Private", "private", self.colors['text_secondary']),
        ]
        
        self.filter_btns = {}
        for text, value, color in filter_buttons:
            btn = ctk.CTkButton(
                filter_inner, text=text,
                width=85, height=32,
                fg_color=color if value == "all" else "transparent",
                border_width=1, border_color=color,
                hover_color=color,
                text_color=self.colors['bg_dark'] if value == "all" else color,
                font=ctk.CTkFont(size=10, weight="bold"),
                command=lambda v=value: self.apply_filter(v)
            )
            btn.pack(side="left", padx=2)
            self.filter_btns[value] = (btn, color)
        
        self.search_var = ctk.StringVar()
        self.search_var.trace("w", lambda *args: self.apply_filter(self.filter_var.get()))
        
        search_entry = ctk.CTkEntry(
            filter_inner, width=140, height=32,
            placeholder_text="🔎 Search...",
            fg_color=self.colors['bg_card'],
            border_color=self.colors['border'],
            font=ctk.CTkFont(family="Consolas", size=11),
            textvariable=self.search_var
        )
        search_entry.pack(side="left", padx=(15, 10))
        
        self.results_count_label = ctk.CTkLabel(
            filter_inner, text="",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['text_secondary']
        )
        self.results_count_label.pack(side="left", padx=5)
        
        # Results table
        table_frame = ctk.CTkFrame(self.right_frame, fg_color=self.colors['bg_input'], corner_radius=10)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Treeview Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Custom.Treeview",
            background=self.colors['bg_input'],
            foreground=self.colors['text_primary'],
            fieldbackground=self.colors['bg_input'],
            borderwidth=0,
            font=('Consolas', 10),
            rowheight=35
        )
        style.configure(
            "Custom.Treeview.Heading",
            background=self.colors['bg_card'],
            foreground=self.colors['accent_cyan'],
            font=('Segoe UI', 10, 'bold'),
            borderwidth=0
        )
        style.map("Custom.Treeview",
            background=[('selected', self.colors['accent_purple'])],
            foreground=[('selected', 'white')]
        )
        
        columns = ("ip", "vt_score", "abuse_score", "country", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Custom.Treeview")
        
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("vt_score", text="VirusTotal")
        self.tree.heading("abuse_score", text="AbuseIPDB")
        self.tree.heading("country", text="Country")
        self.tree.heading("status", text="Status")
        
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("vt_score", width=100, anchor="center")
        self.tree.column("abuse_score", width=100, anchor="center")
        self.tree.column("country", width=120, anchor="center")
        self.tree.column("status", width=100, anchor="center")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        
        self.tree.bind("<Double-1>", self.on_row_double_click)
        
        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0, bg=self.colors['bg_card'], fg=self.colors['text_primary'])
        self.context_menu.add_command(label="🌐 Open in Both Sites", command=self.open_both_sites)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🦠 Open in VirusTotal", command=self.open_virustotal)
        self.context_menu.add_command(label="🚨 Open in AbuseIPDB", command=self.open_abuseipdb)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy IP", command=self.copy_ip)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        # Hint
        hint_label = ctk.CTkLabel(
            self.right_frame,
            text="💡 Double-click IP to open in both sites | Right-click for more options",
            font=ctk.CTkFont(size=11),
            text_color=self.colors['text_secondary']
        )
        hint_label.pack(pady=(0, 10))

    # ===== IP Parsing & Cleaning =====
    def is_valid_ipv4(self, ip):
        """Validate IPv4 address"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if pattern.match(ip):
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        return False
    
    def is_valid_ipv6(self, ip):
        """Validate IPv6 address"""
        # Remove zone ID if present (e.g., %eth0)
        ip = ip.split('%')[0]
        
        # IPv6 patterns
        # Full form: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        # Compressed: 2001:db8:85a3::8a2e:370:7334
        # Loopback: ::1
        # IPv4-mapped: ::ffff:192.168.1.1
        
        try:
            import ipaddress
            ipaddress.IPv6Address(ip)
            return True
        except:
            pass
        
        # Manual validation if ipaddress module fails
        # Check for :: (zero compression)
        if ':::' in ip:
            return False
        
        # Count ::
        double_colon_count = ip.count('::')
        if double_colon_count > 1:
            return False
        
        # Split by :
        if '::' in ip:
            parts = ip.split('::')
            left = parts[0].split(':') if parts[0] else []
            right = parts[1].split(':') if parts[1] else []
            
            # Check for IPv4-mapped addresses
            if right and '.' in right[-1]:
                if not self.is_valid_ipv4(right[-1]):
                    return False
                right = right[:-1]
                total_parts = len(left) + len(right) + 2  # +2 for IPv4 (counts as 2)
            else:
                total_parts = len(left) + len(right)
            
            if total_parts > 8:
                return False
            
            all_parts = left + right
        else:
            parts = ip.split(':')
            
            # Check for IPv4-mapped
            if '.' in parts[-1]:
                if not self.is_valid_ipv4(parts[-1]):
                    return False
                if len(parts) != 7:
                    return False
                all_parts = parts[:-1]
            else:
                if len(parts) != 8:
                    return False
                all_parts = parts
        
        # Validate each part is valid hex (0-ffff)
        for part in all_parts:
            if not part:
                continue
            if len(part) > 4:
                return False
            try:
                val = int(part, 16)
                if val < 0 or val > 0xffff:
                    return False
            except ValueError:
                return False
        
        return True
    
    def is_valid_ip(self, ip):
        """Validate IPv4 or IPv6 address"""
        return self.is_valid_ipv4(ip) or self.is_valid_ipv6(ip)
    
    def is_private_ip(self, ip):
        """Check if IP is private/reserved (not publicly routable)"""
        # Try using ipaddress module first
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_reserved or 
                ip_obj.is_link_local or
                ip_obj.is_multicast
            )
        except:
            pass
        
        # Manual check for IPv4
        if self.is_valid_ipv4(ip):
            parts = [int(p) for p in ip.split('.')]
            
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            # 127.0.0.0/8 (loopback)
            if parts[0] == 127:
                return True
            
            # 169.254.0.0/16 (link-local)
            if parts[0] == 169 and parts[1] == 254:
                return True
            
            # 0.0.0.0/8
            if parts[0] == 0:
                return True
            
            # 100.64.0.0/10 (Carrier-grade NAT)
            if parts[0] == 100 and 64 <= parts[1] <= 127:
                return True
            
            # 192.0.0.0/24 (IETF Protocol Assignments)
            if parts[0] == 192 and parts[1] == 0 and parts[2] == 0:
                return True
            
            # 192.0.2.0/24 (TEST-NET-1)
            if parts[0] == 192 and parts[1] == 0 and parts[2] == 2:
                return True
            
            # 198.51.100.0/24 (TEST-NET-2)
            if parts[0] == 198 and parts[1] == 51 and parts[2] == 100:
                return True
            
            # 203.0.113.0/24 (TEST-NET-3)
            if parts[0] == 203 and parts[1] == 0 and parts[2] == 113:
                return True
            
            # 224.0.0.0/4 (Multicast)
            if 224 <= parts[0] <= 239:
                return True
            
            # 240.0.0.0/4 (Reserved)
            if 240 <= parts[0] <= 255:
                return True
        
        # Manual check for IPv6
        if self.is_valid_ipv6(ip):
            ip_lower = ip.lower()
            
            # ::1 (loopback)
            if ip_lower == '::1' or ip_lower == '0:0:0:0:0:0:0:1':
                return True
            
            # fe80::/10 (link-local)
            if ip_lower.startswith('fe8') or ip_lower.startswith('fe9') or \
               ip_lower.startswith('fea') or ip_lower.startswith('feb'):
                return True
            
            # fc00::/7 (unique local - ULA)
            if ip_lower.startswith('fc') or ip_lower.startswith('fd'):
                return True
            
            # ff00::/8 (multicast)
            if ip_lower.startswith('ff'):
                return True
            
            # :: (unspecified)
            if ip_lower == '::' or ip_lower == '0:0:0:0:0:0:0:0':
                return True
        
        return False
    
    def get_country_name(self, country_code):
        """Convert country code to full country name"""
        if not country_code or country_code == "N/A" or country_code == "-":
            return "Unknown"
        
        code = country_code.upper().strip()
        return COUNTRY_NAMES.get(code, country_code)
    
    def parse_and_clean_ips(self, text):
        """
        Parse and clean IP addresses from various input formats:
        - One IP per line
        - Comma-separated
        - JSON array format
        - With quotes, brackets, null values
        - Supports both IPv4 and IPv6
        """
        ips = []
        
        # Remove common JSON/array characters and clean up
        cleaned = text
        
        # Remove brackets, quotes, null, and other JSON artifacts
        cleaned = re.sub(r'[\[\]\{\}]', '', cleaned)
        cleaned = re.sub(r'null', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'["\']', '', cleaned)
        
        # Split by various delimiters (but be careful with IPv6 colons)
        # First split by newlines and commas
        lines = re.split(r'[\n\r]+', cleaned)
        
        for line in lines:
            # Split by comma and semicolon
            parts = re.split(r'[,;]+', line)
            
            for part in parts:
                # Clean whitespace
                ip = part.strip()
                
                # Skip empty, comments, or invalid
                if not ip or ip.startswith('#'):
                    continue
                
                # Validate IP (IPv4 or IPv6)
                if self.is_valid_ip(ip):
                    if ip not in ips:  # Avoid duplicates
                        ips.append(ip)
        
        return ips
    
    def get_ips(self):
        """Get cleaned IP list from input"""
        text = self.ip_textbox.get("1.0", "end")
        return self.parse_and_clean_ips(text)

    # ===== API Settings =====
    def show_api_settings(self):
        settings_window = ctk.CTkToplevel(self)
        settings_window.title("⚙️ API Key Management")
        settings_window.geometry("700x600")
        settings_window.configure(fg_color=self.colors['bg_dark'])
        settings_window.transient(self)
        settings_window.grab_set()
        
        # Center window
        settings_window.update_idletasks()
        x = (settings_window.winfo_screenwidth() - 700) // 2
        y = (settings_window.winfo_screenheight() - 600) // 2
        settings_window.geometry(f"700x600+{x}+{y}")
        
        # Scrollable Frame
        main_scroll = ctk.CTkScrollableFrame(settings_window, fg_color=self.colors['bg_card'], corner_radius=15)
        main_scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(
            main_scroll, text="🔑 Multiple API Keys Management",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=self.colors['accent_cyan']
        )
        title.pack(pady=(10, 5))
        
        note = ctk.CTkLabel(
            main_scroll,
            text="💡 Add multiple API keys - auto-switches when rate limit is reached",
            font=ctk.CTkFont(size=12),
            text_color=self.colors['accent_yellow']
        )
        note.pack(pady=(0, 20))
        
        # VirusTotal Section
        vt_frame = ctk.CTkFrame(main_scroll, fg_color=self.colors['bg_input'], corner_radius=12)
        vt_frame.pack(fill="x", pady=(0, 15))
        
        vt_header = ctk.CTkFrame(vt_frame, fg_color="transparent")
        vt_header.pack(fill="x", padx=15, pady=(15, 10))
        
        ctk.CTkLabel(
            vt_header, text="🦠 VirusTotal API Keys",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors['accent_cyan']
        ).pack(side="left")
        
        ctk.CTkButton(
            vt_header, text="🔗 Get API Key",
            width=120, height=30,
            fg_color="transparent", border_width=1,
            border_color=self.colors['accent_cyan'],
            text_color=self.colors['accent_cyan'],
            font=ctk.CTkFont(size=11),
            command=lambda: webbrowser.open("https://www.virustotal.com/gui/join-us")
        ).pack(side="right")
        
        self.vt_keys_frame = ctk.CTkFrame(vt_frame, fg_color="transparent")
        self.vt_keys_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        self.vt_entries = []
        for key in self.vt_api_keys if self.vt_api_keys else [""]:
            self.add_api_key_entry(self.vt_keys_frame, self.vt_entries, key)
        
        if not self.vt_entries:
            self.add_api_key_entry(self.vt_keys_frame, self.vt_entries, "")
        
        ctk.CTkButton(
            vt_frame, text="➕ Add VT Key",
            width=150, height=32,
            fg_color=self.colors['accent_green'],
            hover_color="#00cc6a",
            text_color=self.colors['bg_dark'],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.add_api_key_entry(self.vt_keys_frame, self.vt_entries, "")
        ).pack(pady=(0, 15))
        
        # AbuseIPDB Section
        abuse_frame = ctk.CTkFrame(main_scroll, fg_color=self.colors['bg_input'], corner_radius=12)
        abuse_frame.pack(fill="x", pady=(0, 15))
        
        abuse_header = ctk.CTkFrame(abuse_frame, fg_color="transparent")
        abuse_header.pack(fill="x", padx=15, pady=(15, 10))
        
        ctk.CTkLabel(
            abuse_header, text="🚨 AbuseIPDB API Keys",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors['accent_orange']
        ).pack(side="left")
        
        ctk.CTkButton(
            abuse_header, text="🔗 Get API Key",
            width=120, height=30,
            fg_color="transparent", border_width=1,
            border_color=self.colors['accent_orange'],
            text_color=self.colors['accent_orange'],
            font=ctk.CTkFont(size=11),
            command=lambda: webbrowser.open("https://www.abuseipdb.com/register")
        ).pack(side="right")
        
        self.abuse_keys_frame = ctk.CTkFrame(abuse_frame, fg_color="transparent")
        self.abuse_keys_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        self.abuse_entries = []
        for key in self.abuse_api_keys if self.abuse_api_keys else [""]:
            self.add_api_key_entry(self.abuse_keys_frame, self.abuse_entries, key)
        
        if not self.abuse_entries:
            self.add_api_key_entry(self.abuse_keys_frame, self.abuse_entries, "")
        
        ctk.CTkButton(
            abuse_frame, text="➕ Add Abuse Key",
            width=150, height=32,
            fg_color=self.colors['accent_orange'],
            hover_color="#e08e2b",
            text_color=self.colors['bg_dark'],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.add_api_key_entry(self.abuse_keys_frame, self.abuse_entries, "")
        ).pack(pady=(0, 15))
        
        # Save/Cancel buttons
        btn_frame = ctk.CTkFrame(main_scroll, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        ctk.CTkButton(
            btn_frame, text="💾 Save All Keys",
            width=180, height=45,
            fg_color=self.colors['accent_green'],
            hover_color="#00cc6a",
            text_color=self.colors['bg_dark'],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.save_all_api_keys(settings_window)
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            btn_frame, text="Cancel",
            width=100, height=45,
            fg_color="transparent", border_width=1,
            border_color=self.colors['text_secondary'],
            text_color=self.colors['text_secondary'],
            font=ctk.CTkFont(size=14),
            command=settings_window.destroy
        ).pack(side="left", padx=10)
    
    def add_api_key_entry(self, parent, entries_list, initial_value=""):
        entry_frame = ctk.CTkFrame(parent, fg_color="transparent")
        entry_frame.pack(fill="x", pady=3)
        
        entry = ctk.CTkEntry(
            entry_frame, height=38,
            fg_color=self.colors['bg_card'],
            border_color=self.colors['border'],
            font=ctk.CTkFont(family="Consolas", size=11),
            placeholder_text="Enter API key here..."
        )
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        if initial_value:
            entry.insert(0, initial_value)
        
        remove_btn = ctk.CTkButton(
            entry_frame, text="✕", width=35, height=38,
            fg_color=self.colors['accent_red'],
            hover_color="#cc3a47",
            command=lambda: self.remove_api_key_entry(entry_frame, entries_list)
        )
        remove_btn.pack(side="right")
        
        entries_list.append((entry_frame, entry))
    
    def remove_api_key_entry(self, frame, entries_list):
        if len(entries_list) > 1:
            for item in entries_list:
                if item[0] == frame:
                    entries_list.remove(item)
                    frame.destroy()
                    break
    
    def save_all_api_keys(self, window):
        # Collect VT keys
        self.vt_api_keys = []
        for _, entry in self.vt_entries:
            key = entry.get().strip()
            if key:
                self.vt_api_keys.append(key)
        
        # Collect Abuse keys
        self.abuse_api_keys = []
        for _, entry in self.abuse_entries:
            key = entry.get().strip()
            if key:
                self.abuse_api_keys.append(key)
        
        if not self.vt_api_keys and not self.abuse_api_keys:
            messagebox.showwarning("Warning", "Please enter at least one API key!")
            return
        
        # Reset indices
        self.current_vt_index = 0
        self.current_abuse_index = 0
        
        # Save to file
        config = {
            "vt_api_keys": self.vt_api_keys,
            "abuse_api_keys": self.abuse_api_keys
        }
        
        try:
            config_path = os.path.join(os.path.expanduser("~"), ".ip_scanner_config.json")
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            
            self.update_api_status()
            window.destroy()
            
            msg = f"API keys saved successfully!\n\n"
            msg += f"🦠 VirusTotal: {len(self.vt_api_keys)} key(s)\n"
            msg += f"🚨 AbuseIPDB: {len(self.abuse_api_keys)} key(s)"
            messagebox.showinfo("✅ Saved", msg)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys:\n{e}")
    
    def load_api_keys(self):
        self.vt_api_keys = []
        self.abuse_api_keys = []
        
        try:
            config_path = os.path.join(os.path.expanduser("~"), ".ip_scanner_config.json")
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                    if "vt_api_keys" in config:
                        self.vt_api_keys = config.get("vt_api_keys", [])
                    elif "vt_api_key" in config and config["vt_api_key"]:
                        self.vt_api_keys = [config["vt_api_key"]]
                    
                    if "abuse_api_keys" in config:
                        self.abuse_api_keys = config.get("abuse_api_keys", [])
                    elif "abuse_api_key" in config and config["abuse_api_key"]:
                        self.abuse_api_keys = [config["abuse_api_key"]]
        except:
            pass
    
    def update_api_status(self):
        parts = []
        if self.vt_api_keys:
            parts.append(f"VT: {len(self.vt_api_keys)} 🔑")
        if self.abuse_api_keys:
            parts.append(f"Abuse: {len(self.abuse_api_keys)} 🔑")
        
        if parts:
            self.api_status_label.configure(
                text=" | ".join(parts),
                text_color=self.colors['accent_green']
            )
        else:
            self.api_status_label.configure(
                text="🔑 No API Keys configured",
                text_color=self.colors['accent_yellow']
            )

    # ===== API Calls with Rotation =====
    def get_next_vt_key(self):
        if not self.vt_api_keys:
            return None
        return self.vt_api_keys[self.current_vt_index]
    
    def rotate_vt_key(self):
        if len(self.vt_api_keys) > 1:
            self.current_vt_index = (self.current_vt_index + 1) % len(self.vt_api_keys)
            return True
        return False
    
    def get_next_abuse_key(self):
        if not self.abuse_api_keys:
            return None
        return self.abuse_api_keys[self.current_abuse_index]
    
    def rotate_abuse_key(self):
        if len(self.abuse_api_keys) > 1:
            self.current_abuse_index = (self.current_abuse_index + 1) % len(self.abuse_api_keys)
            return True
        return False
    
    def check_virustotal(self, ip, retry_count=0):
        api_key = self.get_next_vt_key()
        if not api_key:
            return None
        
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": api_key},
                timeout=30
            )
            
            if response.status_code == 429:
                if retry_count < len(self.vt_api_keys) - 1 and self.rotate_vt_key():
                    self.after(0, self.update_current_api_label)
                    return self.check_virustotal(ip, retry_count + 1)
                return {"success": False, "error": "Rate limit reached"}
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values())
                
                return {
                    "success": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total": total,
                    "score": f"{malicious + suspicious}/{total}",
                    "country": data["data"]["attributes"].get("country", "N/A"),
                    "asn": data["data"]["attributes"].get("as_owner", "N/A")
                }
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def check_abuseipdb(self, ip, retry_count=0):
        api_key = self.get_next_abuse_key()
        if not api_key:
            return None
        
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=30
            )
            
            if response.status_code == 429:
                if retry_count < len(self.abuse_api_keys) - 1 and self.rotate_abuse_key():
                    self.after(0, self.update_current_api_label)
                    return self.check_abuseipdb(ip, retry_count + 1)
                return {"success": False, "error": "Rate limit reached"}
            
            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "success": True,
                    "score": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "isTor": data.get("isTor", False)
                }
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_current_api_label(self):
        vt_info = f"VT: {self.current_vt_index + 1}/{len(self.vt_api_keys)}" if self.vt_api_keys else "VT: -"
        abuse_info = f"Abuse: {self.current_abuse_index + 1}/{len(self.abuse_api_keys)}" if self.abuse_api_keys else "Abuse: -"
        self.current_api_label.configure(text=f"🔑 {vt_info} | {abuse_info}")

    # ===== Scan Controls =====
    def start_scan(self):
        if self.is_scanning:
            return
        
        ips = self.get_ips()
        
        if not ips:
            messagebox.showwarning("Warning", "No valid IP addresses found!\n\nSupported formats:\n• IPv4: 8.8.8.8\n• IPv6: 2001:4860:4860::8888\n• Comma-separated or one per line\n• JSON array format")
            return
        
        if not self.vt_api_keys and not self.abuse_api_keys:
            messagebox.showwarning("Warning", "Please configure at least one API key")
            self.show_api_settings()
            return
        
        self.is_scanning = True
        self.is_paused = False
        self.stop_scan = False
        self.scan_results = []
        
        # Update buttons
        self.scan_btn.configure(text="⏳ Scanning...", state="disabled")
        self.pause_btn.configure(state="normal", text="⏸️ Pause")
        self.stop_btn.configure(state="normal")
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.update_current_api_label()
        
        thread = threading.Thread(target=self.scan_ips, args=(ips,), daemon=True)
        thread.start()
    
    def toggle_pause(self):
        if self.is_paused:
            self.is_paused = False
            self.pause_btn.configure(text="⏸️ Pause", fg_color=self.colors['accent_orange'])
            self.progress_label.configure(text="Resuming scan...")
        else:
            self.is_paused = True
            self.pause_btn.configure(text="▶️ Resume", fg_color=self.colors['accent_green'])
            self.progress_label.configure(text="⏸️ Paused...")
    
    def stop_scanning(self):
        self.stop_scan = True
        self.is_paused = False
        self.progress_label.configure(text="Stopping...")
    
    def reset_scan(self):
        self.stop_scan = True
        self.is_paused = False
        self.is_scanning = False
        self.scan_results = []
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.scan_btn.configure(text="🔍 Start Scan", state="normal")
        self.pause_btn.configure(state="disabled", text="⏸️ Pause", fg_color=self.colors['accent_orange'])
        self.stop_btn.configure(state="disabled")
        
        self.progress_bar.set(0)
        self.progress_label.configure(text="")
        self.safe_count.configure(text="0")
        self.warning_count.configure(text="0")
        self.danger_count.configure(text="0")
        self.private_count.configure(text="0")
        self.total_count.configure(text="0")
        self.results_count_label.configure(text="")
        self.current_api_label.configure(text="🔑 API: Inactive")
    
    def scan_ips(self, ips):
        total = len(ips)
        
        for i, ip in enumerate(ips):
            if self.stop_scan:
                break
            
            while self.is_paused and not self.stop_scan:
                time.sleep(0.2)
            
            if self.stop_scan:
                break
            
            progress = (i + 1) / total
            self.after(0, lambda p=progress, c=i+1, t=total: self.update_progress(p, c, t))
            
            # Check if private IP - skip scanning
            if self.is_private_ip(ip):
                result = {
                    "ip": ip,
                    "vt_result": None,
                    "abuse_result": None,
                    "status": "private",
                    "country": "Private"
                }
                self.scan_results.append(result)
                self.after(0, lambda r=result: self.add_table_row(r, "Private IP", "Private IP"))
                continue
            
            vt_result = self.check_virustotal(ip)
            abuse_result = self.check_abuseipdb(ip)
            
            status = self.get_status(vt_result, abuse_result)
            country_code = (vt_result.get("country") if vt_result and vt_result.get("success") else None) or \
                     (abuse_result.get("country") if abuse_result and abuse_result.get("success") else "N/A")
            country = self.get_country_name(country_code)
            
            result = {
                "ip": ip,
                "vt_result": vt_result,
                "abuse_result": abuse_result,
                "status": status,
                "country": country
            }
            self.scan_results.append(result)
            
            vt_score = vt_result["score"] if vt_result and vt_result.get("success") else "N/A"
            abuse_score = f"{abuse_result['score']}%" if abuse_result and abuse_result.get("success") else "N/A"
            
            self.after(0, lambda r=result, vs=vt_score, as_=abuse_score: self.add_table_row(r, vs, as_))
            
            if i < total - 1 and not self.stop_scan:
                time.sleep(1.5)
        
        self.after(0, self.scan_complete)
    
    def scan_complete(self):
        self.is_scanning = False
        self.is_paused = False
        self.scan_btn.configure(text="🔍 Start Scan", state="normal")
        self.pause_btn.configure(state="disabled", text="⏸️ Pause", fg_color=self.colors['accent_orange'])
        self.stop_btn.configure(state="disabled")
        
        if self.stop_scan:
            self.progress_label.configure(text="⏹️ Scan stopped")
        else:
            self.progress_label.configure(text="✓ Scan complete!")
            messagebox.showinfo("Complete", f"Scanned {len(self.scan_results)} IP addresses!")

    # ===== Helper Functions =====
    def get_status(self, vt_result, abuse_result):
        vt_score = 0
        abuse_score = 0
        
        if vt_result and vt_result.get("success"):
            vt_score = vt_result["malicious"] + vt_result["suspicious"]
        if abuse_result and abuse_result.get("success"):
            abuse_score = abuse_result["score"]
        
        if vt_score >= 5 or abuse_score >= 50:
            return "malicious"
        if vt_score > 0 or abuse_score >= 25:
            return "suspicious"
        return "safe"
    
    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.ip_textbox.delete("1.0", "end")
                    self.ip_textbox.insert("1.0", content)
                    self.update_ip_count()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file:\n{e}")
    
    def clear_input(self):
        self.ip_textbox.delete("1.0", "end")
        self.update_ip_count()
    
    def update_ip_count(self, event=None):
        ips = self.get_ips()
        self.ip_count_label.configure(text=f"IPs: {len(ips)}")
    
    def update_progress(self, progress, current, total):
        self.progress_bar.set(progress)
        status = "⏸️ Paused | " if self.is_paused else ""
        self.progress_label.configure(text=f"{status}Scanning... {current}/{total}")
        self.update_current_api_label()
    
    def add_table_row(self, result, vt_score, abuse_score):
        status_map = {
            "safe": "✓ Safe", 
            "suspicious": "⚠ Suspicious", 
            "malicious": "✗ Malicious",
            "private": "🏠 Private"
        }
        
        # Check current filter
        current_filter = self.filter_var.get()
        filter_status_map = {
            "safe": "safe", 
            "warning": "suspicious", 
            "danger": "malicious",
            "private": "private"
        }
        
        # Check search text
        search_text = self.search_var.get().strip().lower()
        
        # Determine if this result should be shown based on filter
        should_show = True
        
        if current_filter != "all":
            if result["status"] != filter_status_map.get(current_filter):
                should_show = False
        
        if search_text and should_show:
            if search_text not in result["ip"].lower() and search_text not in result.get("country", "").lower():
                should_show = False
        
        # Only add to tree if it matches the filter
        if should_show:
            self.tree.insert("", "end", values=(
                result["ip"],
                vt_score,
                abuse_score,
                result["country"],
                status_map.get(result["status"], result["status"])
            ))
        
        # Always update stats (for all results, not just filtered)
        self.update_stats()
        
        # Update results count
        self.update_results_count()
    
    def update_stats(self):
        safe = sum(1 for r in self.scan_results if r["status"] == "safe")
        warning = sum(1 for r in self.scan_results if r["status"] == "suspicious")
        danger = sum(1 for r in self.scan_results if r["status"] == "malicious")
        private = sum(1 for r in self.scan_results if r["status"] == "private")
        total = len(self.scan_results)
        
        self.safe_count.configure(text=str(safe))
        self.warning_count.configure(text=str(warning))
        self.danger_count.configure(text=str(danger))
        self.private_count.configure(text=str(private))
        self.total_count.configure(text=str(total))
    
    def update_results_count(self):
        """Update the results count label"""
        shown = len(self.tree.get_children())
        total = len(self.scan_results)
        if total == 0:
            self.results_count_label.configure(text="")
        elif shown == total:
            self.results_count_label.configure(text=f"({total} results)")
        else:
            self.results_count_label.configure(text=f"({shown} of {total})")
    
    def apply_filter(self, filter_type):
        self.filter_var.set(filter_type)
        
        for value, (btn, color) in self.filter_btns.items():
            if value == filter_type:
                btn.configure(fg_color=color, text_color=self.colors['bg_dark'])
            else:
                btn.configure(fg_color="transparent", text_color=color)
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        search_text = self.search_var.get().strip().lower()
        status_map = {
            "safe": "✓ Safe", 
            "suspicious": "⚠ Suspicious", 
            "malicious": "✗ Malicious",
            "private": "🏠 Private"
        }
        filter_status_map = {
            "safe": "safe", 
            "warning": "suspicious", 
            "danger": "malicious",
            "private": "private"
        }
        
        for r in self.scan_results:
            if filter_type != "all":
                if r["status"] != filter_status_map.get(filter_type):
                    continue
            
            if search_text:
                if search_text not in r["ip"].lower() and search_text not in r.get("country", "").lower():
                    continue
            
            # Handle Private IPs display
            if r["status"] == "private":
                vt_score = "Private IP"
                abuse_score = "Private IP"
            else:
                vt = r.get("vt_result") or {}
                abuse = r.get("abuse_result") or {}
                vt_score = vt.get("score", "N/A") if vt.get("success") else "N/A"
                abuse_score = f"{abuse.get('score', 'N/A')}%" if abuse.get("success") else "N/A"
            
            self.tree.insert("", "end", values=(
                r["ip"], vt_score, abuse_score,
                r["country"], status_map.get(r["status"], r["status"])
            ))
        
        self.update_results_count()
    
    def on_row_double_click(self, event):
        ip = self.get_selected_ip()
        if ip:
            # Check if private IP
            if self.is_private_ip(ip):
                messagebox.showinfo("Private IP", f"{ip} is a private/reserved IP address.\n\nPrivate IPs cannot be looked up on threat intelligence services.")
                return
            webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")
            webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def get_selected_ip(self):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            return item["values"][0]
        return None
    
    def open_virustotal(self):
        ip = self.get_selected_ip()
        if ip:
            if self.is_private_ip(ip):
                messagebox.showinfo("Private IP", f"{ip} is a private IP.\nCannot look up on VirusTotal.")
                return
            webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")
    
    def open_abuseipdb(self):
        ip = self.get_selected_ip()
        if ip:
            if self.is_private_ip(ip):
                messagebox.showinfo("Private IP", f"{ip} is a private IP.\nCannot look up on AbuseIPDB.")
                return
            webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
    
    def open_both_sites(self):
        ip = self.get_selected_ip()
        if ip:
            if self.is_private_ip(ip):
                messagebox.showinfo("Private IP", f"{ip} is a private/reserved IP address.\n\nPrivate IPs cannot be looked up on threat intelligence services.")
                return
            webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")
            webbrowser.open(f"https://www.abuseipdb.com/check/{ip}")
    
    def copy_ip(self):
        ip = self.get_selected_ip()
        if ip:
            self.clipboard_clear()
            self.clipboard_append(ip)
    
    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfilename=f"ip_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["IP", "VT_Malicious", "VT_Suspicious", "VT_Score", "Abuse_Score", "Country", "Status"])
                    
                    for r in self.scan_results:
                        if r["status"] == "private":
                            writer.writerow([
                                r["ip"],
                                "Private IP",
                                "Private IP",
                                "Private IP",
                                "Private IP",
                                "Private",
                                "private"
                            ])
                        else:
                            vt = r.get("vt_result") or {}
                            abuse = r.get("abuse_result") or {}
                            
                            writer.writerow([
                                r["ip"],
                                vt.get("malicious", "N/A") if vt.get("success") else "N/A",
                                vt.get("suspicious", "N/A") if vt.get("success") else "N/A",
                                vt.get("score", "N/A") if vt.get("success") else "N/A",
                                f"{abuse.get('score', 'N/A')}%" if abuse.get("success") else "N/A",
                                r["country"],
                                r["status"]
                            ])
                
                # Ask to open folder
                result = messagebox.askyesno(
                    "✅ Export Complete", 
                    f"Results saved to:\n{file_path}\n\nDo you want to open the folder?"
                )
                
                if result:
                    # Open folder and select file
                    folder_path = os.path.dirname(file_path)
                    if os.name == 'nt':  # Windows
                        os.system(f'explorer /select,"{file_path}"')
                    elif os.name == 'posix':  # Linux/Mac
                        os.system(f'xdg-open "{folder_path}"')
                        
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save:\n{e}")


def main():
    """Entry point for the application"""
    app = IPScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
