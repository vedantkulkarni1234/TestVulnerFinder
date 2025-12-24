"""
SOC-EATER v2 - Desktop GUI Application
Full-featured standalone desktop application for SOC analysis.
"""

from __future__ import annotations

import sys
import os
import json
import io
import threading
from datetime import datetime
from typing import Any, Optional
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QProgressBar,
    QFileDialog, QMessageBox, QDialog, QDialogButtonBox, QFormLayout,
    QTabWidget, QListWidget, QListWidgetItem, QGroupBox, QSplitter,
    QStatusBar, QMenuBar, QMenu, QToolBar, QFrame, QScrollArea,
    QGridLayout, QSizePolicy, QSpacerItem
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QObject, QThread, QTimer
from PyQt6.QtGui import (
    QAction, QIcon, QFont, QColor, QPalette, QTextCursor,
    QSyntaxHighlighter, QTextCharFormat, QPixmap, QImage,
    QGuiApplication, QScreen
)
from PyQt6.QtSvgWidgets import QSvgWidget

# Import core functionality
from soc_eater_v2.soc_brain import SOCBrain
from soc_eater_v2.utils.pcap_parser import summarize_pcap_bytes


class WorkerThread(QThread):
    """Worker thread for background analysis operations."""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class AnalysisWorker:
    """Wrapper for analysis operations to run in worker thread."""
    
    def __init__(self, brain: SOCBrain):
        self.brain = brain
    
    def analyze_text(self, prompt: str, context: Optional[dict] = None) -> dict:
        return self.brain.analyze_incident(prompt=prompt, context=context)
    
    def analyze_with_file(self, prompt: str, file_path: str) -> dict:
        """Analyze incident with optional file attachment (image or PCAP)."""
        images = None
        final_prompt = prompt
        
        lowered = file_path.lower()
        
        # Handle images
        if lowered.endswith((".png", ".jpg", ".jpeg", ".webp")):
            from PIL import Image
            img = Image.open(file_path).convert("RGB")
            images = [img]
        
        # Handle PCAP files
        elif lowered.endswith((".pcap", ".pcapng")):
            with open(file_path, "rb") as f:
                pcap_summary = summarize_pcap_bytes(f.read(), max_packets=4000)
            final_prompt = (
                f"{prompt}\n\n[PCAP SUMMARY]\n{pcap_summary}\n\n"
                "Use the PCAP SUMMARY to extract IOCs, timeline, and likely attack narrative."
            )
        
        return self.brain.analyze_incident(prompt=final_prompt, images=images)
    
    def run_playbook(self, playbook_name: str, incident_data: dict) -> dict:
        return self.brain.run_playbook(playbook_name, incident_data)


class SettingsDialog(QDialog):
    """Settings dialog for API key and preferences."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings - SOC-EATER v2")
        self.setMinimumWidth(500)
        self.resize(500, 300)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QFormLayout(self)
        
        # API Key
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Enter your Gemini API Key")
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setText(os.getenv("GEMINI_API_KEY", ""))
        layout.addRow("Gemini API Key:", self.api_key_edit)
        
        # API Key help
        help_label = QLabel(
            "<a href='https://ai.google.dev'>Get your free API key from Google AI Studio</a>"
        )
        help_label.setOpenExternalLinks(True)
        layout.addRow("", help_label)
        
        # Theme
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "System"])
        layout.addRow("Theme:", self.theme_combo)
        
        # Auto-save reports
        self.auto_save_check = QPushButton()
        self.auto_save_check.setCheckable(True)
        self.auto_save_check.setChecked(True)
        layout.addRow("Auto-save reports:", self.auto_save_check)
        
        # Default model
        self.model_label = QLabel("gemini-1.5-flash (1M token context)")
        layout.addRow("Model:", self.model_label)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    
    def get_settings(self) -> dict:
        return {
            "api_key": self.api_key_edit.text(),
            "theme": self.theme_combo.currentText().lower(),
            "auto_save": self.auto_save_check.isChecked()
        }


class PlaybookDialog(QDialog):
    """Dialog for selecting and running playbooks."""
    
    def __init__(self, brain: SOCBrain, parent=None):
        super().__init__(parent)
        self.brain = brain
        self.setWindowTitle("Security Playbooks - SOC-EATER v2")
        self.setMinimumWidth(600)
        self.resize(700, 500)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Playbook list
        self.playbook_list = QListWidget()
        self.playbook_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        
        playbooks = self.brain.list_playbooks()
        for pb in playbooks:
            item = QListWidgetItem(pb.replace("_", " ").title())
            item.setData(Qt.ItemDataRole.UserRole, pb)
            self.playbook_list.addItem(item)
        
        layout.addWidget(QLabel("Select a playbook to execute:"))
        layout.addWidget(self.playbook_list)
        
        # Incident data input
        layout.addWidget(QLabel("Incident Data (JSON):"))
        self.incident_data_edit = QTextEdit()
        self.incident_data_edit.setPlaceholderText('{"host": "WS-001", "user": "john.doe"}')
        self.incident_data_edit.setMaximumHeight(150)
        layout.addWidget(self.incident_data_edit)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_selected_playbook(self) -> tuple:
        item = self.playbook_list.currentItem()
        if not item:
            return None, None
        
        playbook_id = item.data(Qt.ItemDataRole.UserRole)
        
        # Parse incident data
        incident_data = {}
        try:
            text = self.incident_data_edit.toPlainText().strip()
            if text:
                incident_data = json.loads(text)
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "Invalid JSON", f"Failed to parse JSON: {e}")
            return None, None
        
        return playbook_id, incident_data


class ResultHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for analysis results."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Severity colors
        severity_formats = {
            "CRITICAL": QTextCharFormat(),
            "HIGH": QTextCharFormat(),
            "MEDIUM": QTextCharFormat(),
            "LOW": QTextCharFormat()
        }
        
        severity_formats["CRITICAL"].setForeground(QColor("#ff4444"))
        severity_formats["CRITICAL"].setFontWeight(QFont.Weight.Bold)
        
        severity_formats["HIGH"].setForeground(QColor("#ff6b6b"))
        severity_formats["HIGH"].setFontWeight(QFont.Weight.Bold)
        
        severity_formats["MEDIUM"].setForeground(QColor("#ffd93d"))
        severity_formats["MEDIUM"].setFontWeight(QFont.Weight.Bold)
        
        severity_formats["LOW"].setForeground(QColor("#6bcb77"))
        
        for severity, fmt in severity_formats.items():
            self.highlighting_rules.append((f"\\b{severity}\\b", fmt))
        
        # MITRE ATT&CK
        mitre_fmt = QTextCharFormat()
        mitre_fmt.setForeground(QColor("#00d4ff"))
        mitre_fmt.setFontFamily("monospace")
        self.highlighting_rules.append((r"T\d{4}(?:\.\d{3})?", mitre_fmt))
        
        # IPs
        ip_fmt = QTextCharFormat()
        ip_fmt.setForeground(QColor("#ff9f43"))
        self.highlighting_rules.append((r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip_fmt))
        
        # URLs
        url_fmt = QTextCharFormat()
        url_fmt.setForeground(QColor("#a29bfe"))
        url_fmt.setFontUnderline(True)
        self.highlighting_rules.append((r"https?://[^\s]+", url_fmt))
        
        # Code blocks
        code_fmt = QTextCharFormat()
        code_fmt.setFontFamily("monospace")
        code_fmt.setBackground(QColor("#2d2d2d"))
        self.highlighting_rules.append((r"```[\s\S]*?```", code_fmt))
    
    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            start = text.find(pattern)
            while start >= 0:
                length = len(text.match(pattern, start))
                self.setFormat(start, length, fmt)
                start = text.find(pattern, start + length)


class SOCEaterDesktop(QMainWindow):
    """Main desktop application window."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOC-EATER v2 - Security Operations Analysis")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        self.brain: Optional[SOCBrain] = None
        self.worker: Optional[AnalysisWorker] = None
        self.current_thread: Optional[QThread] = None
        self.uploaded_file: Optional[str] = None
        
        self.setup_theme()
        self.setup_ui()
        self.setup_menus()
        self.setup_toolbar()
        self.setup_statusbar()
        
        # Initialize brain with API key
        self.initialize_brain()
    
    def setup_theme(self):
        """Apply dark theme stylesheet."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
                font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
                font-size: 14px;
            }
            QMenuBar {
                background-color: #16213e;
                color: #e0e0e0;
                padding: 8px;
            }
            QMenuBar::item:selected {
                background-color: #0f3460;
            }
            QMenu {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #0f3460;
            }
            QMenu::item:selected {
                background-color: #0f3460;
            }
            QToolBar {
                background-color: #16213e;
                border: none;
                padding: 8px;
                spacing: 8px;
            }
            QToolButton {
                background-color: transparent;
                color: #e0e0e0;
                padding: 8px 12px;
                border-radius: 4px;
            }
            QToolButton:hover {
                background-color: #0f3460;
            }
            QStatusBar {
                background-color: #16213e;
                color: #a0a0a0;
            }
            QLabel {
                color: #b0b0b0;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #16213e;
                color: #e0e0e0;
                border: 2px solid #0f3460;
                border-radius: 6px;
                padding: 10px;
                selection-background-color: #0f3460;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #00d4ff;
            }
            QPushButton {
                background-color: #0f3460;
                color: #e0e0e0;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            QPushButton:pressed {
                background-color: #0a2a50;
            }
            QPushButton:disabled {
                background-color: #2a2a3e;
                color: #666;
            }
            QPushButton.primary {
                background-color: #00d4ff;
                color: #1a1a2e;
            }
            QPushButton.primary:hover {
                background-color: #00b8e6;
            }
            QGroupBox {
                background-color: #16213e;
                border: 2px solid #0f3460;
                border-radius: 8px;
                margin-top: 16px;
                padding-top: 16px;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: #00d4ff;
            }
            QListWidget {
                background-color: #16213e;
                border: 2px solid #0f3460;
                border-radius: 6px;
                color: #e0e0e0;
            }
            QListWidget::item:selected {
                background-color: #0f3460;
                color: #00d4ff;
            }
            QProgressBar {
                background-color: #16213e;
                border: 2px solid #0f3460;
                border-radius: 4px;
                text-align: center;
                color: #e0e0e0;
            }
            QProgressBar::chunk {
                background-color: #00d4ff;
                border-radius: 2px;
            }
            QTabWidget::pane {
                background-color: #16213e;
                border: 2px solid #0f3460;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #1a1a2e;
                color: #a0a0a0;
                padding: 10px 20px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #16213e;
                color: #00d4ff;
            }
            QScrollArea {
                background-color: transparent;
            }
            QDialog {
                background-color: #1a1a2e;
            }
        """)
    
    def setup_ui(self):
        """Set up the main user interface."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header
        self.create_header(main_layout)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_analyze_tab()
        self.create_playbooks_tab()
        self.create_history_tab()
        self.create_stats_tab()
    
    def create_header(self, layout: QVBoxLayout):
        """Create application header."""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0f3460, stop:1 #16213e
                );
                padding: 16px;
            }
        """)
        header_layout = QHBoxLayout(header)
        
        # Logo and title
        title_layout = QVBoxLayout()
        
        title = QLabel("SOC-EATER v2")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: 700;
            color: #00d4ff;
        """)
        title_layout.addWidget(title)
        
        subtitle = QLabel("AI-Powered Security Operations Center")
        subtitle.setStyleSheet("""
            font-size: 13px;
            color: #a0a0a0;
        """)
        title_layout.addWidget(subtitle)
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        # Status indicator
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("""
            font-size: 16px;
            color: #ff4444;
        """)
        header_layout.addWidget(self.status_indicator)
        
        self.status_label = QLabel("API Key Required")
        self.status_label.setStyleSheet("color: #ff6b6b; font-weight: 600;")
        header_layout.addWidget(self.status_label)
        
        layout.addWidget(header)
    
    def create_analyze_tab(self):
        """Create the main analysis tab."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Left panel - Input
        input_panel = QFrame()
        input_panel.setFixedWidth(400)
        input_layout = QVBoxLayout(input_panel)
        input_layout.setContentsMargins(0, 0, 0, 0)
        
        # Input group
        input_group = QGroupBox("Incident Input")
        input_group_layout = QVBoxLayout()
        
        # Quick templates
        template_combo = QComboBox()
        template_combo.addItems([
            "-- Select Template --",
            "Phishing Email Alert",
            "Suspicious PowerShell",
            "Malware Detection",
            "Lateral Movement",
            "Data Exfiltration",
            "Custom Incident"
        ])
        template_combo.currentTextChanged.connect(self.load_template)
        input_group_layout.addWidget(template_combo)
        
        # Input text area
        self.incident_input = QTextEdit()
        self.incident_input.setPlaceholderText(
            "Paste alert text, log entries, IOC list, or incident description...\n\n"
            "Example: Suspicious PowerShell execution detected on WS-001:\n"
            "powershell.exe -encodedCommand SQBFAFgAIAAoAE4AZQB3AC0A..."
        )
        self.incident_input.setMinimumHeight(300)
        input_group_layout.addWidget(self.incident_input)
        
        # File upload
        file_layout = QHBoxLayout()
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("color: #a0a0a0; font-style: italic;")
        file_layout.addWidget(self.file_path_label, stretch=1)
        
        self.upload_btn = QPushButton("📎")
        self.upload_btn.setFixedWidth(40)
        self.upload_btn.setToolTip("Attach file (image or PCAP)")
        self.upload_btn.clicked.connect(self.upload_file)
        file_layout.addWidget(self.upload_btn)
        
        self.clear_file_btn = QPushButton("✕")
        self.clear_file_btn.setFixedWidth(30)
        self.clear_file_btn.setToolTip("Clear file")
        self.clear_file_btn.clicked.connect(self.clear_file)
        file_layout.addWidget(self.clear_file_btn)
        
        input_group_layout.addLayout(file_layout)
        
        # Analyze button
        self.analyze_btn = QPushButton("🔍 Analyze Incident")
        self.analyze_btn.setProperty("class", "primary")
        self.analyze_btn.setMinimumHeight(50)
        self.analyze_btn.clicked.connect(self.analyze_incident)
        input_group_layout.addWidget(self.analyze_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        input_group_layout.addWidget(self.progress_bar)
        
        input_group.setLayout(input_group_layout)
        input_layout.addWidget(input_group)
        
        # Quick actions group
        quick_actions = QGroupBox("Quick Actions")
        quick_layout = QVBoxLayout()
        
        self.playbook_btn = QPushButton("📋 Run Playbook")
        self.playbook_btn.clicked.connect(self.open_playbook_dialog)
        quick_layout.addWidget(self.playbook_btn)
        
        quick_actions.setLayout(quick_layout)
        input_layout.addWidget(quick_actions)
        
        layout.addWidget(input_panel)
        
        # Right panel - Results
        results_panel = QFrame()
        results_layout = QVBoxLayout(results_panel)
        
        # Results group
        results_group = QGroupBox("Analysis Results")
        results_group_layout = QVBoxLayout()
        
        # Results text area with syntax highlighting
        self.results_text = QTextEdit()
        self.results_text.setPlaceholderText(
            "Analysis results will appear here...\n\n"
            "The report includes:\n"
            "• Executive Summary\n"
            "• Severity Assessment\n"
            "• MITRE ATT&CK Mapping\n"
            "• IOCs Extraction\n"
            "• Detection Queries (Splunk, Sentinel, Elastic)\n"
            "• Remediation Recommendations"
        )
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("SF Mono", 11))
        results_group_layout.addWidget(self.results_text)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        self.copy_btn = QPushButton("📋 Copy")
        self.copy_btn.clicked.connect(self.copy_results)
        action_layout.addWidget(self.copy_btn)
        
        self.export_btn = QPushButton("💾 Export")
        self.export_btn.clicked.connect(self.export_results)
        action_layout.addWidget(self.export_btn)
        
        self.clear_results_btn = QPushButton("🗑️ Clear")
        self.clear_results_btn.clicked.connect(self.clear_results)
        action_layout.addWidget(self.clear_results_btn)
        
        action_layout.addStretch()
        
        results_group_layout.addLayout(action_layout)
        results_group.setLayout(results_group_layout)
        results_layout.addWidget(results_group)
        
        layout.addWidget(results_panel)
        
        # Set stretch factors
        layout.setStretch(0, 1)  # Input panel
        layout.setStretch(1, 2)  # Results panel
        
        self.tabs.addTab(tab, "🔍 Analyze")
    
    def create_playbooks_tab(self):
        """Create the playbooks management tab."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Left - Playbook list
        left_panel = QFrame()
        left_panel.setFixedWidth(300)
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("<h3>Available Playbooks</h3>"))
        
        self.playbook_list = QListWidget()
        self.playbook_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        left_layout.addWidget(self.playbook_list)
        
        layout.addWidget(left_panel)
        
        # Right - Playbook details and execution
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Details group
        details_group = QGroupBox("Playbook Details")
        details_layout = QVBoxLayout()
        
        self.playbook_details = QTextEdit()
        self.playbook_details.setReadOnly(True)
        self.playbook_details.setMaximumHeight(200)
        details_layout.addWidget(self.playbook_details)
        
        details_group.setLayout(details_layout)
        right_layout.addWidget(details_group)
        
        # Execution group
        exec_group = QGroupBox("Execute Playbook")
        exec_layout = QVBoxLayout()
        
        exec_layout.addWidget(QLabel("Incident Data (JSON):"))
        self.playbook_incident_data = QTextEdit()
        self.playbook_incident_data.setPlaceholderText('{"host": "WS-001", "alert": "..."}')
        self.playbook_incident_data.setMaximumHeight(150)
        exec_layout.addWidget(self.playbook_incident_data)
        
        self.execute_playbook_btn = QPushButton("▶️ Execute Playbook")
        self.execute_playbook_btn.setProperty("class", "primary")
        self.execute_playbook_btn.clicked.connect(self.execute_selected_playbook)
        exec_layout.addWidget(self.execute_playbook_btn)
        
        exec_group.setLayout(exec_layout)
        right_layout.addWidget(exec_group)
        
        # Results area
        self.playbook_results = QTextEdit()
        self.playbook_results.setPlaceholderText("Playbook execution results will appear here...")
        self.playbook_results.setReadOnly(True)
        right_layout.addWidget(self.playbook_results)
        
        layout.addWidget(right_panel)
        layout.setStretch(0, 1)
        layout.setStretch(1, 2)
        
        self.tabs.addTab(tab, "📋 Playbooks")
    
    def create_history_tab(self):
        """Create analysis history tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.history_list = QListWidget()
        self.history_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.history_list)
        
        self.tabs.addTab(tab, "📜 History")
    
    def create_stats_tab(self):
        """Create statistics tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Stats grid
        stats_grid = QGridLayout()
        
        # Total analyses
        self.total_analyses_label = QLabel("0")
        self.total_analyses_label.setStyleSheet("""
            font-size: 48px;
            font-weight: 700;
            color: #00d4ff;
        """)
        stats_grid.addWidget(self.total_analyses_label, 0, 0)
        stats_grid.addWidget(QLabel("Total Analyses"), 1, 0)
        
        # Total tokens
        self.total_tokens_label = QLabel("0")
        self.total_tokens_label.setStyleSheet("""
            font-size: 48px;
            font-weight: 700;
            color: #00d4ff;
        """)
        stats_grid.addWidget(self.total_tokens_label, 0, 1)
        stats_grid.addWidget(QLabel("Total Tokens"), 1, 1)
        
        # Total cost USD
        self.total_cost_usd_label = QLabel("$0.00")
        self.total_cost_usd_label.setStyleSheet("""
            font-size: 48px;
            font-weight: 700;
            color: #00d4ff;
        """)
        stats_grid.addWidget(self.total_cost_usd_label, 0, 2)
        stats_grid.addWidget(QLabel("Total Cost (USD)"), 1, 2)
        
        # Total cost INR
        self.total_cost_inr_label = QLabel("₹0.00")
        self.total_cost_inr_label.setStyleSheet("""
            font-size: 48px;
            font-weight: 700;
            color: #00d4ff;
        """)
        stats_grid.addWidget(self.total_cost_inr_label, 0, 3)
        stats_grid.addWidget(QLabel("Total Cost (INR)"), 1, 3)
        
        # Average response time
        self.avg_response_label = QLabel("0.0s")
        self.avg_response_label.setStyleSheet("""
            font-size: 48px;
            font-weight: 700;
            color: #00d4ff;
        """)
        stats_grid.addWidget(self.avg_response_label, 2, 0)
        stats_grid.addWidget(QLabel("Avg Response Time"), 3, 0)
        
        stats_grid.setColumnStretch(0, 1)
        stats_grid.setColumnStretch(1, 1)
        stats_grid.setColumnStretch(2, 1)
        stats_grid.setColumnStretch(3, 1)
        
        layout.addLayout(stats_grid)
        layout.addStretch()
        
        self.tabs.addTab(tab, "📊 Statistics")
    
    def setup_menus(self):
        """Set up application menus."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Analysis", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_analysis)
        file_menu.addAction(new_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Report...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        playbook_action = QAction("Playbooks...", self)
        playbook_action.setShortcut("Ctrl+P")
        playbook_action.triggered.connect(self.open_playbook_dialog)
        tools_menu.addAction(playbook_action)
        
        tools_menu.addSeparator()
        
        settings_action = QAction("Settings...", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.open_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(self.open_docs)
        help_menu.addAction(docs_action)
    
    def setup_toolbar(self):
        """Set up application toolbar."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        new_btn = QPushButton("🆕 New")
        new_btn.clicked.connect(self.new_analysis)
        toolbar.addWidget(new_btn)
        
        analyze_btn = QPushButton("🔍 Analyze")
        analyze_btn.setProperty("class", "primary")
        analyze_btn.clicked.connect(self.analyze_incident)
        toolbar.addWidget(analyze_btn)
        
        toolbar.addSeparator()
        
        playbook_btn = QPushButton("📋 Playbooks")
        playbook_btn.clicked.connect(self.open_playbook_dialog)
        toolbar.addWidget(playbook_btn)
        
        toolbar.addSeparator()
        
        settings_btn = QPushButton("⚙️ Settings")
        settings_btn.clicked.connect(self.open_settings)
        toolbar.addWidget(settings_btn)
    
    def setup_statusbar(self):
        """Set up status bar."""
        self.statusBar().showMessage("Ready")
        self.statusBar().addPermanentWidget(QLabel("|"))
        self.statusBar().addPermanentWidget(QLabel("Model: gemini-1.5-flash"))
        self.statusBar().addPermanentWidget(QLabel("|"))
        self.statusBar().addPermanentWidget(QLabel("v2.0.0"))
    
    def initialize_brain(self):
        """Initialize the SOC Brain with API key."""
        api_key = os.getenv("GEMINI_API_KEY", "")
        
        if not api_key:
            # Show settings dialog on first launch
            self.statusBar().showMessage("API Key required - Please configure settings")
            QTimer.singleShot(500, self.open_settings)
            return
        
        try:
            self.brain = SOCBrain(api_key=api_key)
            self.worker = AnalysisWorker(self.brain)
            self.status_indicator.setText("●")
            self.status_indicator.setStyleSheet("font-size: 16px; color: #6bcb77;")
            self.status_label.setText("Connected")
            self.status_label.setStyleSheet("color: #6bcb77; font-weight: 600;")
            self.statusBar().showMessage("Connected to Gemini API")
            
            # Populate playbooks list
            self.refresh_playbooks()
            self.update_stats()
            
        except ValueError as e:
            self.status_indicator.setText("●")
            self.status_indicator.setStyleSheet("font-size: 16px; color: #ff6b6b;")
            self.status_label.setText("API Key Required")
            self.status_label.setStyleSheet("color: #ff6b6b; font-weight: 600;")
            self.statusBar().showMessage("API Key configuration required")
    
    def refresh_playbooks(self):
        """Refresh the playbooks list."""
        if not self.brain:
            return
        
        self.playbook_list.clear()
        playbooks = self.brain.list_playbooks()
        
        for pb in playbooks:
            item = QListWidgetItem(f"📋 {pb.replace('_', ' ').title()}")
            item.setData(Qt.ItemDataRole.UserRole, pb)
            self.playbook_list.addItem(item)
        
        # Connect selection change
        self.playbook_list.itemSelectionChanged.connect(self.on_playbook_selected)
    
    def update_stats(self):
        """Update statistics display."""
        if not self.brain:
            return
        
        stats = self.brain.get_stats()
        
        self.total_analyses_label.setText(str(stats.get("total_analyses", 0)))
        self.total_tokens_label.setText(f"{stats.get('total_tokens', 0):,}")
        self.total_cost_usd_label.setText(f"${stats.get('total_cost_usd', 0):.4f}")
        self.total_cost_inr_label.setText(f"₹{stats.get('total_cost_inr', 0):.2f}")
        self.avg_response_label.setText(f"{stats.get('avg_response_time', 0):.1f}s")
    
    def load_template(self, template_name: str):
        """Load a quick template into the input."""
        templates = {
            "Phishing Email Alert": """Phishing Email Detected
From: suspicious-sender@malicious-domain.com
Subject: URGENT: Wire Transfer Required
To: finance@company.com

The user reported receiving this email:

---
Dear Finance Team,

I need you to process an urgent wire transfer of $45,000 to the following account:

Bank: International Trade Bank
Account: 1234567890
Routing: 987654321

This is time-sensitive. Please process immediately and reply with confirmation.

Regards,
CEO John Smith
---

Indicators:
- Email domain doesn't match company's domain
- Request for urgent wire transfer
- No standard security protocols followed""",
            
            "Suspicious PowerShell": """Alert: Suspicious PowerShell Execution
Host: WS-001 (Workstation-001)
User: john.doe
Time: 2024-01-15 14:32:18 UTC

Process: powershell.exe -encodedCommand UwB0AGEAcgB0AC0AUABsAHIAZQBhAHQAZQBOAG8APQA3ADIA...

Parent Process: explorer.exe
Command Line: powershell.exe -encodedCommand <encoded payload>

Analysis:
- PowerShell launched with encoded command
- No command line logging bypass observed
- Process tree shows PowerShell spawned from explorer.exe
- Encoded payload needs decryption for full analysis""",
            
            "Malware Detection": """EDR Alert: Malware Detected
Host: SRV-DB-001
Alert ID: MAL-2024-0115-001
Severity: HIGH

File Path: C:\\Users\\admin\\Downloads\\invoice.exe
SHA256: 5e84f0a8b7d9c6e7f4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f
MD5: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

Behavior:
- Process injection into explorer.exe
- Network communication to 192.168.1.100:4444
- Registry persistence added
- Attempts to disable security software""",
            
            "Lateral Movement": """SIEM Alert: Lateral Movement Detected
Source Host: WS-HR-002
Destination Host: SRV-FILE-001
Time: 2024-01-15 22:45:12 UTC

Event: SMB Connection to Admin Share
Source IP: 192.168.10.45
Destination IP: 192.168.10.100
User: HR\\sarah.jones

Context:
- User is not normally active at this hour
- No scheduled maintenance tickets
- User's workstation was flagged for malware 2 days ago
- Connection to C$ and ADMIN$ shares"""
        }
        
        if template_name in templates:
            self.incident_input.setText(templates[template_name])
    
    def upload_file(self):
        """Open file dialog to upload evidence."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Evidence File",
            "",
            "All Files (*);;Images (*.png *.jpg *.jpeg *.webp);;PCAP Files (*.pcap *.pcapng)"
        )
        
        if file_path:
            self.uploaded_file = file_path
            filename = os.path.basename(file_path)
            
            # Determine file type
            lowered = file_path.lower()
            if lowered.endswith((".png", ".jpg", ".jpeg", ".webp")):
                file_type = "📷 Image"
            elif lowered.endswith((".pcap", ".pcapng")):
                file_type = "📦 PCAP"
            else:
                file_type = "📄 File"
            
            self.file_path_label.setText(f"{file_type} {filename}")
            self.file_path_label.setStyleSheet("color: #00d4ff; font-style: normal;")
    
    def clear_file(self):
        """Clear the uploaded file."""
        self.uploaded_file = None
        self.file_path_label.setText("No file selected")
        self.file_path_label.setStyleSheet("color: #a0a0a0; font-style: italic;")
    
    def analyze_incident(self):
        """Start incident analysis."""
        if not self.brain:
            QMessageBox.warning(self, "Error", "Please configure API key first")
            self.open_settings()
            return
        
        prompt = self.incident_input.toPlainText().strip()
        if not prompt:
            QMessageBox.warning(self, "Input Required", "Please enter incident details to analyze")
            return
        
        # Show progress
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.statusBar().showMessage("Analyzing incident with Gemini...")
        
        # Clear previous results
        self.results_text.clear()
        
        # Start worker thread
        def do_analysis():
            if self.uploaded_file:
                return self.worker.analyze_with_file(prompt, self.uploaded_file)
            else:
                return self.worker.analyze_text(prompt)
        
        self.current_thread = QThread()
        self.worker_thread = WorkerThread(do_analysis)
        self.worker_thread.moveToThread(self.current_thread)
        
        self.worker_thread.finished.connect(self.on_analysis_complete)
        self.worker_thread.error.connect(self.on_analysis_error)
        
        self.current_thread.started.connect(self.worker_thread.run)
        self.current_thread.start()
    
    def on_analysis_complete(self, result: dict):
        """Handle analysis completion."""
        self.current_thread.quit()
        self.current_thread.wait()
        
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if "error" in result:
            self.statusBar().showMessage("Analysis failed")
            self.results_text.setText(f"Error: {result['error']}")
            QMessageBox.critical(self, "Analysis Failed", result['error'])
            return
        
        # Display results
        raw_analysis = result.get("raw_analysis", "No analysis returned")
        self.results_text.setText(raw_analysis)
        
        # Update stats
        self.update_stats()
        
        # Update status
        metadata = result.get("metadata", {})
        response_time = metadata.get("response_time_seconds", 0)
        self.statusBar().showMessage(f"Analysis complete in {response_time}s")
        
        # Add to history (could implement full history later)
    
    def on_analysis_error(self, error: str):
        """Handle analysis error."""
        self.current_thread.quit()
        self.current_thread.wait()
        
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        self.statusBar().showMessage("Analysis failed")
        self.results_text.setText(f"Error: {error}")
        QMessageBox.critical(self, "Analysis Failed", error)
    
    def open_playbook_dialog(self):
        """Open playbook selection dialog."""
        if not self.brain:
            QMessageBox.warning(self, "Error", "Please configure API key first")
            return
        
        dialog = PlaybookDialog(self.brain, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            playbook_id, incident_data = dialog.get_selected_playbook()
            if playbook_id:
                self.run_playbook(playbook_id, incident_data)
    
    def run_playbook(self, playbook_name: str, incident_data: dict):
        """Run a specific playbook."""
        if not self.brain:
            return
        
        # Show progress
        self.statusBar().showMessage(f"Executing playbook: {playbook_name}...")
        
        def do_playbook():
            return self.worker.run_playbook(playbook_name, incident_data)
        
        self.current_thread = QThread()
        self.worker_thread = WorkerThread(do_playbook)
        self.worker_thread.moveToThread(self.current_thread)
        
        self.worker_thread.finished.connect(self.on_playbook_complete)
        self.worker_thread.error.connect(self.on_playbook_error)
        
        self.current_thread.started.connect(self.worker_thread.run)
        self.current_thread.start()
    
    def on_playbook_complete(self, result: dict):
        """Handle playbook completion."""
        self.current_thread.quit()
        self.current_thread.wait()
        
        if "error" in result:
            self.statusBar().showMessage("Playbook execution failed")
            QMessageBox.critical(self, "Playbook Failed", result['error'])
            return
        
        # Display results in playbook tab
        raw_analysis = result.get("raw_analysis", "No results returned")
        self.playbook_results.setText(raw_analysis)
        
        # Switch to playbook tab
        self.tabs.setCurrentIndex(1)  # Playbooks tab
        
        self.statusBar().showMessage("Playbook executed successfully")
        self.update_stats()
    
    def on_playbook_error(self, error: str):
        """Handle playbook error."""
        self.current_thread.quit()
        self.current_thread.wait()
        
        self.statusBar().showMessage("Playbook execution failed")
        QMessageBox.critical(self, "Playbook Failed", error)
    
    def on_playbook_selected(self):
        """Handle playbook selection in the list."""
        item = self.playbook_list.currentItem()
        if not item:
            return
        
        playbook_id = item.data(Qt.ItemDataRole.UserRole)
        playbook = self.brain.get_playbook(playbook_id)
        
        if playbook:
            details = f"Name: {playbook.get('name', playbook_id)}\n\n"
            details += f"Description: {playbook.get('description', 'N/A')}\n\n"
            details += f"Steps: {len(playbook.get('steps', []))} steps defined"
            
            self.playbook_details.setText(details)
    
    def execute_selected_playbook(self):
        """Execute the currently selected playbook."""
        item = self.playbook_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Select Playbook", "Please select a playbook from the list")
            return
        
        playbook_id = item.data(Qt.ItemDataRole.UserRole)
        
        # Parse incident data
        incident_data = {}
        try:
            text = self.playbook_incident_data.toPlainText().strip()
            if text:
                incident_data = json.loads(text)
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "Invalid JSON", f"Failed to parse incident data: {e}")
            return
        
        self.run_playbook(playbook_id, incident_data)
    
    def copy_results(self):
        """Copy analysis results to clipboard."""
        text = self.results_text.toPlainText()
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("Results copied to clipboard")
    
    def export_results(self):
        """Export analysis results to file."""
        text = self.results_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Results", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            f"soc-eater-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;Markdown Files (*.md);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(text)
                self.statusBar().showMessage(f"Report exported to {file_path}")
                QMessageBox.information(self, "Export Complete", f"Report saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))
    
    def clear_results(self):
        """Clear analysis results."""
        self.results_text.clear()
        self.statusBar().showMessage("Results cleared")
    
    def new_analysis(self):
        """Start a new analysis."""
        self.incident_input.clear()
        self.results_text.clear()
        self.clear_file()
        self.statusBar().showMessage("Ready for new analysis")
    
    def open_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            settings = dialog.get_settings()
            
            # Save API key to environment
            if settings["api_key"]:
                os.environ["GEMINI_API_KEY"] = settings["api_key"]
                
                # Reinitialize brain
                try:
                    self.brain = SOCBrain(api_key=settings["api_key"])
                    self.worker = AnalysisWorker(self.brain)
                    self.status_indicator.setText("●")
                    self.status_indicator.setStyleSheet("font-size: 16px; color: #6bcb77;")
                    self.status_label.setText("Connected")
                    self.status_label.setStyleSheet("color: #6bcb77; font-weight: 600;")
                    self.statusBar().showMessage("API key configured successfully")
                    self.refresh_playbooks()
                    self.update_stats()
                except Exception as e:
                    QMessageBox.critical(self, "Configuration Error", str(e))
    
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About SOC-EATER v2",
            """<h2>SOC-EATER v2</h2>
            <p><b>AI-Powered Security Operations Center</b></p>
            <p>Version 2.0.0</p>
            <hr>
            <p><b>Features:</b></p>
            <ul>
                <li>AI-powered incident analysis</li>
                <li>35+ pre-built security playbooks</li>
                <li>MITRE ATT&CK mapping</li>
                <li>IOC extraction</li>
                <li>Detection queries (Splunk, Sentinel, Elastic)</li>
            </ul>
            <hr>
            <p>Powered by Google Gemini 1.5 Flash</p>
            <p>Built for security teams who want speed, accuracy, and cost-efficiency.</p>
            <hr>
            <p style="color: #888;">© 2024 SOC-EATER Team</p>"""
        )
    
    def open_docs(self):
        """Open documentation."""
        # Could open local docs or web docs
        QMessageBox.information(
            self,
            "Documentation",
            """Available documentation files:
            
            • README.md - Overview and quickstart
            • QUICKSTART.md - Get started guide
            • PLAYBOOKS.md - All playbooks documented
            • ARCHITECTURE.md - System design
            • DEPLOYMENT.md - Production deployment
            
            These files are located in the project directory."""
        )


def main():
    """Main entry point for the desktop application."""
    app = QApplication(sys.argv)
    
    # Set application metadata
    app.setApplicationName("SOC-EATER v2")
    app.setOrganizationName("SOC-EATER")
    app.setDesktopFileName("soc-eater-v2")
    
    # Center window on screen
    window = SOCEaterDesktop()
    
    # Get primary screen and center
    screen = QGuiApplication.primaryScreen()
    screen_geometry = screen.availableGeometry()
    window_geometry = window.frameGeometry()
    center_point = screen_geometry.center()
    window_geometry.moveCenter(center_point)
    window.move(window_geometry.topLeft())
    
    window.show()
    
    sys.exit(app.exec())
