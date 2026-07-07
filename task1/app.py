

import sys
import platform

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
    QTextEdit,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QHBoxLayout,
    QHeaderView,
)

from sniffer import SnifferThread

PROTO_COLORS = {
    "TCP": "#2563eb",
    "UDP": "#059669",
    "ICMP": "#d97706",
    "DNS": "#7c3aed",
    "OTHER": "#6b7280",
}

TABLE_HEADERS = ["#", "Time", "Protocol", "Source IP", "Src Port", "Dest IP", "Dst Port", "Size", "Flags"]

NO_FLAGS = "-"

STYLE_SHEET = """
QMainWindow {
    background-color: #f4f6f9;
}

QWidget {
    font-family: "Segoe UI";
    color: #1a1d23;
}

QWidget#sidebar {
    background-color: #ffffff;
    border-right: 1px solid #e0e4ed;
}

QLabel#appTitle {
    font-size: 15px;
    font-weight: 700;
    color: #1a1d23;
}

QLabel.fieldLabel {
    color: #6b7280;
    font-size: 11px;
    font-weight: 600;
}

QComboBox, QLineEdit {
    background-color: #ffffff;
    border: 1px solid #e0e4ed;
    border-radius: 6px;
    padding: 6px 8px;
    color: #1a1d23;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QPushButton {
    border-radius: 6px;
    padding: 8px;
    font-weight: 600;
    border: none;
}

QPushButton#startBtn {
    background-color: #2563eb;
    color: #ffffff;
}
QPushButton#startBtn:disabled {
    background-color: #a8c1f5;
    color: #f0f4ff;
}

QPushButton#stopBtn {
    background-color: #dc2626;
    color: #ffffff;
}
QPushButton#stopBtn:disabled {
    background-color: #f0abab;
    color: #fff5f5;
}

QPushButton#clearBtn {
    background-color: #f4f6f9;
    color: #1a1d23;
    border: 1px solid #e0e4ed;
}

QFrame#statsCard {
    background-color: #ffffff;
    border: 1px solid #e0e4ed;
    border-radius: 6px;
}

QLabel.statName {
    color: #6b7280;
    font-size: 12px;
}

QLabel.statValue {
    color: #1a1d23;
    font-size: 12px;
    font-weight: 700;
}

QTableWidget {
    background-color: #ffffff;
    border: 1px solid #e0e4ed;
    border-radius: 6px;
    gridline-color: transparent;
    alternate-background-color: #f9fafb;
    selection-background-color: #eff6ff;
    selection-color: #1a1d23;
}

QTableWidget::item {
    padding-left: 6px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #eff6ff;
    color: #1a1d23;
}

QHeaderView::section {
    background-color: #f9fafb;
    color: #9ca3af;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #e0e4ed;
}

QTextEdit#detailPanel {
    background-color: #f9fafb;
    color: #374151;
    border: 1px solid #e0e4ed;
    border-radius: 6px;
    font-family: "Consolas";
}

QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #e0e4ed;
    color: #6b7280;
}

QSplitter::handle {
    background-color: #f4f6f9;
    height: 6px;
}

QScrollBar:vertical {
    width: 6px;
    background: transparent;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #d1d5db;
    border-radius: 3px;
    min-height: 24px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}

QScrollBar:horizontal {
    height: 6px;
    background: transparent;
    margin: 0px;
}
QScrollBar::handle:horizontal {
    background: #d1d5db;
    border-radius: 3px;
    min-width: 24px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: transparent;
}
"""


def get_interfaces():
    """Return a list of (label, device) tuples for the interface dropdown.

    On Windows this uses scapy's get_windows_if_list() so the combo box
    shows a human-readable adapter name/description while the value
    actually handed to scapy.sniff() is the raw \\Device\\NPF_{GUID}
    device path. On Linux we fall back to parsing /proc/net/dev. Any
    other platform gets a small hardcoded default list.
    """
    system = platform.system()
    interfaces = []

    if system == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list

            for iface in get_windows_if_list():
                guid = iface.get("guid") or ""
                if not guid:
                    continue
                name = iface.get("name") or ""
                description = iface.get("description") or name or guid
                device = r"\Device\NPF_%s" % guid
                interfaces.append((description, device))
        except Exception:
            interfaces = []
        if not interfaces:
            interfaces = [("Default interface", None)]

    elif system == "Linux":
        interfaces = _linux_interfaces()
        if not interfaces:
            interfaces = [("eth0", "eth0"), ("lo", "lo")]

    else:
        # macOS / other -- hardcoded, reasonable defaults
        interfaces = [("en0", "en0"), ("en1", "en1"), ("lo0", "lo0")]

    return interfaces


def _linux_interfaces():
    ifaces = []
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
        for line in lines[2:]:
            if ":" not in line:
                continue
            name = line.split(":", 1)[0].strip()
            if name:
                ifaces.append((name, name))
    except Exception:
        pass
    return ifaces


def _field_label(text):
    label = QLabel(text)
    label.setProperty("class", "fieldLabel")
    label.setStyleSheet("color: #6b7280; font-size: 11px; font-weight: 600;")
    return label


def _stat_row(name, color):
    """Build one 'colored dot + name + count' row for the stats section."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 2, 0, 2)
    layout.setSpacing(8)

    dot = QLabel()
    dot.setFixedSize(10, 10)
    dot.setStyleSheet("background-color: {}; border-radius: 5px;".format(color))

    name_label = QLabel(name)
    name_label.setStyleSheet("color: #6b7280; font-size: 12px;")

    count_label = QLabel("0")
    count_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
    count_label.setStyleSheet("color: #1a1d23; font-size: 12px; font-weight: 700;")

    layout.addWidget(dot)
    layout.addWidget(name_label)
    layout.addStretch(1)
    layout.addWidget(count_label)

    return row, count_label


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.resize(1200, 720)

        self._iface_map = {}
        self.packets = []
        self.counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0}
        self.total = 0
        self.sniffer_thread = None

        self._build_ui()
        self.setStyleSheet(STYLE_SHEET)

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        central = QWidget()
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_sidebar())
        root_layout.addWidget(self._build_main_content(), 1)

        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready")

    def _build_sidebar(self):
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(6)

        title = QLabel("Packet Sniffer")
        title.setObjectName("appTitle")
        layout.addWidget(title)
        layout.addSpacing(12)

        # Interface
        layout.addWidget(_field_label("INTERFACE"))
        self.iface_combo = QComboBox()
        for label, device in get_interfaces():
            self.iface_combo.addItem(label)
            self._iface_map[label] = device
        layout.addWidget(self.iface_combo)
        layout.addSpacing(10)

        # Filter
        layout.addWidget(_field_label("FILTER (BPF)"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g. tcp port 80")
        layout.addWidget(self.filter_edit)
        layout.addSpacing(14)

        # Start
        layout.addWidget(_field_label("START CAPTURE"))
        self.start_btn = QPushButton("Start")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_capture)
        layout.addWidget(self.start_btn)
        layout.addSpacing(8)

        # Stop
        layout.addWidget(_field_label("STOP CAPTURE"))
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        layout.addWidget(self.stop_btn)
        layout.addSpacing(8)

        # Clear
        layout.addWidget(_field_label("CLEAR TABLE"))
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("clearBtn")
        self.clear_btn.clicked.connect(self.clear_table)
        layout.addWidget(self.clear_btn)

        layout.addSpacing(20)

        # Stats section
        layout.addWidget(_field_label("LIVE STATS"))
        layout.addSpacing(4)

        self.count_labels = {}
        stats_rows = [
            ("Total", "#1a1d23"),
            ("TCP", PROTO_COLORS["TCP"]),
            ("UDP", PROTO_COLORS["UDP"]),
            ("ICMP", PROTO_COLORS["ICMP"]),
            ("DNS", PROTO_COLORS["DNS"]),
        ]
        for name, color in stats_rows:
            row_widget, count_label = _stat_row(name, color)
            self.count_labels[name] = count_label
            layout.addWidget(row_widget)

        layout.addStretch(1)
        return sidebar

    def _build_main_content(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self.table = QTableWidget(0, len(TABLE_HEADERS))
        self.table.setHorizontalHeaderLabels(TABLE_HEADERS)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setColumnWidth(0, 44)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 80)
        self.table.itemSelectionChanged.connect(self.on_row_selected)

        self.detail = QTextEdit()
        self.detail.setObjectName("detailPanel")
        self.detail.setReadOnly(True)
        self.detail.setFixedHeight(140)
        self.detail.setFont(QFont("Consolas", 10))

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)

        layout.addWidget(splitter)
        return container

    # ------------------------------------------------------------- actions

    def start_capture(self):
        label = self.iface_combo.currentText()
        device = self._iface_map.get(label)
        bpf_filter = self.filter_edit.text().strip()

        self.sniffer_thread = SnifferThread(iface=device, bpf_filter=bpf_filter)
        self.sniffer_thread.packet_received.connect(self.on_packet)
        self.sniffer_thread.status_changed.connect(self.on_status)
        self.sniffer_thread.start()

        self.start_btn.setEnabled(False)
        self.iface_combo.setEnabled(False)
        self.filter_edit.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.statusBar().showMessage("Capturing on {}...".format(label))

    def stop_capture(self):
        if self.sniffer_thread is not None and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait(2000)

        self.start_btn.setEnabled(True)
        self.iface_combo.setEnabled(True)
        self.filter_edit.setEnabled(True)
        self.stop_btn.setEnabled(False)

        self.statusBar().showMessage("Stopped -- {} packets captured".format(self.total))

    def clear_table(self):
        self.table.setRowCount(0)
        self.packets = []
        self.total = 0
        for key in self.counts:
            self.counts[key] = 0
        self._refresh_stats()
        self.detail.clear()
        self.statusBar().showMessage("Cleared")

    # --------------------------------------------------------------- slots

    def on_packet(self, data):
        self.packets.append(data)

        row = self.table.rowCount()
        self.table.insertRow(row)

        proto = data["proto"]
        values = [
            str(row + 1),
            data["time"],
            proto,
            data["src_ip"],
            str(data["src_port"]),
            data["dst_ip"],
            str(data["dst_port"]),
            str(data["size"]),
            data["flags"],
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 2:
                color = PROTO_COLORS.get(proto, "#6b7280")
                item.setForeground(QColor(color))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()

        self.total += 1
        if proto in self.counts:
            self.counts[proto] += 1
        self._refresh_stats()

    def on_status(self, message):
        if message.startswith("error"):
            self.stop_capture()
            self.statusBar().showMessage(message)
        else:
            self.statusBar().showMessage(message)

    def on_row_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        if row < 0 or row >= len(self.packets):
            return

        data = self.packets[row]
        text = (
            "Packet #{n}\n"
            "Time:         {time}\n"
            "Protocol:     {proto}\n"
            "Source:       {src_ip}:{src_port}\n"
            "Destination:  {dst_ip}:{dst_port}\n"
            "Size:         {size} bytes\n"
            "Flags:        {flags}\n"
            "\n"
            "Payload:\n"
            "{payload}"
        ).format(
            n=row + 1,
            time=data["time"],
            proto=data["proto"],
            src_ip=data["src_ip"],
            src_port=data["src_port"],
            dst_ip=data["dst_ip"],
            dst_port=data["dst_port"],
            size=data["size"],
            flags=data["flags"] or NO_FLAGS,
            payload=data["payload"] or "(empty)",
        )
        self.detail.setPlainText(text)

    def _refresh_stats(self):
        self.count_labels["Total"].setText(str(self.total))
        for name in ("TCP", "UDP", "ICMP", "DNS"):
            self.count_labels[name].setText(str(self.counts.get(name, 0)))

    # -------------------------------------------------------------- window

    def closeEvent(self, event):
        self.stop_capture()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 9))

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
