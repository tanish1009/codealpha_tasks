# 🖥️ Desktop Packet Sniffer

A lightweight, real-time desktop network packet sniffer built with Python, featuring a polished graphical user interface engineered in **PyQt5** and a high-performance network capture backend powered by **Scapy**.

This application allows developers, network engineers, and security enthusiasts to capture, filter, inspect, and analyze live network traffic across multiple protocols.

---

## ✨ Features

* **🌐 Live Multi-Protocol Capture:** Seamlessly captures and classifies network packets including **TCP**, **UDP**, **ICMP**, and **DNS** traffic.


* **📊 Real-Time Visual Statistics:** Displays dynamic, color-coded counters for individual protocols and total captured packet counts.


* **🛡️ BPF Filtering Engine:** Offers full support for Berkeley Packet Filter (BPF) syntax (e.g., `tcp port 80`, `icmp`) to precisely narrow down capture streams.


* **👁️ Advanced Packet Inspection Layout:**
* 📋 A comprehensive top data table tracking exact timestamp, protocol type, Source/Destination IPs, source/destination ports, size, and TCP flags.


* 🪵 An isolated lower inspection panel providing an interactive, text-rendered look into the raw payload data (ASCII-sanitized representation).




* **⚙️ Cross-Platform Interface Resolution:** Automatically resolves hardware adapters natively across **Windows** (using WinPcap/Npcap GUID mapping), **Linux** (via `/proc/net/dev`), and **macOS**.


* **⚡ Robust Execution Model:** Utilizes dedicated multi-threading via `QThread` to safeguard the UI loop from locking up during aggressive network capture conditions.



---

## 🛠️ Prerequisites & Requirements

The system depends on a few Python packages and low-level packet capture drivers:

### 1. System-Level Dependencies 🔌

* **🪟 Windows:** Requires **Npcap** (or WinPcap) installed in WinPcap API-compatible mode to facilitate raw packet capturing. Download from [Npcap.com](https://npcap.com).


* **🐧 Linux / 🍎 macOS:** Requires standard root/administrator permissions to access raw network sockets (`sudo`).

### 2. Python Packages 🐍

Install the required dependencies directly via `pip`:

```bash
pip install PyQt5 scapy psutil

```

---

## 📂 Project Structure

```text
├── app.py          # Application entry point, UI layout, stylesheet, and window controller
├── sniffer.py      # Background worker thread (QThread) handling packet ingestion and parsing
└── run.bat         # Automated batch script to provision administrator elevation on Windows

```

---

## 🚀 How To Run

### On Windows 🪟

For immediate deployment with correct hardware privileges, double-click or run the provided batch wrapper from an administrative command prompt:

```cmd
run.bat

```

> 💡 **Note:** This script automatically checks for administrator privileges and triggers a Windows UAC prompt via PowerShell if elevation is missing.
> 
> 

### On Linux / macOS 🐧 🍎

To run raw packet interfaces natively, launch the application controller using elevated terminal privileges:

```bash
sudo python app.py

```

---

## 🔍 Architecture Details

* **🧵 Thread-Separated Processing (`sniffer.py`):** The `SnifferThread` wraps Scapy’s `sniff()` framework in a distinct execution lifecycle, dispatching structured Python dictionaries to the main application process using Qt's thread-safe signal-slot mechanism (`pyqtSignal`).


* **🧼 Resilient Payload Sanitization:** Non-printable raw bytes are elegantly scrubbed and translated into dot notation (`.`) to maintain readable terminal integrity within the text panel without corrupting text buffers or throwing decoder exceptions.


* **🧹 Clean State Management:** Full UI control allows users to stop, clear counters, change filter directives, or switch interface paths without interrupting active environment memory states.
