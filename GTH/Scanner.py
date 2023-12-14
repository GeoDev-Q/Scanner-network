import os
import sys
import nmap
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QPushButton, QLabel
from PyQt5.QtGui import QColor, QFont
from scapy.all import ARP, Ether, srp
from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal
import threading

class NetworkScanner(QMainWindow):
    update_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner")
        self.setGeometry(100, 100, 400, 300)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #333333;
            }

            QTextEdit {
                background-color: #1a1a1a;
                color: white;
                border: none;
                font-family: Arial;
                font-size: 12px;
            }

            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                font-family: Arial;
                font-size: 14px;
            }

            QPushButton:hover {
                background-color: #45a049;
            }

            QLabel {
                color: white;
                font-family: Arial;
                font-size: 14px;
            }
        """)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setMinimumHeight(400)
        self.scan_button = QPushButton("Scan Network")
        self.wait_label = QLabel("")
        self.text_edit.setMinimumWidth(700)

        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        layout.addWidget(self.wait_label)
        layout.addWidget(self.scan_button)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.scan_button.clicked.connect(self.scan_network)

        db_path = os.path.join(os.path.dirname(__file__), r'C:\Users\Estudiante\Desktop\GTH\base.sql')
        self.db_connection = sqlite3.connect(db_path)
        self.create_table()

        self.update_signal.connect(self.update_ui)

    def create_table(self):
        cursor = self.db_connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT, mac TEXT, name TEXT)")
        self.db_connection.commit()

    def insert_device(self, device):
        cursor = self.db_connection.cursor()
        cursor.execute("INSERT INTO devices VALUES (?, ?, ?)", (device['ip'], device['mac'], device['name']))
        self.db_connection.commit()

    def scan_network(self):
        self.wait_label.setText("Espera...")
        self.wait_label.setAlignment(Qt.AlignCenter)
        self.wait_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.wait_label.setStyleSheet("color: #FFD700;")
        
        ip = "192.168.100.1/24"

        # Crear un hilo para el escaneo de red
        scan_thread = threading.Thread(target=self.perform_scan, args=(ip,))
        scan_thread.start()

    def perform_scan(self, ip):
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=3, verbose=0)[0]

        nm = nmap.PortScanner()
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'name': self.get_device_name(received.psrc, nm)})

        self.update_signal.emit(devices)

    def update_ui(self, devices):
        self.text_edit.clear()
        for device in devices:
            self.text_edit.append("IP: " + device['ip'] + "\tMAC: " + device['mac'] + "\tName: " + device['name'])
            self.insert_device(device)

        QTimer.singleShot(2000, self.hide_wait_label)

    def hide_wait_label(self):
        self.wait_label.clear()

    def get_device_name(self, ip, nm):
        try:
            nm.scan(ip, arguments='-O')
            return nm[ip]['osmatch'][0]['name']
        except Exception:
            return "Unknown"

if __name__ == "__main__":
    app = QApplication([])
    window = NetworkScanner()
    window.show()
    sys.exit(app.exec_())
