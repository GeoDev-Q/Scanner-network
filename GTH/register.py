import sys
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QHBoxLayout
import subprocess

class IPRegistry(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Registro de IP")
        self.setGeometry(100, 100, 400, 500)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #333333;
            }

            QLineEdit {
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
                font-size: 12px;
            }

            QPushButton:hover {
                background-color: #45a049;
            }
        """)

        self.ip_layout = QVBoxLayout()
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.ip_layout)
        self.setCentralWidget(self.central_widget)

        self.db_path = 'base.sql'  # Ruta de la base de datos
        self.db_connection = sqlite3.connect(self.db_path)
        self.display_ips()

    def display_ips(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT ip FROM devices")
        ips = cursor.fetchall()

        for ip in ips:
            ip_box = self.create_ip_box(ip[0])
            self.ip_layout.addLayout(ip_box)

    def create_ip_box(self, ip):
        ip_box = QHBoxLayout()
        ip_text = QLineEdit()
        ip_text.setText(ip)
        ip_box.addWidget(ip_text)

        remove_button = QPushButton("Quitar")
        remove_button.clicked.connect(lambda state, ip=ip_text: self.remove_device(ip))
        ip_box.addWidget(remove_button)

        limit_button = QPushButton("Bloquear")
        limit_button.clicked.connect(lambda state, ip=ip_text: self.block_ip(ip))
        ip_box.addWidget(limit_button)

        return ip_box

    def remove_device(self, ip_text):
        ip = ip_text.text()
        print(f"Simulando desconexión del dispositivo: {ip}")
        # Aquí podrías añadir lógica para desconectar el dispositivo de la red

    def block_ip(self, ip_text):
        ip = ip_text.text()
        powershell_command = f"New-NetFirewallRule -DisplayName 'Bloquear IP específica' -Direction Inbound -RemoteAddress {ip} -Action Block -Enabled True"
        try:
            subprocess.run(["powershell", "-Command", powershell_command], shell=True, check=True)
            print(f"Se ha bloqueado el tráfico de entrada desde la IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")

if __name__ == "__main__":
    app = QApplication([])
    window = IPRegistry()
    window.show()
    sys.exit(app.exec_())
