from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, 
                           QPlainTextEdit, QLabel, QMessageBox, QProgressBar, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PyQt5.QtGui import QFont, QPainter, QColor, QBrush, QLinearGradient, QPen
import requests
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
from urllib.request import urlopen

class APIKeyManager:
    def __init__(self):
        # Kunci enkripsi (harus tetap rahasia, jangan diupload ke GitHub)
        self.encryption_key = b'admin_tsecnetwork_orang_bengkulu'
        
        # URL ke file API key terenkripsi di GitHub (ganti dengan URL Anda)
        self.encrypted_api_url = "https://raw.githubusercontent.com/username/repo/main/encrypted_api_keys.json"
    
    def decrypt_api_keys(self):
        try:
            # Download file terenkripsi dari GitHub
            response = urlopen(self.encrypted_api_url)
            encrypted_data = json.loads(response.read().decode('utf-8'))
            
            # Dekripsi data
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, 
                            base64.b64decode(encrypted_data['iv'].encode('utf-8')))
            decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data['data'].encode('utf-8'))), 
                            AES.block_size)
            
            return json.loads(decrypted.decode('utf-8'))['api_keys']
        except Exception as e:
            print(f"Error decrypting API keys: {e}")
            # Fallback ke API key default jika ada masalah
            return [
                "M17bkWbXbYAALYlFqzRE4hakjDxnTUCO",
                "0IE8aT4fH6jPWBM8jgYvcJmFYXK58ESw",
                "2TLu_qiwpDlJimP96LwULQUtGXQtFsbH"
            ]

class SubdomainWorker(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    scan_status = pyqtSignal(str)

    def __init__(self, domain, api_keys):
        super().__init__()
        self.domain = domain
        self.api_keys = api_keys
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        result_found = False
        total_keys = len(self.api_keys)
        found_subdomains = []

        for idx, api_key in enumerate(self.api_keys):
            if not self.is_running:
                break

            try:
                self.progress.emit(int((idx + 1) / total_keys * 100))
                self.scan_status.emit(f"🔑 Trying Scanning")
                
                api_url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
                headers = {
                    "Content-Type": "application/json",
                    "APIKEY": api_key
                }
                response = requests.get(api_url, headers=headers, timeout=10)
                data = response.json()

                if response.status_code != 200 or 'error' in data:
                    self.scan_status.emit(f"⚠️ Fixing error")
                    continue
                
                subdomains = data.get('subdomains', [])
                if subdomains:
                    found_subdomains.extend(subdomains)
                    result_found = True
                    break
                
                time.sleep(0.5)  # Prevent API rate limiting

            except requests.Timeout:
                self.scan_status.emit(f"⏱️ Error!! Hal ini akan Segera Diperbaiki")
                continue
            except Exception as e:
                self.error.emit(f"❌ Error!! Hal ini akan Segera Diperbaiki")
                continue

        if result_found:
            result_text = "\n"
            unique_subdomains = list(set(found_subdomains))
            for i, subdomain in enumerate(unique_subdomains):
                result_text += f"{subdomain}.{self.domain}\n"
            result_text += f"\n📊 Total subdomains found: {len(unique_subdomains)}\n\n\n\n"
            self.result.emit(result_text)
        else:
            self.result.emit("❌ Error!! Hal ini akan Segera Diperbaiki.")

        self.finished.emit()

class AnimatedProgressBar(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation_phase = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateAnimation)
        self.timer.start(30)
        
    def updateAnimation(self):
        self.animation_phase = (self.animation_phase + 0.1) % (2 * 3.14159)
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background
        bg_rect = self.rect()
        painter.fillRect(bg_rect, QColor(10, 20, 30, 200))
        
        # Border
        painter.setPen(QPen(QColor(0, 242, 255, 100), 1))
        painter.drawRect(bg_rect.adjusted(0, 0, -1, -1))
        
        # Progress fill
        if self.value() > 0:
            progress_width = int(self.width() * self.value() / 100)
            progress_rect = QRect(0, 0, progress_width, self.height())
            
            # Gradient fill
            gradient = QLinearGradient(0, 0, progress_width, 0)
            gradient.setColorAt(0, QColor(0, 242, 255, 150))
            gradient.setColorAt(1, QColor(0, 255, 128, 150))
            painter.fillRect(progress_rect, gradient)
            
            # Scanline effect
            scan_x = int(progress_width + 20 * abs(time.time() % 2 - 1))
            if scan_x < progress_width:
                scan_rect = QRect(scan_x, 0, 2, self.height())
                painter.fillRect(scan_rect, QColor(255, 255, 255, 100))
        
        # Text
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Courier New", 9))
        painter.drawText(bg_rect, Qt.AlignCenter, f"{self.value()}%")

class SubdoFinderPage(QWidget):
    def __init__(self):
        super().__init__()
        # Menggunakan APIKeyManager untuk mendapatkan API keys
        self.key_manager = APIKeyManager()
        self.api_keys = self.key_manager.decrypt_api_keys()
        self.worker = None
        self.initUI()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background grid
        grid_size = 40
        pen = QPen(QColor(0, 150, 200, 10), 1)
        painter.setPen(pen)
        
        for x in range(0, self.width(), grid_size):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), grid_size):
            painter.drawLine(0, y, self.width(), y)

    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
    
            
        # Main content container
        content_container = QFrame()
        content_container.setStyleSheet("""
            QFrame {
                background-color: rgba(10, 20, 30, 0.7);
                border: 1px solid rgba(0, 242, 255, 0.2);
            }
        """)
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)
        
        # Input section
        input_container = QWidget()
        input_layout = QHBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain (e.g., example.com)")
        self.domain_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(10, 20, 30, 0.8);
                border: 2px solid rgba(0, 242, 255, 0.3);
                padding: 5px;
                color: #7fdbff;
                font-family: 'Courier New';
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #00f2ff;
            }
        """)
        
        input_layout.addWidget(self.domain_input)
        content_layout.addWidget(input_container)
        
        # Progress bar
        self.progress_bar = AnimatedProgressBar()
        self.progress_bar.setMinimumHeight(8)
        self.progress_bar.setMaximumHeight(8)
        self.progress_bar.hide()
        content_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("""
            color: #7fdbff;
            font-family: 'Courier New';
            font-size: 12px;
            border: 0px;
        """)
        content_layout.addWidget(self.status_label)
        
        # Buttons
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.search_button = QPushButton("🔍 Start Scanning")
        self.search_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 242, 255, 0.1);
                color: #00f2ff;
                border: 2px solid #00f2ff;
                padding: 5px 10px;
                font-family: 'Courier New';
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(0, 242, 255, 0.2);
            }
            QPushButton:pressed {
                background-color: rgba(0, 242, 255, 0.3);
            }
        """)
        self.search_button.clicked.connect(self.startSearch)
        
        self.cancel_button = QPushButton("⏹ Stop Scan")
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 59, 48, 0.1);
                color: #ff3b30;
                border: 2px solid #ff3b30;
                padding: 5px 10px;
                font-family: 'Courier New';
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 59, 48, 0.2);
            }
            QPushButton:pressed {
                background-color: rgba(255, 59, 48, 0.3);
            }
        """)
        self.cancel_button.clicked.connect(self.stopSearch)
        self.cancel_button.hide()
        
        button_layout.addWidget(self.search_button)
        button_layout.addWidget(self.cancel_button)
        content_layout.addWidget(button_container)
        
        # Results output
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Results will appear here...")
        self.output.setStyleSheet("""
            QPlainTextEdit {
                background-color: rgba(10, 20, 30, 0.8);
                border: 2px solid rgba(0, 242, 255, 0.2);
                padding: 5px;
                color: #7fdbff;
                font-family: 'Courier New';
                font-size: 13px;
            }
        """)
        self.output.setMinimumHeight(250)
        content_layout.addWidget(self.output)
        
        layout.addWidget(content_container)
    
    def startSearch(self):
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a valid domain.")
            return
        
        self.output.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.search_button.hide()
        self.cancel_button.show()
        self.status_label.setText("🔄 Scanning in progress...")
        self.domain_input.setEnabled(False)
        
        self.worker = SubdomainWorker(domain, self.api_keys)
        self.worker.progress.connect(self.updateProgress)
        self.worker.result.connect(self.showResults)
        self.worker.error.connect(self.showError)
        self.worker.scan_status.connect(self.updateStatus)
        self.worker.finished.connect(self.searchCompleted)
        self.worker.start()
    
    def stopSearch(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            self.searchCompleted()
            self.status_label.setText("⏹ Scan stopped by user")
    
    def updateProgress(self, value):
        self.progress_bar.setValue(value)
    
    def updateStatus(self, status):
        self.status_label.setText(status)
    
    def showResults(self, text):
        self.output.setPlainText(text)
    
    def showError(self, error_text):
        self.output.appendPlainText(error_text)
    
    def searchCompleted(self):
        self.progress_bar.hide()
        self.search_button.show()
        self.cancel_button.hide()
        self.domain_input.setEnabled(True)
        if "No valid subdomains" not in self.output.toPlainText():
            self.status_label.setText("✅ Scan completed successfully")