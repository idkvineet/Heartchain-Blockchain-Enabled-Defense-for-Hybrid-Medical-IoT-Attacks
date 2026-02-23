import sys
import os
import time
import sqlite3
import threading
import hashlib

from fastapi import FastAPI, Request
import uvicorn

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit,
    QMessageBox, QFrame, QSplitter, QDialog,
    QFormLayout, QTabWidget
)
from PyQt6.QtCore import QTimer, Qt

import pyqtgraph as pg

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ================= CONFIG =================

HTTPS_PORT = 8443
DEVICE_ID = "device1"
DEVICE_NAME = "HeartMonitor-ESP32"

# ================= DATABASE =================

conn = sqlite3.connect("heartchain.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    firmware_hash TEXT,
    status TEXT,
    last_seen INTEGER,
    public_key TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS challenges (
    device_id TEXT PRIMARY KEY,
    nonce TEXT,
    timestamp INTEGER
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS admin (
    id TEXT PRIMARY KEY,
    password_hash TEXT
)
""")

conn.commit()

cursor.execute("SELECT * FROM admin")
if not cursor.fetchone():
    cursor.execute("INSERT INTO admin VALUES (?,?)",
                   ("admin", hashlib.sha256("admin123".encode()).hexdigest()))
    conn.commit()

# ================= TELEMETRY + BLOCKCHAIN =================

telemetry_stream = []
latency_history = []
blockchain = []
MAX_POINTS = 50

def log_event(message):
    timestamp = time.strftime("%H:%M:%S")
    telemetry_stream.append(f"[{timestamp}] {message}")

def add_block(data):
    previous_hash = blockchain[-1]["hash"] if blockchain else "GENESIS"
    block_string = str(data) + previous_hash
    block_hash = hashlib.sha256(block_string.encode()).hexdigest()

    block = {
        "index": len(blockchain),
        "data": data,
        "previous_hash": previous_hash,
        "hash": block_hash,
        "timestamp": time.time()
    }
    blockchain.append(block)

def detect_anomaly(latency):
    if latency > 1500:
        return "HIGH_LATENCY"
    if len(latency_history) > 5:
        avg = sum(latency_history) / len(latency_history)
        if latency > avg * 2:
            return "SPIKE_DETECTED"
    return None

# ================= FASTAPI =================

app = FastAPI()

@app.post("/register")
def register(data: dict, request: Request):
    ip = request.client.host
    port = request.client.port

    log_event(f"[SERVER] Registration from {ip}:{port}")

    nonce = os.urandom(16).hex()

    cursor.execute("""
        INSERT OR REPLACE INTO devices
        VALUES (?,?,?,?,?)
    """, (data["device_id"],
          data["firmware_hash"],
          "active",
          int(time.time()),
          data["public_key"]))

    cursor.execute("""
        INSERT OR REPLACE INTO challenges
        VALUES (?,?,?)
    """, (data["device_id"], nonce, int(time.time())))

    conn.commit()

    log_event("[SERVER] Device registered")
    return {"status": "registered", "nonce": nonce}


@app.post("/telemetry")
def telemetry(data: dict):
    try:
        start = time.time()

        device_id = data.get("device_id")
        nonce = data.get("nonce")
        signature = data.get("signature")
        sensor_data = data.get("data")

        if not all([device_id, nonce, signature]):
            log_event("MISSING FIELDS")
            return {"status": "invalid_request"}

        row = cursor.execute("""
            SELECT firmware_hash, public_key, status
            FROM devices WHERE device_id=?
        """, (device_id,)).fetchone()

        if not row:
            log_event("UNKNOWN DEVICE")
            return {"status": "unknown"}

        firmware_hash, public_key_hex, status = row

        if status != "active":
            log_event(f"DEVICE BLOCKED: {status}")
            return {"status": status}

        chal = cursor.execute(
            "SELECT nonce FROM challenges WHERE device_id=?",
            (device_id,)
        ).fetchone()

        if not chal or nonce != chal[0]:
            log_event("INVALID NONCE")
            return {"status": "invalid_nonce"}

        message = device_id + firmware_hash + str(sensor_data) + nonce

        try:
            pub = serialization.load_der_public_key(bytes.fromhex(public_key_hex))
            pub.verify(
                bytes.fromhex(signature),
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
        except Exception as e:
            log_event(f"SIGNATURE ERROR: {str(e)}")
            return {"status": "invalid_signature"}

        latency = round((time.time() - start) * 1000, 2)

        latency_history.append(latency)
        if len(latency_history) > MAX_POINTS:
            latency_history.pop(0)

        anomaly = detect_anomaly(latency)

        log_event(f"VERIFIED | {latency} ms")

        if anomaly:
            log_event(f"ANOMALY: {anomaly}")

        add_block({"latency": latency})

        new_nonce = os.urandom(16).hex()
        cursor.execute("UPDATE challenges SET nonce=? WHERE device_id=?",
                       (new_nonce, device_id))
        cursor.execute("UPDATE devices SET last_seen=? WHERE device_id=?",
                       (int(time.time()), device_id))
        conn.commit()

        return {"status": "verified", "nonce": new_nonce}

    except Exception as e:
        log_event(f"SERVER CRASH: {str(e)}")
        return {"status": "server_error"}

# ================= GUI =================

class EnterpriseGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.logged_in = False
        self.last_log_index = 0
        self.key_visible = False
        self.pass_visible = False

        self.setWindowTitle("HeartChain Enterprise Dashboard")
        self.resize(1300, 800)

        self.tabs = QTabWidget()

        # ================= DASHBOARD TAB =================

        dashboard = QWidget()
        dash_layout = QVBoxLayout()

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # LEFT PANEL
        left_layout = QVBoxLayout()

        self.status_indicator = QLabel("● LOCKED")
        left_layout.addWidget(self.status_indicator)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background:#111;color:white;")
        left_layout.addWidget(self.log_box)

        self.btn_revoke = QPushButton("Revoke")
        self.btn_approve = QPushButton("Approve")

        self.btn_revoke.clicked.connect(self.revoke)
        self.btn_approve.clicked.connect(self.approve)

        left_layout.addWidget(self.btn_revoke)
        left_layout.addWidget(self.btn_approve)

        left_widget = QWidget()
        left_widget.setLayout(left_layout)

        # RIGHT PANEL
        right_layout = QVBoxLayout()

        self.device_info = QLabel("")
        right_layout.addWidget(self.device_info)

        self.key_field = QLineEdit("******")
        self.key_field.setReadOnly(True)
        self.btn_getkey = QPushButton("Show / Hide Key")
        self.btn_getkey.clicked.connect(self.toggle_key)

        right_layout.addWidget(self.key_field)
        right_layout.addWidget(self.btn_getkey)

        self.admin_id = QLineEdit()
        self.admin_id.setPlaceholderText("Admin ID")

        pass_row = QHBoxLayout()
        self.admin_pass = QLineEdit()
        self.admin_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.btn_show_pass = QPushButton("Show")
        self.btn_show_pass.clicked.connect(self.toggle_password)

        pass_row.addWidget(self.admin_pass)
        pass_row.addWidget(self.btn_show_pass)

        self.btn_login = QPushButton("Unlock")
        self.btn_login.clicked.connect(self.login)

        self.btn_change_pass = QPushButton("Change Password")
        self.btn_change_pass.clicked.connect(self.change_password)

        right_layout.addWidget(self.admin_id)
        right_layout.addLayout(pass_row)
        right_layout.addWidget(self.btn_login)
        right_layout.addWidget(self.btn_change_pass)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        dash_layout.addWidget(splitter)

        # LATENCY GRAPH
        self.latency_plot = pg.PlotWidget(title="Live Latency (ms)")
        self.latency_plot.setBackground("#111")
        self.latency_curve = self.latency_plot.plot(pen="y")
        dash_layout.addWidget(self.latency_plot)

        dashboard.setLayout(dash_layout)
        self.tabs.addTab(dashboard, "Dashboard")

        # ================= BLOCKCHAIN TAB =================

        self.blockchain_view = QTextEdit()
        self.blockchain_view.setReadOnly(True)

        blockchain_tab = QWidget()
        bc_layout = QVBoxLayout()
        bc_layout.addWidget(self.blockchain_view)
        blockchain_tab.setLayout(bc_layout)

        self.tabs.addTab(blockchain_tab, "Blockchain")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.setLayout(layout)

        self.lock_ui(True)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

        log_event("[SERVER] Dashboard started")

    # ================= LOCK =================

    def lock_ui(self, lock):
        self.btn_revoke.setEnabled(not lock)
        self.btn_approve.setEnabled(not lock)
        self.btn_getkey.setEnabled(not lock)
        self.btn_change_pass.setEnabled(not lock)

        if lock:
            self.status_indicator.setText("● LOCKED")
        else:
            self.status_indicator.setText("● ACTIVE")

    # ================= LOGIN =================

    def login(self):
        pwd_hash = hashlib.sha256(self.admin_pass.text().encode()).hexdigest()
        cursor.execute("SELECT password_hash FROM admin WHERE id=?", (self.admin_id.text(),))
        row = cursor.fetchone()

        if row and row[0] == pwd_hash:
            self.logged_in = True
            self.lock_ui(False)
            log_event("[ADMIN] Logged In")
        else:
            QMessageBox.warning(self, "Error", "Invalid credentials")

    def toggle_password(self):
        if self.pass_visible:
            self.admin_pass.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_pass.setText("Show")
        else:
            self.admin_pass.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_pass.setText("Hide")
        self.pass_visible = not self.pass_visible

    def change_password(self):
        if not self.logged_in:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Change Password")
        layout = QFormLayout(dialog)

        old_pass = QLineEdit()
        old_pass.setEchoMode(QLineEdit.EchoMode.Password)
        new_pass = QLineEdit()
        new_pass.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addRow("Old Password:", old_pass)
        layout.addRow("New Password:", new_pass)

        btn = QPushButton("Update")
        layout.addWidget(btn)

        def update():
            old_hash = hashlib.sha256(old_pass.text().encode()).hexdigest()
            cursor.execute("SELECT password_hash FROM admin WHERE id='admin'")
            row = cursor.fetchone()
            if not row or row[0] != old_hash:
                QMessageBox.warning(dialog, "Error", "Incorrect old password")
                return

            new_hash = hashlib.sha256(new_pass.text().encode()).hexdigest()
            cursor.execute("UPDATE admin SET password_hash=? WHERE id='admin'", (new_hash,))
            conn.commit()
            dialog.accept()
            log_event("[ADMIN] Password Changed")

        btn.clicked.connect(update)
        dialog.exec()

    def toggle_key(self):
        if not self.logged_in:
            return

        if self.key_visible:
            self.key_field.setText("******")
        else:
            cursor.execute("SELECT public_key FROM devices WHERE device_id=?", (DEVICE_ID,))
            row = cursor.fetchone()
            self.key_field.setText(row[0] if row else "N/A")
        self.key_visible = not self.key_visible

    def revoke(self):
        cursor.execute("UPDATE devices SET status='revoked' WHERE device_id=?", (DEVICE_ID,))
        conn.commit()
        log_event("[ADMIN] Device Revoked")

    def approve(self):
        cursor.execute("UPDATE devices SET status='active' WHERE device_id=?", (DEVICE_ID,))
        conn.commit()
        log_event("[ADMIN] Device Approved")

    # ================= REFRESH =================

    def refresh(self):

        cursor.execute("SELECT status, firmware_hash, last_seen FROM devices WHERE device_id=?", (DEVICE_ID,))
        row = cursor.fetchone()

        if row:
            status, fw, last = row
            self.device_info.setText(
                f"Device: {DEVICE_NAME}\nFirmware: {fw}\nLast Seen: {last}\nStatus: {status}"
            )

        if self.last_log_index < len(telemetry_stream):
            new_logs = telemetry_stream[self.last_log_index:]
            for entry in new_logs:
                if "ANOMALY" in entry:
                    self.log_box.append(f"<span style='color:red'>{entry}</span>")
                elif "VERIFIED" in entry:
                    self.log_box.append(f"<span style='color:green'>{entry}</span>")
                elif "[SERVER]" in entry:
                    self.log_box.append(f"<span style='color:cyan'>{entry}</span>")
                else:
                    self.log_box.append(entry)

            self.last_log_index = len(telemetry_stream)
            self.log_box.verticalScrollBar().setValue(
                self.log_box.verticalScrollBar().maximum()
            )

        if latency_history:
            self.latency_curve.setData(latency_history)

        block_text = ""
        for block in blockchain[-10:]:
            block_text += (
                f"Block #{block['index']}\n"
                f"Latency: {block['data']['latency']} ms\n"
                f"Hash: {block['hash'][:20]}...\n"
                f"Prev: {block['previous_hash'][:20]}...\n"
                "------------------------\n"
            )
        self.blockchain_view.setText(block_text)

# ================= START =================

def start_server():
    log_event("[SERVER] HTTPS server starting...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=HTTPS_PORT,
        ssl_keyfile="certs/server.key",
        ssl_certfile="certs/server.crt",
        log_level="warning"
    )

if __name__ == "__main__":
    threading.Thread(target=start_server, daemon=True).start()
    qt_app = QApplication(sys.argv)
    window = EnterpriseGUI()
    window.show()
    sys.exit(qt_app.exec())