# Banlist – Automatic SSH/Telnet Brute-Force Protection + Web UI

**Banlist** is a lightweight Python daemon that monitors  
`/var/log/auth.log` in real time, detects failed authentication attempts  
(SSH, Telnet, PAM), and automatically bans offending IP addresses.

A built-in Web UI exposes live ban files:

- `ipv4.txt`
- `ipv6.txt`
- An HTML summary page

The daemon runs as a **systemd service** and includes an installer.

---

## ✨ Features

- Real-time monitoring of SSH/Telnet/PAM authentication failures  
- IPv4 & IPv6 detection  
- Hostname → IP auto-resolution  
- Configurable failure threshold (default: 3 attempts)  
- Automatic ban for 12 hours  
- Separate output files for IPv4 and IPv6  
- CIDR whitelist support (`whitelist.txt`)  
- Simple built-in Web UI (port configurable via `install.sh`)  
- Automatic cleanup of expired bans  
- Fully managed by systemd

---

## 📦 Installation

### 1. Clone the repository

Recommended location:

```bash
sudo mkdir -p /opt
sudo chown "$USER" /opt
git clone https://github.com/<your-org>/banlist.git /opt/banlist
cd /opt/banlist
```

---

## 🔧 2. Install the systemd service

Run:

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer:

- Checks required files  
- Asks for the **HTTP Web UI port** (default: `8080`)  
- Injects the port into `banlist.service`  
- Installs the service into `/etc/systemd/system/`  
- Reloads systemd  
- Enables the service on boot  
- Starts the daemon  

Example output:

```text
HTTP port for the web interface [8080]: 9090
→ Installing…
Web UI available at: http://192.168.1.10:9090/
```

---

## 🌐 3. Web UI usage

Once the service is running:

- Main page:  
  `http://<server>:<port>/`

- Raw files:  
  `http://<server>:<port>/ipv4.txt`  
  `http://<server>:<port>/ipv6.txt`

---

## 🔥 4. Requirements: a working `/var/log/auth.log`

On Debian / Ubuntu:

```bash
sudo apt install openssh-server rsyslog login
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
sudo systemctl restart ssh
```

(Optional) Telnet logging:

```bash
sudo apt install telnetd
```

---

## 🗂️ Project structure

```text
banlist/
├── banlist.py
├── banlist.service
├── install.sh
├── whitelist.txt
└── README.md
```

---

## 📄 Whitelist format (`whitelist.txt`)

CIDR notation, one per line:

```text
172.16.0.0/12
192.168.0.0/16
10.0.0.0/8
```

---

## 🔧 systemd commands

Start:

```bash
sudo systemctl start banlist
```

Stop:

```bash
sudo systemctl stop banlist
```

Restart:

```bash
sudo systemctl restart banlist
```

Logs:

```bash
journalctl -u banlist -f
```

---

## ❌ Uninstall

```bash
sudo systemctl stop banlist
sudo systemctl disable banlist
sudo rm -f /etc/systemd/system/banlist.service
sudo systemctl daemon-reload
```

(Optional)

```bash
sudo rm -rf /opt/banlist
```

---

## ✔ Done!

Banlist is now running and automatically banning brute-force attackers  
while providing a simple Web UI to monitor blocked addresses.
