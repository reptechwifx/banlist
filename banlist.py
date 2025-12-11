import os
import socket
import time
import threading
from datetime import datetime, timedelta
import re
import ipaddress
import argparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


# === Configuration ===
AUTH_LOG_FILE = "/var/log/auth.log"
IPV4_FILE = "ipv4.txt"
IPV6_FILE = "ipv6.txt"
WHITELIST_FILE = "whitelist.txt"
BLOCK_DURATION_HOURS = 12
FAILURE_THRESHOLD = 3  # Number of failures before banning an IP

# === In-Memory Stores ===
blocked_ips = {}       # ip -> timestamp of ban
failed_counts = {}     # ip -> number of failures
whitelist = []         # list of ip_network objects

# === Regex for SSH/Telnet log lines (IPv4 or IPv6) ===
REGEX_PATTERNS = [
    re.compile(r"telnetd.*Failed.*from\s+([0-9a-fA-F\.:]+)"),
    re.compile(r"sshd\S*\[\d+\]: Failed password .* from ([0-9a-fA-F\.:]+)"),
    re.compile(r"sshd\S*\[\d+\]: Invalid user .* from ([0-9a-fA-F\.:]+)"),
    re.compile(r"sshd\S*\[\d+\]: .*rhost=([0-9a-fA-F\.:]+)"),
    re.compile(r"login\[\d+\]: pam_unix\(login:auth\): authentication failure;.*rhost=([\w\.\-\:]+)"),
    re.compile(r"login\[\d+\]: FAILED LOGIN \(\d+\) on '.*' from '([\w\.\-\:]+)'"),
    re.compile(r"login\[\d+\]: TOO MANY LOGIN TRIES .* from '([\w\.\-\:]+)'"),
]


# === Web UI ===

class BanlistHTTPRequestHandler(BaseHTTPRequestHandler):
    def setup(self):
        # Timeout de 10s par connexion, à ajuster si tu veux
        self.request.settimeout(10)
        super().setup()


    def _read_lines(self, path):
        try:
            with open(path, "r") as f:
                return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            return []

    def _send_plain(self, content, code=200):
        content_bytes = content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)

    def _send_html(self, content, code=200):
        content_bytes = content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)

    def do_GET(self):
        if self.path == "/ipv4.txt":
            lines = self._read_lines(IPV4_FILE)
            self._send_plain("\n".join(lines) + ("\n" if lines else ""))
            return

        if self.path == "/ipv6.txt":
            lines = self._read_lines(IPV6_FILE)
            self._send_plain("\n".join(lines) + ("\n" if lines else ""))
            return

        # Page HTML principale
        ipv4_list = self._read_lines(IPV4_FILE)
        ipv6_list = self._read_lines(IPV6_FILE)

        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            "<title>Banlist</title>",
            "<style>",
            "body { font-family: sans-serif; margin: 20px; }",
            "h1 { margin-bottom: 0.2em; }",
            "h2 { margin-top: 1.5em; }",
            "table { border-collapse: collapse; min-width: 200px; }",
            "th, td { border: 1px solid #ccc; padding: 4px 8px; }",
            "th { background: #eee; }",
            "code { background: #f5f5f5; padding: 2px 4px; }",
            "</style>",
            "</head>",
            "<body>",
            "<h1>Banlist</h1>",
            f"<p>Generated at: {datetime.now().isoformat(timespec='seconds')}</p>",
            "<p>",
            "Raw files: ",
            "<a href='/ipv4.txt'>ipv4.txt</a> | ",
            "<a href='/ipv6.txt'>ipv6.txt</a>",
            "</p>",
            "<h2>IPv4 banned</h2>",
        ]

        if ipv4_list:
            html.append("<table>")
            html.append("<tr><th>#</th><th>IP</th></tr>")
            for idx, ip in enumerate(ipv4_list, start=1):
                html.append(f"<tr><td>{idx}</td><td><code>{ip}</code></td></tr>")
            html.append("</table>")
        else:
            html.append("<p><em>Aucune IP IPv4 bannie pour l’instant.</em></p>")

        html.append("<h2>IPv6 banned</h2>")
        if ipv6_list:
            html.append("<table>")
            html.append("<tr><th>#</th><th>IP</th></tr>")
            for idx, ip in enumerate(ipv6_list, start=1):
                html.append(f"<tr><td>{idx}</td><td><code>{ip}</code></td></tr>")
            html.append("</table>")
        else:
            html.append("<p><em>Aucune IP IPv6 bannie pour l’instant.</em></p>")

        html.append("</body></html>")
        self._send_html("\n".join(html))

    # Évite le spam de logs dans stderr systemd
    def log_message(self, format, *args):
        print(f"[http] {self.address_string()} - {format % args}")


def run_web_server(host: str, port: int):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, BanlistHTTPRequestHandler)
    print(f"[*] Web UI running on http://{host}:{port} (IPv4/IPv6 ban files)")
    httpd.serve_forever()


# === Utility Functions ===

def resolve_ip(raw):
    # Return IP address, whether input is IP or hostname
    try:
        ip_obj = ipaddress.ip_address(raw)
        return str(ip_obj)  # already an IP
    except ValueError:
        try:
            resolved = socket.getaddrinfo(raw, None)
            for res in resolved:
                ip = res[4][0]
                return ip
        except socket.gaierror:
            print(f"[!] Failed to resolve hostname: {raw}")
            return None


def is_ipv6(ip):
    return ':' in ip


def load_whitelist():
    global whitelist
    whitelist = []
    try:
        with open(WHITELIST_FILE, "r") as f:
            for line in f:
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    try:
                        whitelist.append(ipaddress.ip_network(entry, strict=False))
                    except ValueError:
                        print(f"[!] Invalid whitelist entry skipped: {entry}")
    except FileNotFoundError:
        pass


def is_whitelisted(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in whitelist)
    except ValueError:
        return False


def log_failed_ip(ip_raw):
    ip = resolve_ip(ip_raw)
    if ip is None:
        return

    now = datetime.now()

    if is_whitelisted(ip):
        print(f"[~] Whitelisted IP ignored: {ip}")
        return

    if ip in blocked_ips:
        print(f"[-] IP already banned: {ip}")
        return

    failed_counts[ip] = failed_counts.get(ip, 0) + 1
    print(f"[!] Failure {failed_counts[ip]}/{FAILURE_THRESHOLD} for IP: {ip}")

    if failed_counts[ip] >= FAILURE_THRESHOLD:
        blocked_ips[ip] = now
        file_path = IPV6_FILE if is_ipv6(ip) else IPV4_FILE
        with open(file_path, "a") as f:
            f.write(f"{ip}\n")
        print(f"[+] IP banned: {ip}")


def cleanup_old_ips():
    while True:
        time.sleep(300)
        cutoff = datetime.now() - timedelta(hours=BLOCK_DURATION_HOURS)
        new_blocked = {ip: ts for ip, ts in blocked_ips.items() if ts > cutoff}

        # Rewrite ban files
        with open(IPV4_FILE, "w") as f4, open(IPV6_FILE, "w") as f6:
            for ip in new_blocked:
                if is_whitelisted(ip):
                    continue
                if is_ipv6(ip):
                    f6.write(f"{ip}\n")
                else:
                    f4.write(f"{ip}\n")

        print(f"[~] Cleanup complete at {datetime.now()}")

        blocked_ips.clear()
        blocked_ips.update(new_blocked)

        # Clear failed_counts for expired or banned IPs
        active_ips = set(blocked_ips.keys())
        for ip in list(failed_counts.keys()):
            if ip not in active_ips:
                del failed_counts[ip]


def tail_log():
    """
    Lecture continue de AUTH_LOG_FILE avec gestion de la rotation,
    équivalent à `tail -F`.
    """
    print(f"[*] Tailing {AUTH_LOG_FILE} (avec gestion de la rotation)")
    while True:
        try:
            with open(AUTH_LOG_FILE, "r") as f:
                # Aller à la fin du fichier existant
                f.seek(0, os.SEEK_END)
                current_inode = os.fstat(f.fileno()).st_ino

                while True:
                    line = f.readline()
                    if line:
                        # On a une nouvelle ligne -> on l'analyse
                        for pattern in REGEX_PATTERNS:
                            match = pattern.search(line)
                            if match:
                                ip = match.group(1)
                                log_failed_ip(ip)
                                break
                    else:
                        # Pas de nouvelle ligne, on attend un peu
                        time.sleep(0.5)

                        # Vérifier si le fichier a été rotaté ou tronqué
                        try:
                            st = os.stat(AUTH_LOG_FILE)
                        except FileNotFoundError:
                            # auth.log pas encore recréé (juste après rotation)
                            print("[*] auth.log introuvable, en attente de recréation...")
                            break  # on sort pour relire dans la boucle externe

                        # Si l'inode change, c'est qu'on a un nouveau fichier
                        # Si la taille est plus petite que notre position, il a été tronqué
                        if st.st_ino != current_inode or st.st_size < f.tell():
                            print("[*] Rotation/tronquage de auth.log détecté, réouverture...")
                            break  # on sort de la boucle interne pour rouvrir

        except FileNotFoundError:
            print(f"[!] {AUTH_LOG_FILE} n'existe pas encore, nouvelle tentative dans 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"[!] Erreur dans tail_log(): {e}, on retente dans 5s...")
            time.sleep(5)


def parse_args():
    parser = argparse.ArgumentParser(description="Banlist daemon with simple web UI")
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port HTTP pour la web UI (défaut: 8080)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Adresse d'écoute HTTP (défaut: 0.0.0.0)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Clear block files at startup
    open(IPV4_FILE, "w").close()
    open(IPV6_FILE, "w").close()

    print("[*] Starting fresh. Cleared ban files.")
    load_whitelist()
    print(f"[*] Loaded {len(whitelist)} whitelist entries.")

    # Start cleanup thread
    cleaner_thread = threading.Thread(target=cleanup_old_ips, daemon=True)
    cleaner_thread.start()

    # Start web UI thread
    web_thread = threading.Thread(
        target=run_web_server, args=(args.host, args.port), daemon=True
    )
    web_thread.start()

    print("[*] Watching auth.log for SSH/Telnet failures...")
    tail_log()


if __name__ == "__main__":
    main()
