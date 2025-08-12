# mr_prince/cli.py
"""
mr_prince — Advanced self-contained CLI Port Scanner
(Secret Code: PORTSCANNER-AI-2025-CLI)

No external libs. Pure Python socket/threading/queue.
"""

import socket
import threading
import argparse
from queue import Queue
from datetime import datetime
import sys
import time

# Defaults
BANNER_TIMEOUT = 1.5
CONNECT_TIMEOUT = 0.6
DEFAULT_THREADS = 100
MAX_THREADS = 500
PRINT_LOCK = threading.Lock()

ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_RESET = "\033[0m"

ASCII_BANNER = r"""
███╗   ███╗██████╗         ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗███████╗
████╗ ████║██╔══██╗        ██╔══██╗██╔══██╗██║████╗  ██║██╔════╝██╔════╝
██╔████╔██║██████╔╝        ██████╔╝██████╔╝██║██╔██╗ ██║██║     █████╗  
██║╚██╔╝██║██╔══██╗        ██╔═══╝ ██╔══██╗██║██║╚██╗██║██║     ██╔══╝  
██║ ╚═╝ ██║██║  ██║███████╗██║     ██║  ██║██║██║ ╚████║╚██████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
                        mr_prince
"""

# Common port -> service hints (used for guessing even without banner)
COMMON_PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 587: "smtp-submission", 631: "ipp", 3306: "mysql",
    3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt"
}

def print_banner():
    print(ASCII_BANNER)

def safe_recv(sock, timeout):
    try:
        sock.settimeout(timeout)
        return sock.recv(2048)
    except Exception:
        return b""

def probe_for_service(sock, port, timeout):
    """
    Send lightweight, safe probes for likely services to elicit banners.
    Only probes a few well-known protocols; doesn't send anything dangerous.
    """
    try:
        sock.settimeout(timeout)
        # decide probe by common port
        hint = COMMON_PORT_SERVICES.get(port, "").lower()
        if "http" in hint or port in (80, 8080, 8000, 8888):
            # HTTP probe
            try:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            except Exception:
                pass
        elif "smtp" in hint or port in (25,587):
            try:
                sock.sendall(b"HELO example.com\r\n")
            except Exception:
                pass
        elif "ftp" in hint or port in (21,20):
            # many FTP servers send banner immediately; send nothing
            pass
        elif "mysql" in hint or port == 3306:
            # MySQL sends a greeting automatically; no probe
            pass
        # default: send a newline to encourage simple text banners
        else:
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
    except Exception:
        pass

def decode_banner(data_bytes):
    if not data_bytes:
        return None
    try:
        return data_bytes.decode("utf-8", errors="replace").strip()
    except Exception:
        try:
            return data_bytes.decode(errors="replace").strip()
        except Exception:
            return repr(data_bytes)[:200]

class Scanner:
    def __init__(self, target, ports, threads=DEFAULT_THREADS, timeout=CONNECT_TIMEOUT, banner_timeout=BANNER_TIMEOUT, do_banner=True, color=True, verbose=False):
        self.target = target
        self.ports = ports
        self.threads = max(1, min(MAX_THREADS, threads))
        self.timeout = max(0.05, float(timeout))
        self.banner_timeout = max(0.05, float(banner_timeout))
        self.do_banner = do_banner
        self.color = color
        self.verbose = verbose
        self.ip = None
        self.q = Queue()
        self.results = []  # list of (port, banner or None, guessed_service)

    def resolve(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            return True
        except Exception as e:
            print(f"[!] Could not resolve {self.target}: {e}")
            return False

    def guess_service(self, port, banner_text):
        # If banner contains obvious service names, use them
        if banner_text:
            b = banner_text.lower()
            if "ssh" in b:
                return "ssh"
            if "http" in b or "html" in b or "apache" in b or "nginx" in b:
                return "http"
            if "smtp" in b or "esmtp" in b:
                return "smtp"
            if "ftp" in b:
                return "ftp"
            if "mysql" in b or "mariadb" in b:
                return "mysql"
            if "rdp" in b or "microsoft" in b:
                return "rdp"
            if "vnc" in b:
                return "vnc"
            if "pop3" in b:
                return "pop3"
            if "imap" in b:
                return "imap"
        # fallback to common port mapping
        return COMMON_PORT_SERVICES.get(port, "unknown")

    def scan_port(self, port):
        banner_text = None
        guessed = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                rc = sock.connect_ex((self.ip, port))
                if rc == 0:
                    # optional banner grabbing / probing
                    if self.do_banner:
                        # try to receive any immediate banner
                        data = safe_recv(sock, self.banner_timeout * 0.5)
                        if not data:
                            # probe lightly to coax response
                            probe_for_service(sock, port, self.banner_timeout * 0.5)
                            data = safe_recv(sock, self.banner_timeout * 0.5)
                        banner_text = decode_banner(data)
                    guessed = self.guess_service(port, banner_text)
                    with PRINT_LOCK:
                        if self.color:
                            print(f"{ANSI_GREEN}[+] {self.target}:{port} OPEN{ANSI_RESET}", end="")
                            if banner_text:
                                print(f" {ANSI_YELLOW}— {banner_text[:200]}{ANSI_RESET}", end="")
                            print(f" {ANSI_YELLOW}[{guessed}]{ANSI_RESET}")
                        else:
                            out = f"[+] {self.target}:{port} OPEN"
                            if banner_text: out += f" — {banner_text[:200]}"
                            out += f" [{guessed}]"
                            print(out)
                    self.results.append((port, banner_text, guessed))
                else:
                    if self.verbose:
                        with PRINT_LOCK:
                            print(f"{ANSI_RED}[-] {self.target}:{port} closed/filtered (rc={rc}){ANSI_RESET}" if self.color else f"[-] {self.target}:{port} closed/filtered")
        except Exception:
            # ignore errors per port
            if self.verbose:
                with PRINT_LOCK:
                    print(f"{ANSI_RED}[!] Exception scanning {self.target}:{port}{ANSI_RESET}" if self.color else f"[!] Exception scanning {self.target}:{port}")
        return

    def worker(self):
        while True:
            port = self.q.get()
            if port is None:
                self.q.task_done()
                break
            self.scan_port(port)
            self.q.task_done()

    def run(self):
        if not self.resolve():
            return
        print(ASCII_BANNER)
        print(f"[mr] Scanning {self.target} ({self.ip})")
        print(f"[mr] Ports: {self.ports_str()}  Threads: {self.threads}  Banner-grab: {self.do_banner}")
        print(f"[mr] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # start threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        # queue ports
        for p in self.ports:
            self.q.put(p)

        self.q.join()

        # stop workers
        for _ in threads:
            self.q.put(None)
        for t in threads:
            t.join(timeout=0.01)

        print(f"\n[mr] Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        # optionally return results
        return self.results

    def ports_str(self):
        if len(self.ports) > 40:
            return f"{min(self.ports)}-{max(self.ports)} ({len(self.ports)} ports)"
        else:
            return ",".join(str(p) for p in self.ports)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            start = int(start.strip())
            end = int(end.strip())
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)

def build_arg_parser():
    p = argparse.ArgumentParser(prog="mr", description="mr_prince — PORTSCANNER-AI-2025-CLI (pure Python)")
    p.add_argument("target", help="Target hostname or IP")
    p.add_argument("-p", "--ports", default="1-1024", help="Ports: range (1-1024) or list (22,80,443) or both")
    p.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Number of threads (default 100)")
    p.add_argument("--no-banner", action="store_true", help="Disable banner grabbing/probing")
    p.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT, help="Connect timeout seconds (default 0.6)")
    p.add_argument("--banner-timeout", type=float, default=BANNER_TIMEOUT, help="Banner/receive timeout seconds")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colored output")
    p.add_argument("--verbose", action="store_true", help="Print closed ports and errors (verbose)")
    return p

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        ports = parse_ports(args.ports)
    except Exception:
        print("[!] Invalid port specification. Use e.g. 1-1024 or 22,80,443")
        return 2
    sc = Scanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        banner_timeout=args.banner_timeout,
        do_banner=(not args.no_banner),
        color=(not args.no_color),
        verbose=args.verbose
    )
    sc.run()
    return 0

if __name__ == "__main__":
    sys.exit(main())

