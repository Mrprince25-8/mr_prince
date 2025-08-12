```markdown
<h1 align="center">⚡ mr_prince — PORTSCANNER-2025-CLI ⚡</h1>

<p align="center">
<img src="https://img.shields.io/badge/Python-3.8%2B-blue" />
<img src="https://img.shields.io/badge/License-MIT-green" />
<img src="https://img.shields.io/badge/Threads-500%2B-orange" />
<img src="https://img.shields.io/badge/Dependency-Free-success" />
</p>


███╗   ███╗██████╗         ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗███████╗
████╗ ████║██╔══██╗        ██╔══██╗██╔══██╗██║████╗  ██║██╔════╝██╔════╝
██╔████╔██║██████╔╝        ██████╔╝██████╔╝██║██╔██╗ ██║██║     █████╗
██║╚██╔╝██║██╔══██╗        ██╔═══╝ ██╔══██╗██║██║╚██╗██║██║     ██╔══╝
██║ ╚═╝ ██║██║  ██║███████╗██║     ██║  ██║██║██║ ╚████║╚██████╗███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
```
###  🛠 Overview

**mr_prince** is a **pure Python**, **high-performance**, and **dependency-free**  
CLI port scanner for security professionals. Inspired by `nmap`, but built from scratch  
with full source control so you can tweak, extend, and optimize it without external tools.

---

###  ✨ Features

- **🚀 Pure Python** — No `nmap`, no `masscan`, no 3rd-party scanners.
- **⚡ Multi-threaded scanning** — Up to **500 concurrent scans**.
- **🔍 Banner grabbing** — Get service information for open ports.
- **🎯 Flexible port selection** — Ranges (`1-1000`), lists (`22,80,443`), single ports.
- **⚙️ Adjustable timeouts** — Trade speed for reliability.
- **📦 Single file executable** — Easy to deploy anywhere.
- **🖥 Cross-platform** — Runs on Linux, macOS, and Windows.
- **🛡 Ethical by default** — Designed for authorized penetration testing.
##  📥 Installation
### 1️⃣ Clone and Install
```bash
git clone https://github.com/yourusername/mr_prince.git
cd mr_prince
pip install .
````
### 2️⃣ Global Command Setup

After installation, run:

```bash
mr --help
```

Now `mr` works just like `nmap`.

---

## 📌 Usage

Basic syntax:

```bash
mr TARGET [OPTIONS]
```

| Option             | Description                                    |
| ------------------ | ---------------------------------------------- |
| `-p` / `--ports`   | Port(s) to scan. (`1-1024`, `22,80,443`, `80`) |
| `-t` / `--threads` | Number of threads (default: 100, max: 500)     |
| `--timeout`        | Connection timeout in seconds (default: 0.6)   |
| `--no-banner`      | Skip banner grabbing (faster, quieter)         |

---

## 📚 Examples

### Scan common web ports

```bash
mr scanme.nmap.org -p 80,443
```

### Full range scan with max speed

```bash
mr example.com -p 1-65535 -t 500
```

### Local network scan with banners

```bash
mr 192.168.1.10 -p 1-1024
```

### Quiet, stealthy mode

```bash
mr target.com -p 22,80,443 --no-banner
```

---

## 📊 Example Output

```
[mr_prince] Scanning scanme.nmap.org (45.33.32.156)
[mr_prince] Ports: 22,80,443  Threads: 100  Banner-grab: True
[mr_prince] Started at: 2025-08-12 14:22:01

[+] scanme.nmap.org:22 OPEN — banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
[+] scanme.nmap.org:80 OPEN — banner: Apache/2.4.41 (Ubuntu)
[+] scanme.nmap.org:443 OPEN — banner: TLS handshake successful

[mr_prince] Scan finished at: 2025-08-12 14:22:05
```

---

## 🆘 Help Menu

```bash
mr --help
```

Output:

```
usage: mr target [-p PORTS] [-t THREADS] [--no-banner] [--timeout SECONDS]

mr_prince — PORTSCANNER-AI-2025-CLI

positional arguments:
  target               Target hostname or IP

options:
  -p, --ports          Ports to scan. Range (1-1024), comma list (22,80,443), or single (80)
  -t, --threads        Number of threads (default 100)
  --no-banner          Disable banner grabbing
  --timeout            Connection timeout in seconds (default 0.6)
```

---

## 🆚 Why mr\_prince Over Others?

* **No bloat** — zero external dependencies.
* **Direct socket control** — tweak everything down to packet level.
* **Full source code ownership** — modify, extend, automate.
* **Faster targeted scans** — ideal for precise penetration testing.

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**.
Scanning systems you do not own or have permission for **is illegal**
and punishable by law in most countries.

---

## 🤝 Contributing

1. Fork the repo.
2. Create a new branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m "Description"`
4. Push and open a Pull Request.

## 📜 License & Usage Terms

**mr_prince** is released under the **MIT License**, meaning you are free to  
use, modify, and distribute this tool — **but only for lawful and authorized purposes**.

By using this software, you agree to:

1. **Obtain explicit permission** from the system owner before scanning.
2. **Comply with all local, national, and international laws** regarding cybersecurity.
3. Accept that **the author assumes no liability** for misuse or damages caused.
4. Understand that **unauthorized port scanning is illegal** in many countries and  
   may result in criminal prosecution.

> **Ethical Note:** This project is created for penetration testers, security researchers,  and system administrators to strengthen their own networks — not to harm others.

---

**MIT License — Summary:**
- ✅ Commercial and private use allowed
- ✅ Modification and redistribution allowed
- ❌ No warranty — software is provided "as is"
- ❌ No liability for damages

Full license text is available in the [`LICENSE`](LICENSE) file.

