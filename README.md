# IAST Tool — Internal Assessment & Scanning Toolkit

> İç ağ sızma testi için modüler Python aracı.  
> **Windows 10/11** ve **Linux (Kali)** üzerinde çalışır.

---

## Özellikler

| Modül | Açıklama | Windows | Linux |
|-------|----------|---------|-------|
| Host Discovery | Nmap ping tarama, alive host tespiti | ✅ | ✅ |
| TCP Scan | Nmap servis/versiyon tarama | ✅ | ✅ |
| TCP Scan (Hızlı) | RustScan + Nmap pipeline | ❌ | ✅ |
| UDP Scan | Nmap -sU ile yaygın UDP portları | ✅* | ✅* |
| FTP Analysis | .nmap çıktısından FTP servis tespiti | ✅ | ✅ |
| Telnet Analysis | .nmap çıktısından Telnet servis tespiti | ✅ | ✅ |

> \* UDP tarama yönetici/root yetkisi gerektirir.

---

## Proje Yapısı

```
IAST_tool/
├── main.py                      # Ana giriş noktası
├── requirements.txt
├── config/
│   └── settings.py              # Merkezi path/parametre konfigürasyon
├── core/
│   ├── logger.py                # Merkezi logging (konsol + dosya)
│   ├── platform_utils.py        # OS tespiti, güvenli subprocess
│   ├── validators.py            # IP/input validasyonu
│   └── dependency_checker.py    # Nmap/Npcap/RustScan kontrolü
├── modules/
│   ├── discovery/
│   │   └── host_discovery.py    # Host keşfi
│   ├── scans/
│   │   ├── scan_menu.py         # Tarama menüsü
│   │   ├── tcp_scan.py          # TCP tarama
│   │   ├── udp_scan.py          # UDP tarama
│   │   ├── inputs/              # alive_hosts.txt vb.
│   │   └── outputs/             # Nmap çıktıları
│   ├── vuln/
│   │   ├── vuln_menu.py         # Zafiyet menüsü
│   │   ├── ftp.py               # FTP analizi
│   │   ├── telnet.py            # Telnet analizi
│   │   ├── inputs/              # Kullanıcı input dosyaları
│   │   └── outputs/             # Zafiyet çıktıları
│   └── reports/
│       ├── report_generator.py  # JSON rapor üreticisi
│       └── outputs/             # report_YYYYMMDD_HHMMSS.json
└── logs/                        # Otomatik oluşturulur: iast_YYYYMMDD.log
```

---

## Kurulum

### Windows Kurulum Rehberi

**1. Python 3.10+**
```
https://www.python.org/downloads/
```
Kurulum sırasında **"Add Python to PATH"** seçeneğini işaretleyin.

**2. Nmap**
```
https://nmap.org/download.html
```
Windows installer'ı indirip kurun. Npcap kurulumu da dahildir.

**3. Npcap (ayrı kurulum — raw socket taramaları için)**
```
https://npcap.com/#download
```

**4. Python bağımlılıkları**
```powershell
cd C:\Users\...\IAST_tool
pip install -r requirements.txt
```

**5. Çalıştır (Yönetici olarak PowerShell/CMD açın)**
```powershell
python main.py
```

> **Not:** Host Discovery ve UDP Scan için **Yönetici yetkisi** gereklidir.  
> PowerShell'i sağ tıklayıp "Yönetici olarak çalıştır" seçin.

---

### Linux (Kali) Kurulum Rehberi

**1. Nmap**
```bash
sudo apt install nmap
```

**2. RustScan (opsiyonel — hızlı TCP tarama)**
```bash
# Kali reposundan
sudo apt install rustscan
# veya
cargo install rustscan
```

**3. Python bağımlılıkları**
```bash
pip install -r requirements.txt
```

**4. Çalıştır**
```bash
sudo python main.py
```

---

## Kullanım

```
=== MAIN MENU ===
1 - Host Discovery
2 - Scans (TCP / UDP / AUTO)
3 - Vulnerability Analysis
0 - Exit
```

### Örnek Senaryo 1 — Tam Ağ Sızma Testi

```
1. Ana Menü → 1 (Host Discovery)
   IP Range: 192.168.1.0/24
   → Çıktı: modules/scans/inputs/alive_hosts.txt

2. Ana Menü → 2 (Scans)
   Scan: 0 (AUTO — TCP + UDP)
   Input: 1 (Discovery çıktısı kullan)
   → Çıktı: modules/scans/outputs/tcp_alive_hosts_full.txt

3. Ana Menü → 3 (Vulnerability Analysis)
   Analiz: 1 (FTP) veya 2 (Telnet)
   Input: 1 (Scan outputs kullan)
   → Çıktı: modules/vuln/outputs/ftp_*.txt
```

### Örnek Senaryo 2 — Kendi Host Listesiyle Tarama

```
1. Kendi hosts.txt dosyanızı şuraya koyun:
   modules/scans/inputs/hosts.txt

2. Ana Menü → 2 (Scans) → TCP Scan
   Input: 2 (Kendi dosyamı ver)
   Dosya adı: hosts.txt
```

## Rapor Dosyaları

Her zafiyet analizi tamamlandığında `modules/reports/outputs/` altına JSON rapor kaydedilir:

```json
{
  "tool": "IAST Tool v2.0.0",
  "generated_at": "2026-05-16T12:00:00",
  "scan_type": "FTP Analysis",
  "target_source": "modules/scans/outputs",
  "findings": [
    {
      "ip": "192.168.1.10",
      "service": "FTP",
      "url": "ftp://192.168.1.10",
      "port": 21,
      "risk": "HIGH"
    }
  ],
  "summary": {
    "total_findings": 1,
    "unique_hosts": 1
  }
}
```

---

## Log Dosyaları

Tüm işlemler `logs/iast_YYYYMMDD.log` dosyasına kaydedilir:

```
2026-05-16 12:00:00 [INFO]  iast.discovery — Nmap discovery başlıyor... Hedef: 192.168.1.0/24
2026-05-16 12:00:15 [INFO]  iast.discovery — [+] 5 alive host kaydedildi
2026-05-16 12:00:20 [INFO]  iast.scans.tcp — TCP tarama başlıyor (Nmap) — 5 host, 3 thread
```

---

## Gereksinimler

| Araç | Zorunlu | Not |
|------|---------|-----|
| Python 3.10+ | ✅ | |
| Nmap | ✅ | Windows + Linux |
| Npcap | ✅ Windows | Raw socket için |
| RustScan | ❌ Opsiyonel | Yalnızca Linux, hızlı TCP tarama |
| colorama | ✅ | `pip install colorama` |
| rich | ❌ Opsiyonel | `pip install rich` — gelişmiş UI |
