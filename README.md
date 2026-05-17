# IAST Tool — Internal Assessment & Scanning Toolkit

IAST Tool, kurumsal iç ağlarda güvenlik açıklarını tespit etmek amacıyla geliştirilmiş modüler bir sızma testi aracıdır. Araç; ağ keşfi, port tarama ve zafiyet analizi aşamalarını sıralı biçimde yürütür ve tüm bulguları JSON formatında raporlar. Hem **Windows 10/11** hem de **Linux (Kali)** üzerinde çalışacak şekilde tasarlanmıştır.

---

## Proje Amacı

İç ağlarda çalışan güvensiz servislerin (FTP, Telnet, SSH gibi şifrelenmemiş veya eski protokollerin) tespit edilmesi güvenlik denetimlerinin temel adımlarından biridir. IAST Tool bu süreci otomatize eder:

1. Ağdaki aktif cihazları keşfeder
2. Açık portları ve çalışan servisleri tespit eder
3. Güvensiz protokolleri analiz eder ve raporlar

---

## Modüller ve Dosya Açıklamaları

### `main.py`
Uygulamanın giriş noktasıdır. Ana menüyü gösterir ve kullanıcının seçimine göre ilgili modülü çağırır. `rich` kütüphanesi yüklüyse gelişmiş terminal arayüzü, yoksa sade metin tabanlı menü kullanılır.

### `config/settings.py`
Tüm dizin yolları, tarama parametreleri ve uygulama sabitleri bu dosyada merkezi olarak tanımlanır. Herhangi bir yolu veya parametreyi değiştirmek için tek bir dosyaya bakmak yeterlidir.

### `core/logger.py`
Merkezi loglama modülüdür. Log mesajları hem renkli olarak terminale yazdırılır hem de `logs/iast_YYYYMMDD.log` dosyasına kaydedilir.

### `core/platform_utils.py`
İşletim sistemi tespiti ve güvenli `subprocess` yardımcılarını içerir. Nmap ve RustScan'in sistem üzerindeki yolunu bulur. `shell=False` kullanarak komut enjeksiyonu riskini ortadan kaldırır.

### `core/validators.py`
Kullanıcıdan alınan IP adresi, CIDR notasyonu ve dosya adı girdilerini doğrular.

### `core/dependency_checker.py`
Program başlangıcında Nmap, Npcap (Windows) ve Python paketlerinin kurulu olup olmadığını kontrol eder.

### `modules/discovery/host_discovery.py`
Nmap'in ping tarama modunu (`-sn`) kullanarak belirtilen IP aralığındaki aktif cihazları bulur. Sonuçları `modules/scans/inputs/alive_hosts.txt` dosyasına yazar.

### `modules/scans/tcp_scan.py`
TCP port taramasını yürütür. `ThreadPoolExecutor` ile birden fazla hostu paralel olarak tarar. İki mod sunar: sık kullanılan 24 portu tarayan **hızlı mod** ve 0-65535 arası tüm portları tarayan **tam mod**.

### `modules/scans/udp_scan.py`
Nmap `-sU` komutuyla en yaygın UDP portlarını tarar. Raw socket kullandığı için yönetici/root yetkisi gerektirir.

### `modules/vuln/ftp.py`
TCP scan çıktılarını parse ederek açık FTP servisi (port 21) bulunan cihazları listeler. FTP şifrelenmemiş bir protokol olduğundan yüksek risk olarak değerlendirilir.

### `modules/vuln/telnet.py`
TCP scan çıktılarını parse ederek açık Telnet servisi (port 23) bulunan cihazları tespit eder. Telnet de şifrelenmemiş olduğundan yüksek risk taşır.

### `modules/vuln/ssh.py`
Açık SSH servislerini tespit etmenin yanı sıra banner bilgisini (servis versiyonu) de yakalar. Eski SSH versiyonları bilinen güvenlik açıkları barındırabileceğinden versiyon bilgisi kritik öneme sahiptir.

### `modules/reports/report_generator.py`
Zafiyet analizi tamamlandığında bulguları JSON formatında raporlar. Her rapor, tespit edilen servisi, IP adresini, port numarasını ve risk seviyesini (HIGH / MEDIUM / LOW) içerir.

---

## Proje Yapısı

```
IAST_tool/
├── main.py
├── requirements.txt
├── config/
│   └── settings.py
├── core/
│   ├── logger.py
│   ├── platform_utils.py
│   ├── validators.py
│   └── dependency_checker.py
├── modules/
│   ├── discovery/
│   │   └── host_discovery.py
│   ├── scans/
│   │   ├── scan_menu.py
│   │   ├── tcp_scan.py
│   │   └── udp_scan.py
│   ├── vuln/
│   │   ├── vuln_menu.py
│   │   ├── ftp.py
│   │   ├── ssh.py
│   │   └── telnet.py
│   └── reports/
│       └── report_generator.py
└── logs/
```

---

## Kurulum

### Windows

```powershell
# 1. Nmap'i kur (Npcap dahil): https://nmap.org/download.html
# 2. Python bağımlılıklarını yükle
pip install -r requirements.txt
# 3. Yönetici olarak PowerShell aç ve çalıştır
python main.py
```

### Linux (Kali)

```bash
sudo apt install nmap
pip install -r requirements.txt
sudo python main.py
```

> UDP Scan ve Host Discovery için **yönetici/root** yetkisi gereklidir.

---

## Kullanım

Program başlatıldığında ana menü gösterilir:

```
1 - Host Discovery
2 - Scans (TCP Hızlı / TCP Tam / UDP)
3 - Vulnerability Analysis (FTP / Telnet / SSH)
0 - Exit
```

**Tipik kullanım akışı:**
1. **Host Discovery** → Ağ aralığını gir → Aktif cihazlar `alive_hosts.txt`'e kaydedilir
2. **Scans → TCP Hızlı** → Discovery çıktısını kullan → Scan sonuçları `modules/scans/outputs/` altına yazılır
3. **Vulnerability Analysis** → Scan çıktıları üzerinde FTP / Telnet / SSH analizi yapılır → JSON rapor üretilir

---

## Çıktılar

| Tür | Konum |
|---|---|
| Alive hosts | `modules/scans/inputs/alive_hosts.txt` |
| TCP scan çıktıları | `modules/scans/outputs/` |
| Zafiyet çıktıları | `modules/vuln/outputs/` |
| JSON raporlar | `modules/reports/outputs/report_YYYYMMDD_HHMMSS.json` |
| Log dosyaları | `logs/iast_YYYYMMDD.log` |

---

## Gereksinimler

| Araç | Zorunlu | Not |
|---|---|---|
| Python 3.10+ | ✅ | |
| Nmap | ✅ | Windows + Linux |
| Npcap | ✅ Windows | Raw socket desteği |
| colorama | ✅ | `pip install colorama` |
| RustScan | ❌ Opsiyonel | Yalnızca Linux, hızlı TCP tarama |
| rich | ❌ Opsiyonel | Gelişmiş terminal UI |
