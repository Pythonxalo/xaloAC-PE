# 🛡️ xaloAC - Güvenli Tersine Mühendislik ve İkilik Analiz Aracı

**xaloAC**, devlet kurumları, kritik altyapılar ve siber güvenlik analistleri için geliştirilmiş, `.exe` ve `.dll` uzantılı taşınabilir çalıştırılabilir (PE) dosyalarını otomatik olarak ayrıştıran (decompile) ve analiz eden gelişmiş bir siber güvenlik aracıdır.

Bu araç, hedef yazılımın mimarisini otomatik olarak tespit ederek uygun tersine mühendislik motorunu (ILSpy veya Ghidra) devreye sokar ve kaynak kodları analiz edilebilir formatta dışa aktarır.

## ✨ Özellikler

*   🔍 **Otomatik Mimari Tespiti:** İkilik dosya başlıklarını (PE Headers) inceleyerek `.NET` (Yönetilen Kod) veya `Native` (C/C++) ayrımını otomatik yapar.
*   💻 **Çift Motor Desteği:** 
    *   `.NET` uygulamaları için **ILSpy** entegrasyonu.
    *   `Yerel (Native)` uygulamalar için **Ghidra Headless** entegrasyonu.
*   🧮 **Kriptografik İmza Hesaplama:** Analiz edilen her dosyanın `SHA-256` ve `MD5` özetlerini çıkarır.
*   📋 **Resmi Raporlama ve Denetim:** Kurumsal standartlara uygun JSON manifestoları ve metin tabanlı analiz özetleri üretir.
*   🤖 **İnteraktif Sihirbaz:** Parametre girmeden, sadece dosyayı sürükle-bırak yöntemiyle çalıştırabileceğiniz kullanıcı dostu arayüz.

## 🚀 Kurulum ve Gereksinimler

Projenin tüm özellikleriyle çalışabilmesi için sisteminizde aşağıdaki araçların kurulu olması önerilir:

1.  **Python 3.x**
2.  **.NET Kod Çözümü İçin:** `ilspycmd` aracı.
    ```bash
    dotnet tool install -g ilspycmd
    ```
3.  **Yerel Kod Çözümü İçin:** **Ghidra** yazılımı ve `GHIDRA_HOME` ortam değişkeninin tanımlanması.

## 🛠️ Kullanım

### 1. İnteraktif Mod (Sihirbaz)
Herhangi bir parametre vermeden betiği çalıştırarak sihirbazı başlatabilirsiniz:
```bash
python xaloAC.py
```

### 2. Komut Satırı Modu (CLI)
Belirli parametrelerle doğrudan analiz başlatmak için:
```bash
# Otomatik analiz başlatma
python xaloAC.py "analiz_edilecek_dosya.exe"

# Özel çıktı dizini ve motor zorlama
python xaloAC.py "analiz_edilecek_dosya.exe" -o "./sonuclar" -b ghidra
```

## 📝 Parametreler

| Parametre | Açıklama |
| :--- | :--- |
| `binary` | Analiz edilecek `.exe` veya `.dll` dosyasının yolu. |
| `-o`, `--output` | Analiz sonuçlarının ve raporların kaydedileceği dizin. |
| `-b`, `--backend` | Kullanılacak motoru zorlar: `ilspy` veya `ghidra`. |
| `-g`, `--ghidra-path` | Ghidra kurulumunun ana dizin yolu. |

---
**Marka Sahibi & Geliştirici:** x410m1s0  
**Marka Adı:** xaloAC  
