# By xaloAC - x410m1s0
import sys
import os
import subprocess
import shutil
import argparse
import tempfile
import struct
import logging
import hashlib
import json
from datetime import datetime

# ==============================================================================
# EĞİTİM AMAÇLI GÜVENLİ TERSİNE MÜHENDİSLİK ARACI
# ==============================================================================

def setup_secure_logging(output_dir):
    log_format = "%(asctime)s [%(levelname)s] [SİBER_ANALİZ] %(message)s"
    log_file = os.path.join(output_dir, "analiz_sureci.log")
    
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_file

def calculate_file_hashes(file_path):
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)
            
    return {
        "SHA-256": sha256_hash.hexdigest().upper(),
        "MD5": md5_hash.hexdigest().upper()
    }

def is_dotnet_assembly(file_path):
    try:
        with open(file_path, "rb") as f:
            dos_header = f.read(64)
            if not dos_header.startswith(b"MZ"):
                return False
            
            f.seek(60)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b"PE\x00\x00":
                return False
            
            f.seek(pe_offset + 24)
            magic = struct.unpack("<H", f.read(2))[0]
            
            if magic == 0x10b:      
                data_dir_offset = pe_offset + 24 + 96
            elif magic == 0x20b:    
                data_dir_offset = pe_offset + 24 + 112
            else:
                return False
            
            f.seek(data_dir_offset + (14 * 8))
            virtual_address = struct.unpack("<I", f.read(4))[0]
            size = struct.unpack("<I", f.read(4))[0]
            
            return virtual_address > 0 and size > 0
    except Exception as e:
        logging.error(f"PE başlık analizi sırasında hata: {e}")
        return False

def generate_audit_manifest(file_path, hashes, is_dotnet, output_dir):
    manifest_data = {
        "analiz_tarihi": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "orjinal_dosya_adi": os.path.basename(file_path),
        "dosya_boyutu_bytes": os.path.getsize(file_path),
        "kriptografik_ozetler": hashes,
        "mimari_turu": ".NET Yönetilen Kod (Managed Assembly)" if is_dotnet else "Yerel Kod (Native / C-C++)",
        "analiz_durumu": "Tamamlandı"
    }
    
    manifest_path = os.path.join(output_dir, "analiz_raporu_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=4, ensure_ascii=False)
        
    summary_txt_path = os.path.join(output_dir, "analiz_ozeti.txt")
    with open(summary_txt_path, "w", encoding="utf-8") as f:
        f.write("====================================================\n")
        f.write("           OTOMATİK İKİLİ ANALİZ ÖZETİ            \n")
        f.write("====================================================\n")
        f.write(f"Dosya Adı     : {manifest_data['orjinal_dosya_adi']}\n")
        f.write(f"Analiz Tarihi : {manifest_data['analiz_tarihi']}\n")
        f.write(f"Dosya Boyutu  : {manifest_data['dosya_boyutu_bytes']} bayt\n")
        f.write(f"Mimari Türü   : {manifest_data['mimari_turu']}\n")
        f.write(f"SHA-256       : {hashes['SHA-256']}\n")
        f.write(f"MD5           : {hashes['MD5']}\n")
        f.write("====================================================\n")
        
    logging.info(f"[+] Resmi analiz raporları oluşturuldu: {output_dir}")

def run_ghidra_headless(binary_path, output_dir, custom_ghidra_path):
    logging.info("[*] Yerel kod çözümü için Ghidra mimarisi yapılandırılıyor...")
    
    headless_cmd = None
    if custom_ghidra_path and custom_ghidra_path != "system_path":
        potential_path = os.path.join(custom_ghidra_path, "support", "analyzeHeadless")
        if os.name == 'nt':
            potential_path += ".bat"
        if os.path.exists(potential_path):
            headless_cmd = potential_path
            
    if not headless_cmd and os.environ.get("GHIDRA_HOME"):
        potential_path = os.path.join(os.environ.get("GHIDRA_HOME"), "support", "analyzeHeadless")
        if os.name == 'nt':
            potential_path += ".bat"
        if os.path.exists(potential_path):
            headless_cmd = potential_path

    if not headless_cmd:
        headless_name = "analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless"
        headless_cmd = shutil.which(headless_name)
        
    if not headless_cmd:
        logging.error("[-] KRİTİK HATA: Ghidra 'analyzeHeadless' aracı sistemde bulunamadı.")
        logging.error("Lütfen Ghidra yolunu belirtin veya GHIDRA_HOME ortam değişkenini tanımlayın.")
        return

    temp_proj_dir = tempfile.mkdtemp(prefix="gov_ghidra_sec_")
    proj_name = "gov_secure_analysis_proj"
    
    script_path = os.path.join(output_dir, "export_sources.py")
    with open(script_path, "w", encoding="utf-8") as sf:
        sf.write("# -*- coding: utf-8 -*-\n")
        sf.write("from ghidra.app.decompiler import DecompInterface\n")
        sf.write("from ghidra.util.task import ConsoleTaskMonitor\n")
        sf.write("import os\n\n")
        sf.write("currentProgram = state.getCurrentProgram()\n")
        sf.write("ifc = DecompInterface()\n")
        sf.write("ifc.openProgram(currentProgram)\n")
        sf.write("out_path = r'''" + output_dir.replace(os.sep, '/') + "''' + '/decompiled_functions.txt'\n")
        sf.write("with open(out_path, 'w') as out_f:\n")
        sf.write("    functionManager = currentProgram.getFunctionManager()\n")
        sf.write("    iterator = functionManager.getFunctions(True)\n")
        sf.write("    while iterator.hasNext():\n")
        sf.write("        func = iterator.next()\n")
        sf.write("        res = ifc.decompileFunction(func, 30, ConsoleTaskMonitor())\n")
        sf.write("        if res.decompileCompleted():\n")
        sf.write("            out_f.write('// ================================================\\n')\n")
        sf.write("            out_f.write('// Fonksiyon Adı: ' + func.getName() + '\\n')\n")
        sf.write("            out_f.write('// ================================================\\n')\n")
        sf.write("            out_f.write(str(res.getDecompiledFunction().getC()) + '\\n\\n')\n")
        sf.write("print('[+] Ghidra fonksiyon kodlarını başarıyla dışa aktardı.')\n")

    cmd = [
        headless_cmd,
        temp_proj_dir,
        proj_name,
        "-import", binary_path,
        "-scriptPath", output_dir,
        "-postScript", "export_sources.py",
        "-overwrite"
    ]

    logging.info("[*] Ghidra analizi başlatıldı, lütfen bekleyin (büyük dosyalarda sürebilir)...")
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if process.returncode == 0:
            logging.info(f"[+] Analiz başarılı! C Kodları burada: {output_dir}/decompiled_functions.txt")
        else:
            logging.error(f"[-] Ghidra hata kodu: {process.returncode}")
            logging.error(f"Detay:\n{process.stderr}")
    except subprocess.TimeoutExpired:
        logging.error("[-] ZAMAN AŞIMI: İşlem 15 dakikayı geçtiği için sonlandırıldı.")
    except Exception as e:
        logging.error(f"[-] Alt süreç hatası: {e}")
    finally:
        if os.path.exists(temp_proj_dir):
            try:
                shutil.rmtree(temp_proj_dir)
                logging.info("[*] Geçici çalışma alanı güvenle temizlendi.")
            except Exception as cleanup_err:
                logging.warning(f"[!] Temizleme uyarısı: {cleanup_err}")

def decompile_binary(file_path, output_dir=None, force_backend=None, ghidra_path=None):
    file_path = file_path.strip('"\'')

    if not os.path.exists(file_path):
        print(f"[-] HATA: Belirtilen dosya bulunamadı: {file_path}")
        return

    if not output_dir:
        output_dir = os.path.splitext(file_path)[0] + "_analiz_sonuc"
    
    os.makedirs(output_dir, exist_ok=True)
    
    log_file = setup_secure_logging(output_dir)
    logging.info("======================================================")
    logging.info("                 PE DECOMPILE ARACI                   ")
    logging.info("======================================================")
    logging.info(f"[*] Hedef Dosya: {file_path}")

    hashes = calculate_file_hashes(file_path)
    logging.info(f"[+] SHA-256 : {hashes['SHA-256']}")
    logging.info(f"[+] MD5     : {hashes['MD5']}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in [".exe", ".dll"]:
        logging.error("[-] HATA: Sadece .exe veya .dll dosyaları analiz edilebilir.")
        return

    is_dotnet = False
    if force_backend == "ilspy":
        is_dotnet = True
    elif force_backend == "ghidra":
        is_dotnet = False
    else:
        is_dotnet = is_dotnet_assembly(file_path)

    generate_audit_manifest(file_path, hashes, is_dotnet, output_dir)

    if is_dotnet:
        logging.info("[+] Tür Tespiti: Yönetilen .NET Assembly.")
        if not shutil.which("ilspycmd"):
            logging.error("[-] HATA: 'ilspycmd' aracı sistemde eksik.")
            logging.error("Kurulum komutu: dotnet tool install -g ilspycmd")
            return
        
        logging.info("[*] ILSpy ile kodlar çıkarılıyor...")
        try:
            cmd = ["ilspycmd", file_path, "-o", output_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                logging.info(f"[+] Başarılı! Kaynak dosyalar burada: {output_dir}")
            else:
                logging.error(f"[-] ILSpy hatası:\n{result.stderr}")
        except Exception as e:
            logging.error(f"[-] İstisna oluştu: {e}")
    else:
        logging.info("[+] Tür Tespiti: Yerel (Native) İkilik Dosya.")
        run_ghidra_headless(file_path, output_dir, ghidra_path)

def interactive_wizard():
    print("======================================================")
    print("      İNTERAKTİF TERSİNE MÜHENDİSLİK ASİSTANI         ")
    print("======================================================")
    
    try:
        file_path = input("\n> Lütfen analiz edilecek .exe veya .dll dosyasını sürükleyip bırakın (veya yolunu yazın): ").strip()
        if not file_path:
            print("[-] Dosya yolu boş bırakılamaz.")
            return

        print("\n[Seçenekler]")
        print("1. Otomatik Mimari Tespiti (Önerilen)")
        print("2. Zorla .NET (.NET / ILSpy)")
        print("3. Zorla Yerel Kod (Native / Ghidra)")
        choice = input("\nSeçiminiz [1/2/3] (Varsayılan: 1): ").strip()
        
        backend = None
        if choice == "2":
            backend = "ilspy"
        elif choice == "3":
            backend = "ghidra"
            
        ghidra_path = None
        if backend == "ghidra" or choice == "1":
            gp = input("\nGhidra ana dizini var mı? (Yoksa boş bırakıp Enter'a basın): ").strip()
            if gp:
                ghidra_path = gp.strip('"\'')

        print("\n[+] Analiz süreci başlatılıyor, lütfen bekleyin...\n")
        decompile_binary(file_path, force_backend=backend, ghidra_path=ghidra_path)
        
    except KeyboardInterrupt:
        print("\n\n[*] İşlem kullanıcı tarafından iptal edildi.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive_wizard()
    else:
        parser = argparse.ArgumentParser(description="Gelişmiş PE Decompile ve Analiz Otomasyonu")
        parser.add_argument("binary", help="Analiz edilecek .exe veya .dll dosyası")
        parser.add_argument("-o", "--output", help="Çıktı dizini")
        parser.add_argument("-b", "--backend", choices=["ilspy", "ghidra"], help="Motor seçimi")
        parser.add_argument("-g", "--ghidra-path", help="Ghidra dizini")
        
        args = parser.parse_args()
        decompile_binary(args.binary, output_dir=args.output, force_backend=args.backend, ghidra_path=args.ghidra_path)