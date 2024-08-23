import os
import shutil
import zipfile
import subprocess
from tkinter import Tk, Label, Entry, Button, filedialog, Text, Scrollbar, messagebox
from tkinter.ttk import Progressbar
import threading
from tqdm import tqdm
import getpass

# İşlemi durdurma bayrağı
stop_flag = False

# Fonksiyonlar
def connect_to_computer(computer, user, username, password):
    """Belirtilen bilgisayara ve kullanıcıya ağ sürücüsü ekleyen fonksiyon."""
    net_use_command: str = f'net use \\\\{computer}\\Users\\{user} /user:{username} {password}'
    try:
        subprocess.run(net_use_command, shell=True, check=True)
        log_text.insert("end", f'Bağlanıldı: {computer}\\Users\\{user}\n')
    except Exception as e:
        log_text.insert("end", f'Hata: {computer}\\Users\\{user} - {e}\n')

def disconnect_from_computer(computer, user, log_text, net_use_command=None):
    """Belirtilen bilgisayardan ve kullanıcıdan ağ sürücüsünü kaldıran fonksiyon."""
    net_delete_command = f'net use \\\\{computer}\\Users\\{user} /delete'
    try:
        subprocess.run(net_use_command, shell=True, check=True)
        log_text.insert("end", f'Bağlantı kesildi: {computer}\\Users\\{user}\n')
    except Exception as e:
        log_text.insert("end", f'Hata: {computer}\\Users\\{user} - {e}\n')

def copy_file_to_desktop(computer, user, source, username, password, log_text):
    """Belirtilen bilgisayara ve kullanıcıya dosya kopyalama."""
    desktop_path = fr'\\{computer}\Users\{user}\Desktop'
    dest = os.path.join(desktop_path, os.path.basename(source))
    try:
        connect_to_computer(computer, user, username, password)
        shutil.copy(source, dest)
        log_text.insert("end", f"{computer} -> {user} - {os.path.basename(source)} kopyalandı.\n")
    except Exception as e:
        log_text.insert("end", f"Hata: {computer} -> {user} - {e}\n")
    finally:
        disconnect_from_computer(computer, user)

def extract_zip_to_folder(computer, user, source, dest_folder, username, password, log_text):
    """ZIP dosyasını belirtilen bilgisayara ve kullanıcıya belirtilen klasöre çıkarma."""
    dest_path = fr'\\{computer}\c\\EsriTraining'
    try:
        connect_to_computer(computer, user, username, password)
        with zipfile.ZipFile(source, 'r') as zip_ref:
            zip_ref.extractall(dest_path)
        log_text.insert("end", f"{computer} dosyasının içeriği başarıyla {dest_path} konumuna çıkarıldı.\n")
    except Exception as e:
        log_text.insert("end", f"Hata: {source} osyasının içeriği çıkarılırken bir hata oluştu. {e}\n")
    finally:
        disconnect_from_computer(computer, user)

def start_process():
    global stop_flag
    stop_flag = False  # İşlemi başlatırken durdurma bayrağını sıfırla
    
    username = username_entry.get()
    password = password_entry.get()
    pdf_source = pdf_entry.get()
    zip_source = zip_entry.get()

    if not username or not password or not pdf_source or not zip_source:
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurunuz!")
        return

    # Mevcut tüm ağ bağlantılarını sonlandırma komutu
    net_use_delete_all_command = 'net use * /delete /y'
    subprocess.run(net_use_delete_all_command, shell=True, check=True)

    total_tasks = len(computers) * 2  # Her bilgisayar için iki görev: PDF kopyalama ve ZIP çıkarma
    progress_bar["maximum"] = total_tasks
    progress_bar["value"] = 0

    for computer, users in computers.items():
        if stop_flag:  # Durdurma bayrağı kontrolü
            log_text.insert("end", "İşlem durduruldu.\n")
            break
        for user in users:
            if stop_flag:  # Durdurma bayrağı kontrolü
                log_text.insert("end", "İşlem durduruldu.\n")
                break
            copy_file_to_desktop(computer, user, pdf_source, username, password, log_text)
            progress_bar["value"] += 1
            progress_bar.update()

            if stop_flag:  # Durdurma bayrağı kontrolü
                log_text.insert("end", "İşlem durduruldu.\n")
                break
            extract_zip_to_folder(computer, user, zip_source, 'EsriTraining', username, password, log_text)
            progress_bar["value"] += 1
            progress_bar.update()

    log_text.insert("end", "Tüm işlemler tamamlandı.\n")

def stop_process():
    global stop_flag
    stop_flag = True  # Durdurma bayrağını etkinleştir

def browse_pdf_file():
    """PDF dosyasını seçmek için dosya seçici açar."""
    pdf_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    pdf_entry.delete(0, "end")
    pdf_entry.insert(0, pdf_path)

def browse_zip_file():
    """ZIP dosyasını seçmek için dosya seçici açar."""
    zip_path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
    zip_entry.delete(0, "end")
    zip_entry.insert(0, zip_path)

# Hedef bilgisayarlar ve kullanıcılar
computers = {
    'Egitim9': ['Egitim2'],
    'Egitim10': ['Egitim9'],
    'Egitim11': ['EGITIM-1'],
    'Egitim12': ['Egitim7'],
    'Egitim13': ['Egitim6'],
    'Egitim14': ['Egitim3'],
    'Egitim15': ['Egitim14'],
    'Egitim16': ['Egitim12'],
    'Egitim17': ['Egitim17'],
    'Egitim18': ['Egitim20'],
    'Egitim19': ['Egitim16'],
    'Egitim20': ['Egitim8']
}

# Arayüz kurulumu
root = Tk()
root.title("Enlem Sınıfı Dosya Aktarım Aracı")

# Kullanıcı adı ve şifre
Label(root, text="Kullanıcı Adı:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
username_entry = Entry(root, width=30)
username_entry.grid(row=0, column=1, padx=10, pady=5)

Label(root, text="Şifre:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
password_entry = Entry(root, show='*', width=30)
password_entry.grid(row=1, column=1, padx=10, pady=5)

# PDF dosyası seçimi
Label(root, text="PDF Dosya Yolu:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
pdf_entry = Entry(root, width=50)
pdf_entry.grid(row=2, column=1, padx=10, pady=5)
Button(root, text="Gözat", command=browse_pdf_file).grid(row=2, column=2, padx=10, pady=5)

# ZIP dosyası seçimi
Label(root, text="ZIP Dosya Yolu:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
zip_entry = Entry(root, width=50)
zip_entry.grid(row=3, column=1, padx=10, pady=5)
Button(root, text="Gözat", command=browse_zip_file).grid(row=3, column=2, padx=10, pady=5)

# Progress Bar
Label(root, text="İlerleme:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
progress_bar = Progressbar(root, length=200, mode='determinate')
progress_bar.grid(row=4, column=1, padx=10, pady=5)

# Log alanı
Label(root, text="İşlem Durumu:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
log_text = Text(root, height=10, width=50)
log_text.grid(row=5, column=1, padx=10, pady=5)
scroll = Scrollbar(root, command=log_text.yview)
scroll.grid(row=5, column=2, sticky='nsew')
log_text['yscrollcommand'] = scroll.set


# İşlem başlat ve durdur butonları
Button(root, text="Başlat", command=lambda: threading.Thread(target=start_process).start()).grid(row=6, column=1, padx=10, pady=10, sticky="w")
Button(root, text="Durdur", command=stop_process).grid(row=6, column=1, padx=10, pady=10, sticky="e")

root.mainloop()
