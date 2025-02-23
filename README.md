# BrowserDataExtractor - Enhanced Version

This project is an enhanced and modified version of the original **BrowserDataExtractor**, created by **danghuutruong**. The original project was designed to extract browser data such as saved passwords, cookies, history, and system information.

## 📌 Modifications & Improvements
- **Improved Code Readability**: Refactored the structure to make it more modular and maintainable.
- **Better Logging**: Replaced print statements with Python's logging module and used lazy formatting for efficiency.
- **Timeouts in Requests**: Added timeout parameters to `requests` calls to prevent indefinite blocking.
- **Stronger Error Handling**: More specific exception handling for better debugging.
- **Fixed Subprocess Calls**: Used `check=True` in `subprocess.run()` to catch execution errors.
- **Cleaned Unused Variables**: Removed redundant variables and improved memory management.
- **Updated README**: Added clear documentation to explain modifications and usage.

## 🚀 Features
- Extracts saved passwords from various browsers.
- Retrieves browsing history.
- Extracts stored cookies.
- Gathers system information such as OS, CPU, GPU, RAM, and installed applications.
- Sends collected data securely via Telegram.

## 🔧 Installation & Usage
### Requirements
- Python 3.6+
- Required Python libraries:
  ```sh
  pip install requests pycryptodome pycountry screeninfo psutil pywin32
  ```
- A Telegram bot token and chat ID (set in environment variables `BOT_TOKEN` and `CHAT_ID`).

### Running the Script
```sh
python browser_data_extractor.py
```

## ⚠️ Disclaimer
This tool is intended for **educational purposes only**. Unauthorized use of this tool on devices without consent is strictly prohibited. The author is not responsible for any misuse.

## 📌 Credits
- **Original Creator:** [danghuutruong](https://github.com/danghuutruong/BrowserDataExtractor)
- **Modified & Enhanced by:** [Edu Olivares](https://github.com/eduolihez)

Feel free to contribute and suggest further improvements! 🚀

