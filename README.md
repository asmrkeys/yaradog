<h1>​DISCLAIMER:</h1> This project is in process and can delete important system files, do not use it without knowing what you are doing.<hr>

# yaradog
*Intrusion Prevention Dog for Windows*

# Implementations:
1. Uses `YARA` and `Watchdog` for malware and payload detection. Automatic removal of malware and files with configured extensions can be enabled.

# Notes 0.5.6:
- Pending:
1. [bug to be fixed in TextReaderWidget class](https://github.com/asmrkeys/yaradog/commit/b980035abe9bf51efd6ac1d2f31597489d6d4e70)<br>"Task was destroyed but it is pending!" <--- Hint about the bug
2. idle_yaradog.png position before running filesystem_scanner,
3. barking if detects a warning,
4. creation of notification system,
5. creation of configuration menu.

# **Credits:**
- **YARA:** *The pattern matching swiss knife*<br>The project uses the [yara-python](https://github.com/VirusTotal/yara-python) library. YARA Open Source [here](https://github.com/virustotal/yara).
- **YARA Forge:** *Automated YARA Rule Standardization and Quality Assurance Tool*<br>A huge updated collection of high quality YARA rules. OpenSource [here](https://github.com/YARAHQ/yara-forge).
- **Watchdog:** *Python library and shell utilities to monitor filesystem events.*<br>Used for filesystem scanner. OpenSource [here](https://github.com/gorakhargosh/watchdog)
- **PyQt:** *PyQt is a Python binding of the cross-platform GUI toolkit Qt*<br>The PyQt5 module is used for the frontend. Website [here](https://www.riverbankcomputing.com/software/pyqt/)
- **psutil:** *Cross-platform lib for process and system monitoring in Python*<br>monitoring/funcs.py uses the disk_partitions function. OpenSource [here](https://github.com/giampaolo/psutil)
- **aiofiles:** *File support for asyncio*<br>monitoring/funcs.py uses the open function. OpenSource [here](https://github.com/Tinche/aiofiles)
