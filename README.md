<h1>​DISCLAIMER:</h1> This project is in process and can delete important system files, do not use it without knowing what you are doing.<hr>

# yaradog
*Intrusion Prevention Dog for Windows*

Uses `YARA` and `Watchdog` for malware and payload prevention. `ChangeHandler` defense mode can be enabled to automatically delete malware files if is detected by YARA and with the aggressive mode active we will delete any file created with any extension configured. 

# Notes 0.5.1:
* Front end in progress:
- Pending assignment of different dog positions, barking, and alarm systems
- Pending creation of configuration menu.
* Pending backups to external device and file cleanup.
* Review of cache and aggressive mode: The cache system was being changed, and now there are some strange behaviors to check in the log system. This needs to be reviewed.

# **Credits:**
- **YARA:** *The pattern matching swiss knife*<br>The project uses the [yara-python](https://github.com/VirusTotal/yara-python) library. YARA Open Source [here](https://github.com/virustotal/yara).
- **YARA Forge:** *Automated YARA Rule Standardization and Quality Assurance Tool*<br>A huge updated collection of high quality YARA rules. OpenSource [here](https://github.com/YARAHQ/yara-forge).
- **Watchdog:** *Python library and shell utilities to monitor filesystem events.* [OpenSource](https://github.com/gorakhargosh/watchdog)
- **psutil:** *Cross-platform lib for process and system monitoring in Python* [OpenSource](https://github.com/giampaolo/psutil)
- **aiofiles:** *File support for asyncio* [OpenSource](https://github.com/Tinche/aiofiles)
- **PyQt:** *PyQt is a Python binding of the cross-platform GUI toolkit Qt*<br>The PyQt5 module is used for the frontend. [Website](https://www.riverbankcomputing.com/software/pyqt/)