from json import dump, load
from psutil import disk_partitions
from os.path import dirname, join, abspath, getsize, basename
from os import walk, makedirs
from asyncio import Lock, run, sleep, get_event_loop
from aiofiles import open as aiofiles_open
import yara

script_dir = dirname(abspath(__file__))
json_dir = join(script_dir, 'json', 'paths.json')
yara_rules = yara.compile(filepath=join(script_dir, 'yara', 'yara-forge-rules-full.yar'))
log_lock = None # lock for log entries
last_log_text = None  # Variable to store the last logged text
max_log_size = 100 * 1024  # 100 KB
log_cache = set()  # Cache to keep track of recent logs
cache_cleanup_interval = 60  # Time interval for cache cleanup in seconds

def initialize_lock():
    global log_lock
    log_lock = Lock()

# List all directories in the given directory.
def list_directories(directory):
    directories = []
    for root, dir_list, _ in walk(directory):
        for dir_name in dir_list:
            directories.append(join(root, dir_name))
    return directories

# Get all system partitions except 'cdrom' and empty file systems.
def get_partitions():
    partitions = []
    for part in disk_partitions():
        if 'cdrom' not in part.opts and part.fstype != '':
            partitions.append(part.mountpoint)
    return partitions

# Generate a JSON file with all directories in all partitions.
def gen_json():
    partitions = get_partitions()
    all_directories = {}
    total_directories = 0
    run(session_log('Scanning partitions...'))
    for partition in partitions:
        run(session_log(f'Scanning {partition}...'))
        directories = list_directories(partition)
        all_directories[partition] = directories
        total_directories += len(directories)
    run(session_log(f'Total directories: {total_directories}'))
    with open(json_dir, 'w') as f:
        dump(all_directories, f, indent=4)
    run(session_log(f'JSON saved at {json_dir}'))

# Read partitions from a JSON file.
def read_partitions_from_json(json_file):
    partitions = []
    try:
        with open(json_file, 'r') as f:
            data = load(f)
            partitions = list(data.keys())
    except FileNotFoundError:
        run(session_log(f'JSON file not found: {json_file}'))
    except Exception as e:
        run(session_log(f'Error reading JSON file: {e}'))
    return partitions

# Scan a file using YARA rules.
def yara_scan(file_path):
    try:
        matches = yara_rules.match(file_path)
        if matches:
            for match in matches:
                rule = match.rule
            return True, rule
        else:
            return False, None
    except:
        return False, None

# Backup the log file if it exceeds the maximum size.
async def backup_log_file(log_filename):
    backup_dir = join(dirname(log_filename), 'saved')
    makedirs(backup_dir, exist_ok=True)
    backup_filename = join(backup_dir, basename(log_filename))
    async with aiofiles_open(log_filename, 'r') as log_file:
        lines = await log_file.readlines()
    async with aiofiles_open(backup_filename, 'a') as backup_file:
        await backup_file.writelines(lines)
    async with aiofiles_open(log_filename, 'w') as log_file:
        await log_file.write("")

# Asynchronously logs the provided text to the session log file.
# Ensures that log entries do not overlap by using a lock.
# Logs only if the new log_text is different from the last logged text.
# Also handles backing up the log file if it exceeds a certain size.
async def session_log(log_text):
    global log_lock, last_log_text, max_log_size, log_cache
    log_filename = join(script_dir, 'logs', 'session.log')
    if log_lock is None:
        initialize_lock()
    async with log_lock:
        if log_text != last_log_text:  # Log only if the text is different from the last log
            if log_text not in log_cache:
                log_cache.add(log_text)
                async with aiofiles_open(log_filename, 'a') as log_file:
                    await log_file.write(log_text + '\n')
                last_log_text = log_text  # Update the last logged text
                # Check the size of the log file and backup if necessary
                log_size = getsize(log_filename)
                if log_size > max_log_size:
                    await backup_log_file(log_filename)

# Periodically clean the log cache to allow new alerts to be logged.
async def clean_log_cache():
    global log_cache
    while True:
        await sleep(cache_cleanup_interval)
        log_cache.clear()

# Initialize the event loop and start the cache cleanup task
loop = get_event_loop()
loop.create_task(clean_log_cache())