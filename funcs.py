from json import dump, load
from psutil import disk_partitions
from os.path import dirname, join, abspath
from os import walk, makedirs
from asyncio import Lock, run, get_running_loop
from aiofiles import open as aiofiles_open
import yara

# Directory paths
script_dir = dirname(abspath(__file__))
json_filename = join(script_dir, 'json', 'paths.json')
yara_rules = yara.compile(filepath=join(script_dir, 'yara', 'yara-forge-rules-full.yar'))
log_lock = None

def initialize_lock():
    global log_lock
    log_lock = Lock()

def list_directories(directory):
    """
    List all directories in the given directory.
    """
    directories = []
    for root, dir_list, _ in walk(directory):
        for dir_name in dir_list:
            directories.append(join(root, dir_name))
    return directories

def get_partitions():
    """
    Get all system partitions except 'cdrom' and empty file systems.
    """
    partitions = []
    for part in disk_partitions():
        if 'cdrom' not in part.opts and part.fstype != '':
            partitions.append(part.mountpoint)
    return partitions

async def gen_json():
    """
    Generate a JSON file with all directories in all partitions.
    """
    partitions = get_partitions()
    all_directories = {}
    total_directories = 0
    await session_log('Scanning partitions...')
    for partition in partitions:
        await session_log(f'Scanning {partition}...')
        directories = list_directories(partition)
        all_directories[partition] = directories
        total_directories += len(directories)
    await session_log(f'Total directories: {total_directories}')
    with open(json_filename, 'w') as f:
        dump(all_directories, f, indent=4)
    await session_log(f'JSON saved at {json_filename}')

def read_partitions_from_json(json_file):
    """
    Read partitions from a JSON file.
    """
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

def yara_scan(file_path):
    """
    Scan a file using YARA rules.
    """
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

async def session_log(log_text):
    """
    Asynchronously logs the provided text to the session log file.
    Ensures that log entries do not overlap by using a lock.
        
    :param log_text: The text to be logged.
    """
    global log_lock
    log_filename = join(script_dir, 'logs', 'session.log')
    if log_lock is None:
        initialize_lock()
    async with log_lock:
        async with aiofiles_open(log_filename, 'a') as log_file:
            await log_file.write(log_text + '\n')
