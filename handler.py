from funcs import script_dir, yara_scan, session_log
from asyncio import Lock, create_task, sleep, get_running_loop, run
from aiofiles import open as aiofiles_open
from watchdog.events import FileSystemEventHandler
from os.path import join, getsize, exists, basename
from os import makedirs
from subprocess import run as subprocess_run, PIPE
from json import dumps
from atexit import register
from datetime import datetime
from time import time

class ChangeHandler(FileSystemEventHandler):
    """
    Handles file system events and performs actions based on those events.
    """
    def __init__(self, loop, debug=False, defense=False, aggressive=False):
        self.processed_files = {}
        self.debug = debug
        self.defense = defense
        self.aggressive = aggressive
        self.loop = loop  # Store the loop for later use

        # Initialize the log_lock in the provided loop
        self.loop.call_soon_threadsafe(self.initialize_lock)

        # Initialize event caches and log file paths
        self.event_caches = {
            'file_created': [],
            'file_modified': [],
            'file_deleted': [],
            'file_moved': [],
            'directory_created': [],
            'directory_modified': [],
            'directory_deleted': [],
            'link_created': [],
            'link_deleted': [],
            'link_modified': [],
            'link_moved': [],
            'warning_events': [],
            'warning_files': [],
            'warning_malware_detected': [],
            'deleted_files': []
        }
        self.session_log_filename = join(script_dir, 'logs', 'session.log')
        self.file_created_log_filename = join(script_dir, 'logs', 'file_created.log')
        self.file_modified_log_filename = join(script_dir, 'logs', 'file_modified.log')
        self.file_deleted_log_filename = join(script_dir, 'logs', 'file_deleted.log')
        self.file_moved_log_filename = join(script_dir, 'logs', 'file_moved.log')
        self.directory_created_log_filename = join(script_dir, 'logs', 'directory_created.log')
        self.directory_modified_log_filename = join(script_dir, 'logs', 'directory_modified.log')
        self.directory_deleted_log_filename = join(script_dir, 'logs', 'directory_deleted.log')
        self.link_created_log_filename = join(script_dir, 'logs', 'link_created.log')
        self.link_deleted_log_filename = join(script_dir, 'logs', 'link_deleted.log')
        self.link_modified_log_filename = join(script_dir, 'logs', 'link_modified.log')
        self.link_moved_log_filename = join(script_dir, 'logs', 'link_moved.log')
        self.warning_events_log_filename = join(script_dir, 'logs', 'warning_events.log')
        self.warning_files_log_filename = join(script_dir, 'logs', 'warning_executable_files.log')
        self.warning_malware_detected_log_filename = join(script_dir, 'logs', 'warning_malware_detected.log')
        self.deleted_files_log_filename = join(script_dir, 'logs', 'deleted_files.log')
        self.yara_forge_rules_full_path = join(script_dir, 'yara', 'yara-forge-rules-full.yar')
        self.all_paths = [
            self.session_log_filename[1:],
            self.file_created_log_filename[1:],
            self.file_modified_log_filename[1:],
            self.file_deleted_log_filename[1:],
            self.file_moved_log_filename[1:],
            self.directory_created_log_filename[1:],
            self.directory_modified_log_filename[1:],
            self.directory_deleted_log_filename[1:],
            self.link_created_log_filename[1:],
            self.link_deleted_log_filename[1:],
            self.link_modified_log_filename[1:],
            self.link_moved_log_filename[1:],
            self.warning_events_log_filename[1:],
            self.warning_files_log_filename[1:],
            self.warning_malware_detected_log_filename[1:],
            self.deleted_files_log_filename[1:]
        ]

        self.scan_whitelist_path = join(script_dir, 'conf', 'whitelist.txt')
        whitelist_paths = open(self.scan_whitelist_path, 'r').read().splitlines()
        self.scan_whitelist_tuple = tuple(whitelist_paths)

        self.file_extensions_path = join(script_dir, 'conf', 'file_extensions.txt')
        extensions = open(self.file_extensions_path, 'r').read().splitlines()
        self.file_extensions_tuple = tuple(extensions)

        # Log initial messages after the event loop is running
        self.loop.call_soon(self.initial_log)

        # Register the cache flush function to be called on exit
        register(self.flush_caches)

        # Schedule the session log length checker
        self.loop.create_task(self.periodic_session_log_check())

        # Schedule the processed files cleaner
        self.loop.create_task(self.clean_processed_files())

    def initialize_lock(self):
        """
        Initialize the log lock in the correct event loop.
        """
        self.log_lock = Lock()

    def initial_log(self):
        if self.debug:
            self.loop.create_task(session_log('DEBUG MODE ACTIVE: Relevant INFO will be displayed.'))
        if self.defense:
            self.loop.create_task(session_log('DEFENSE MODE ACTIVE: Malware files will be automatically deleted.'))
        if self.aggressive:
            self.loop.create_task(session_log('AGGRESSIVE MODE ACTIVE: Files with the configured extensions created will be automatically deleted.'))

    async def log_event(self, event_type, event_path, dest_path=None):
        event_time = datetime.now().isoformat()
        try:
            file_size = getsize(event_path) if exists(event_path) else None
        except FileNotFoundError:
            file_size = None
        except Exception as e:
            if self.debug:
                await session_log(f'Error getting size of {event_path}: {e}')
            file_size = None
        event_details = {
            'event_type': event_type,
            'event_time': event_time,
            'file_path': event_path,
            'dest_path': dest_path if dest_path else None,
            'file_size': file_size,
            'yara_rule': self.yara_rule(event_path)
        }
        cache_key = f"{event_type}_{event_path}"

        if event_type in ['File created', 'File modified']:
            if event_details['file_path'].endswith(self.file_extensions_tuple):
                await session_log(f'[{event_time}] WARNING: File with a configured extension created in: "{event_path}"')
                await self.cache_event(event_details, 'warning_files', 1)
                if not event_details['file_path'].startswith(self.scan_whitelist_tuple):
                    await self.if_aggressive(event_time, event_path, event_details)
            if yara_scan(event_path)[0]:
                await session_log(f'[{event_time}] WARNING: Malware detected in: "{event_path}"')
                if not event_details['file_path'].startswith(self.scan_whitelist_tuple) and event_path[1:] != self.yara_forge_rules_full_path[1:]:
                    await self.if_defense(event_time, event_path, event_details)
                await session_log(f'[{event_time}] INFO: Alert received by {yara_scan(event_path)[1]} YARA Rule in "{event_path}"')
                await self.cache_event(event_details, 'warning_malware_detected', 1)
        
        if cache_key not in self.processed_files:
            self.processed_files[cache_key] = time()
            current_time = time()

            if event_type == 'File created':
                if event_path[:1] not in self.all_paths:
                    await self.cache_event(event_details, 'file_created', 9)
                    await session_log(f'[{event_time}] Attention: File created in: "{event_path}"')
                    await self.cache_event(event_details, 'warning_events', 1)

            elif event_type == 'File modified' and event_path[:1]:
                if event_path[1:] not in self.all_paths:
                    await self.cache_event(event_details, 'file_modified', 100)

            elif event_type == 'File deleted':
                await self.cache_event(event_details, 'file_deleted', 10)
                self.processed_files.pop(cache_key, None)  # Remove from processed_files

            elif event_type == 'File moved':
                await self.cache_event(event_details, 'file_moved', 10)
                self.processed_files.pop(cache_key, None)  # Remove from processed_files

            elif event_type == 'Directory created':
                await self.cache_event(event_details, 'directory_created', 10)

            elif event_type == 'Directory modified':
                await self.cache_event(event_details, 'directory_modified', 10)

            elif event_type == 'Directory deleted':
                await self.cache_event(event_details, 'directory_deleted', 10)

            elif event_type == 'Link created':
                await self.cache_event(event_details, 'link_created', 10)

            elif event_type == 'Link deleted':
                await self.cache_event(event_details, 'link_deleted', 10)

            elif event_type == 'Link modified':
                await self.cache_event(event_details, 'link_modified', 10)

            elif event_type == 'Link moved':
                await self.cache_event(event_details, 'link_moved', 10)

    async def if_defense(self, event_time, event_path, event_details):
        """
        Delete the file if defense mode is active.
        """
        if self.defense:
            try:
                await sleep(0.5)  # Small delay to ensure logs are written
                subprocess_run(f'del /f "{event_path}"', shell=True, check=True, stdout=PIPE, stderr=PIPE)
                await session_log(f'[{event_time}] SUCCESSFUL: The file "{event_path}" has been deleted.')
                await self.cache_event(event_details, 'deleted_files', 1)
            except Exception as e:
                await session_log(f'"{event_path}" file could not be removed: {e}')

    async def if_aggressive(self, event_time, event_path, event_details):
        """
        Delete the file if aggressive mode is active.
        """
        if self.aggressive:
            try:
                await sleep(0.5)  # Small delay to ensure logs are written
                subprocess_run(f'del /f "{event_path}"', shell=True, check=True, stdout=PIPE, stderr=PIPE)
                await session_log(f'[{event_time}] SUCCESSFUL: The file "{event_path}" has been deleted.')
                await self.cache_event(event_details, 'deleted_files', 1)
            except Exception as e:
                await session_log(f'"{event_path}" file could not be removed: {e}')

    def yara_rule(self, event_path):
        """
        Get the YARA rule that matched the file.
        """
        return yara_scan(event_path)[1]

    async def cache_event(self, event_details, cache_key, log_threshold):
        """
        Cache the event and flush to log if the threshold is reached.
        """
        self.event_caches[cache_key].append(event_details)
        if len(self.event_caches[cache_key]) >= log_threshold:
            await self.flush_cache_to_log(cache_key)

    async def flush_cache_to_log(self, cache_key):
        """
        Flush the cached events to the log file.
        """
        log_filename = getattr(self, f'{cache_key}_log_filename')
        self.backup_log_file(log_filename)
        async with self.log_lock:
            async with aiofiles_open(log_filename, 'a') as log_file:
                for event in self.event_caches[cache_key]:
                    await log_file.write(dumps(event) + '\n')
            self.event_caches[cache_key] = []

    def backup_log_file(self, log_filename):
        """
        Backup the log file if it exceeds a certain size.
        """
        if exists(log_filename):
            try:
                backup_dir = join(script_dir, 'logs', 'saved')
                makedirs(backup_dir, exist_ok=True)
                with open(log_filename, 'r') as file:
                    lines = file.readlines()
                    if len(lines) >= 100:
                        backup_filename = join(backup_dir, basename(log_filename))
                        with open(backup_filename, 'a') as backup_file:
                            backup_file.writelines(lines)
                        with open(log_filename, 'w') as file:
                            pass  # Clear the log file after backing up
            except FileNotFoundError:
                if self.debug:
                    create_task(session_log(f'Log file not found for backup: {log_filename}'))
            except Exception as e:
                if self.debug:
                    create_task(session_log(f'Error during log file backup: {e}'))

    async def periodic_session_log_check(self):
        """
        Periodically check the session log length and back it up if necessary.
        """
        while True:
            self.check_session_log_length()
            await sleep(60)  # Check every 60 seconds

    def check_session_log_length(self):
        """
        Check the length of the session log and back it up if it exceeds 100 lines.
        """
        log_filename = self.session_log_filename
        if exists(log_filename):
            try:
                backup_dir = join(script_dir, 'logs', 'saved')
                makedirs(backup_dir, exist_ok=True)
                with open(log_filename, 'r') as file:
                    lines = file.readlines()
                    if len(lines) >= 100:
                        backup_filename = join(backup_dir, 'session.log')
                        with open(backup_filename, 'a') as backup_file:
                            backup_file.writelines(lines)
                        with open(log_filename, 'w') as file:
                            pass  # Clear the log file after backing up
            except FileNotFoundError:
                if self.debug:
                    create_task(session_log(f'Log file not found for backup: {log_filename}'))
            except Exception as e:
                if self.debug:
                    create_task(session_log(f'Error during log file backup: {e}'))

    async def clean_processed_files(self):
        """
        Periodically clean the processed_files set.
        """
        while True:
            current_time = time()
            keys_to_delete = [key for key, timestamp in self.processed_files.items() if current_time - timestamp > 60]
            for key in keys_to_delete:
                del self.processed_files[key]
            await sleep(60)  # Clean every 60 seconds

    def flush_caches(self):
        """
        Flush all event caches to their respective log files.
        """
        for cache_key in self.event_caches:
            if self.event_caches[cache_key]:
                self.loop.call_soon_threadsafe(create_task, self.flush_cache_to_log(cache_key))

    def on_created(self, event):
        self.loop.call_soon_threadsafe(create_task, self.log_event('File created', event.src_path))

    def on_deleted(self, event):
        self.loop.call_soon_threadsafe(create_task, self.log_event('File deleted', event.src_path))

    def on_modified(self, event):
        self.loop.call_soon_threadsafe(create_task, self.log_event('File modified', event.src_path))

    def on_moved(self, event):
        self.loop.call_soon_threadsafe(create_task, self.log_event('File moved', event.src_path, event.dest_path))