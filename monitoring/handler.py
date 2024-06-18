from monitoring.funcs import script_dir, yara_scan, session_log
from asyncio import Lock, create_task, sleep, run
from aiofiles import open as aiofiles_open
from watchdog.events import FileSystemEventHandler
from os.path import join, getsize, exists, basename, dirname
from os import makedirs
from subprocess import run as subprocess_run, PIPE
from json import dumps
from atexit import register
from datetime import datetime
from time import time

class ChangeHandler(FileSystemEventHandler):
    def __init__(self, loop, debug=False, defense=False, aggressive=False):
        self.cache = {}
        self.debug = debug
        self.defense = defense
        self.aggressive = aggressive
        self.loop = loop
        self.loop.call_soon_threadsafe(self.initialize_lock)
        self.event_caches = {key: [] for key in [
            'file_created', 'file_modified', 'file_deleted', 'file_moved',
            'directory_created', 'directory_modified', 'directory_deleted',
            'link_created', 'link_deleted', 'link_modified', 'link_moved',
            'warning_events', 'warning_files', 'warning_malware_detected', 'deleted_files'
        ]}
        self.log_files = {key: join(script_dir, 'logs', f'{key}.log') for key in self.event_caches}
        self.saved_log_files = {key: join(script_dir, 'logs', 'saved', f'{key}.log') for key in self.event_caches}
        self.yara_forge_rules_full_path = join(script_dir, 'yara', 'yara-forge-rules-full.yar')
        self.all_paths = [path[1:] for path in self.log_files.values()]

        self.scan_whitelist_path = join(script_dir, 'conf', 'whitelist.txt')
        whitelist_paths = open(self.scan_whitelist_path, 'r').read().splitlines()
        self.scan_whitelist_tuple = tuple(whitelist_paths)

        self.file_extensions_path = join(script_dir, 'conf', 'file_extensions.txt')
        extensions = open(self.file_extensions_path, 'r').read().splitlines()
        self.file_extensions_tuple = tuple(extensions)

        self.loop.call_soon(self.initial_log)
        register(self.flush_caches)

    def initialize_lock(self):
        self.log_lock = Lock()

    def initial_log(self):
        if self.debug:
            create_task(session_log('DEBUG MODE ACTIVE: Relevant INFO will be displayed.'))
        if self.defense:
            create_task(session_log('DEFENSE MODE ACTIVE: Malware files will be automatically deleted.'))
        if self.aggressive:
            create_task(session_log('AGGRESSIVE MODE ACTIVE: Files with the configured extensions created will be automatically deleted.'))

    async def log_event(self, event_type, event_path, dest_path=None):
        await self.clean_cache()
        event_time = datetime.now().isoformat()
        try:
            file_size = getsize(event_path) if exists(event_path) else None
        except FileNotFoundError:
            file_size = None
        except Exception as e:
            if self.debug:
                create_task(session_log(f'Error getting size of {event_path}: {e}'))
            file_size = None
        yara_rule = self.yara_rule(event_path)
        event_details = {
            'event_type': event_type,
            'event_time': event_time,
            'file_path': event_path,
            'dest_path': dest_path if dest_path else None,
            'file_size': file_size,
            'yara_rule': yara_rule
        }

        cache_key = (event_type, event_path, file_size, yara_rule)
        current_time = time()

        # Check for duplicate events within a short time period
        if cache_key in self.cache and current_time - self.cache[cache_key]['time'] < 1:
            return  # Skip this event as it was logged recently

        self.cache[cache_key] = {'event_details': event_details, 'time': current_time}

        if yara_scan(event_path)[0]:
            create_task(session_log(f'WARNING: Malware detected in: "{event_path}"'))
            if not event_details['file_path'].startswith(self.scan_whitelist_tuple) and event_path[1:] != self.yara_forge_rules_full_path[1:]:
                if self.defense:
                    await self.delete_file(event_time, event_path, event_details)
            create_task(session_log(f'INFO: Alert received by {yara_scan(event_path)[1]} YARA Rule in "{event_path}"'))
            await self.cache_event(event_details, 'warning_malware_detected', 1)
        
        if event_type == 'File created':
            if event_details['file_path'].endswith(self.file_extensions_tuple):
                create_task(session_log(f'WARNING: File with a configured extension created in: "{event_path}"'))
                await self.cache_event(event_details, 'warning_files', 1)
                if not event_details['file_path'].startswith(self.scan_whitelist_tuple):
                    if self.aggressive:
                        await self.delete_file(event_time, event_path, event_details)
            if event_path[:1] not in self.all_paths:
                await self.cache_event(event_details, 'file_created', 9)
                create_task(session_log(f'Attention: File created in: "{event_path}"'))
                await self.cache_event(event_details, 'warning_events', 1)

        elif event_type == 'File modified':
            if event_details['file_path'].endswith(self.file_extensions_tuple):
                create_task(session_log(f'WARNING: File with a configured extension modified in: "{event_path}"'))
                await self.cache_event(event_details, 'warning_files', 1)
            if event_path[1:] not in self.all_paths:
                await self.cache_event(event_details, 'file_modified', 100)

        elif event_type == 'File deleted':
            await self.cache_event(event_details, 'file_deleted', 10)
            self.cache[cache_key] = {'event_details': event_details, 'time': current_time}

        elif event_type == 'File moved':
            await self.cache_event(event_details, 'file_moved', 10)
            self.cache[cache_key] = {'event_details': event_details, 'time': current_time}
            self.cache[(event_type, dest_path, file_size, yara_rule)] = {'event_details': event_details, 'time': current_time}

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

    async def delete_file(self, event_time, event_path, event_details):
        """
        Delete the file if defense or aggressive mode is active.
        """
        try:
            await sleep(0.1)
            while not exists(event_path):
                await sleep(0.1)
            subprocess_run(f'del /f "{event_path}"', shell=True, check=True, stdout=PIPE, stderr=PIPE)
            create_task(session_log(f'SUCCESSFUL: The file "{event_path}" has been deleted.'))
            await self.cache_event(event_details, 'deleted_files', 1)
        except Exception as e:
            create_task(session_log(f'"{event_path}" file could not be removed: {e}'))

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

    async def clean_cache(self):
        """
        Clean the cache by removing old entries and log them.
        """
        current_time = time()
        keys_to_delete = [key for key, value in self.cache.items() if current_time - value['time'] > 60]
        for key in keys_to_delete:
            event_details = self.cache[key]['event_details']
            cache_key = event_details['event_type'].lower().replace(' ', '_')
            if cache_key in self.saved_log_files:
                await self.flush_event_to_log(event_details, self.saved_log_files[cache_key])
            del self.cache[key]

    async def flush_event_to_log(self, event_details, log_filename):
        """
        Flush a single event to the specified log file.
        """
        async with self.log_lock:
            async with aiofiles_open(log_filename, 'a') as log_file:
                await log_file.write(dumps(event_details) + '\n')

    async def flush_cache_to_log(self, cache_key):
        """
        Flush the cached events to the log file.
        """
        log_filename = self.log_files[cache_key]
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
        try:
            with open(log_filename, 'r') as file:
                lines = file.readlines()
                if len(lines) >= 100:
                    backup_dir = join(dirname(log_filename), 'saved')
                    makedirs(backup_dir, exist_ok=True)
                    backup_filename = join(backup_dir, basename(log_filename))
                    with open(backup_filename, 'a') as backup_file:
                        backup_file.writelines(lines)
                    with open(log_filename, 'w') as file:
                        pass
        except FileNotFoundError:
            if self.debug:
                create_task(session_log(f'Log file not found for backup: {log_filename}'))
        except Exception as e:
            if self.debug:
                create_task(session_log(f'Error during log file backup: {e}'))

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
