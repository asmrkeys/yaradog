from monitoring.funcs import script_dir, yara_scan, session_log
from asyncio import Lock, sleep, run_coroutine_threadsafe
from watchdog.events import FileSystemEventHandler
from subprocess import run as subprocess_run, PIPE
from os.path import join, getsize, exists
from os import getlogin
from datetime import datetime

class ChangeHandler(FileSystemEventHandler):
    def __init__(self, loop, delete_malware=False, delete_extensions=False):
        self.delete_malware = delete_malware
        self.delete_extensions = delete_extensions
        self.loop = loop
        self.yara_forge_rules_full_path = join(script_dir, 'yara', 'yara-forge-rules-full.yar')
        self.session_log_path = join(script_dir, 'logs', 'session.log')
        self.windows_username = getlogin()

        # Load whitelist paths
        self.scan_whitelist_path = join(script_dir, 'conf', 'whitelist.txt')
        with open(self.scan_whitelist_path, 'r') as f:
            whitelist_paths = set([line.replace('<username>', self.windows_username) for line in f.read().splitlines()])
        self.scan_whitelist_tuple = tuple(whitelist_paths)

        # Load file extensions
        self.file_extensions_path = join(script_dir, 'conf', 'file_extensions.txt')
        with open(self.file_extensions_path, 'r') as f:
            extensions = set(f.read().splitlines())
        self.file_extensions_tuple = tuple(extensions)

        self.initialize_locks()
        run_coroutine_threadsafe(self.initial_log(), self.loop)

    def initialize_locks(self):
        self.log_lock = Lock()
        self.pending_events = {}

    async def initial_log(self):
        if self.delete_malware:
            await session_log('INFO: Malware files will be automatically deleted.')
        if self.delete_extensions:
            await session_log('INFO: Created files with the configured extensions will be automatically deleted.')

    async def log_event(self, event_type, event_path, dest_path=None):
        event_time = datetime.now().strftime('%H:%M - %d/%m/%Y')
        
        await sleep(0.1)  # adding a small delay to handle events occurring in rapid succession.

        try:
            file_size = getsize(event_path) if exists(event_path) else None
        except FileNotFoundError:
            file_size = None
        except Exception as e:
            await session_log(f'[{event_time}] ERROR: Error getting size of {event_path}: {e}')
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

        # processing the event
        if not event_details['file_path'].startswith(self.scan_whitelist_tuple):
            if yara_scan(event_path)[0]:
                if event_path.lower() != self.yara_forge_rules_full_path.lower():
                    await session_log(f'[{event_time}] WARNING: Malware detected in: "{event_path}"')
                    if self.delete_malware:
                        await self.delete_file(event_time, event_path, event_details)
                    await session_log(f'[{event_time}] INFO: Alert received by {yara_scan(event_path)[1]} YARA Rule in "{event_path}"')
            else:
                if event_type == 'File created':
                    if event_details['file_path'].endswith(self.file_extensions_tuple):
                        await session_log(f'[{event_time}] WARNING: File with a configured extension created in: "{event_path}"')
                        if not event_details['file_path'].startswith(self.scan_whitelist_tuple):
                            if self.delete_extensions:
                                await self.delete_file(event_time, event_path, event_details)
                    await session_log(f'[{event_time}] Attention: File created in: "{event_path}"')
                elif event_type == 'File modified':
                    if event_details['file_path'].endswith(self.file_extensions_tuple):
                        await session_log(f'[{event_time}] WARNING: File with a configured extension modified in: "{event_path}"')
                    elif event_path.lower() != self.session_log_path.lower():
                        await session_log(f'[{event_time}] Attention: File modified in: "{event_path}"')
                elif event_type == 'File deleted':
                    if not exists(event_path):
                        await session_log(f'[{event_time}] Attention: File deleted in: "{event_path}"')
                elif event_type == 'File moved':
                    await session_log(f'[{event_time}] Attention: File moved from "{event_path}" to "{dest_path}"')
                elif event_type == 'Directory created':
                    await session_log(f'[{event_time}] Attention: Directory created in: "{event_path}"')
                elif event_type == 'Directory modified':
                    await session_log(f'[{event_time}] Attention: Directory modified in: "{event_path}"')
                elif event_type == 'Directory deleted':
                    await session_log(f'[{event_time}] Attention: Directory deleted in: "{event_path}"')
                elif event_type == 'Link created':
                    await session_log(f'[{event_time}] Attention: Link created in: "{event_path}"')
                elif event_type == 'Link deleted':
                    await session_log(f'[{event_time}] Attention: Link deleted in: "{event_path}"')
                elif event_type == 'Link modified':
                    await session_log(f'[{event_time}] Attention: Link modified in: "{event_path}"')
                elif event_type == 'Link moved':
                    await session_log(f'[{event_time}] Attention: Link moved from "{event_path}" to "{dest_path}"')

    async def delete_file(self, event_time, event_path, event_details):
        """
        Delete the file if delete_malware or delete_extensions equals True.
        """
        await session_log(f'[{event_time}] INFO: Attempting to delete file: {event_path}')

        try:
            await sleep(0.1)
            while not exists(event_path):
                await sleep(0.1)
            
            result = subprocess_run(f'del /f "{event_path}"', shell=True, check=True, stdout=PIPE, stderr=PIPE)
            if result.returncode == 0:
                await session_log(f'[{event_time}] SUCCESSFUL: The file "{event_path}" has been deleted.')
            else:
                await session_log(f'[{event_time}] ERROR: The file "{event_path}" could not be deleted.')
        except Exception as e:
            await session_log(f'[{event_time}] ERROR: "{event_path}" file could not be removed: {e}')

    def yara_rule(self, event_path):
        """
        Get the YARA rule that matched the file.
        """
        return yara_scan(event_path)[1]

    def on_created(self, event):
        run_coroutine_threadsafe(self.log_event('File created', event.src_path), self.loop)

    def on_deleted(self, event):
        run_coroutine_threadsafe(self.log_event('File deleted', event.src_path), self.loop)

    def on_modified(self, event):
        run_coroutine_threadsafe(self.log_event('File modified', event.src_path), self.loop)

    def on_moved(self, event):
        run_coroutine_threadsafe(self.log_event('File moved', event.src_path, event.dest_path), self.loop)
