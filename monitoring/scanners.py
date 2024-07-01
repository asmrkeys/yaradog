from monitoring.funcs import read_partitions_from_json, json_filename, gen_json, session_log, initialize_lock
from monitoring.handler import ChangeHandler, sleep
from watchdog.observers import Observer
from threading import Thread, Event
import asyncio

# Global variable to stop the loop
filesystem_scanner_stop_event = Event()

def start_filesystem_monitoring(paths, loop):
    """
    Start monitoring the given paths for changes.
    """
    observer = Observer()
    handler = ChangeHandler(loop=loop, delete_malware=False, delete_extensions=False)
    asyncio.run_coroutine_threadsafe(session_log('Starting monitoring for changes...'), loop).result()
    for path in paths:
        observer.schedule(handler, path, recursive=True)
    observer.start()
    try:
        while not filesystem_scanner_stop_event.is_set():  # Check for stop event
            asyncio.run_coroutine_threadsafe(sleep(1), loop).result()
    except Exception as e:
        asyncio.run_coroutine_threadsafe(session_log(f'Error: {e}'), loop).result()
    finally:
        asyncio.run_coroutine_threadsafe(session_log('Stopping monitoring...'), loop).result()
        observer.stop()
        observer.join()  # Wait for the observer to fully stop

def scan_tree(loop):
    """
    Start monitoring based on the JSON data.
    """
    paths = read_partitions_from_json(json_filename)
    start_filesystem_monitoring(paths, loop)

def filesystem_scanner(loop):
    gen_json()  # Generate the JSON file before starting the event loop
    asyncio.set_event_loop(loop)  # Set the provided loop
    initialize_lock()  # Initializes the lock in the current event loop
    t = Thread(target=loop.run_forever)
    t.start()
    try:
        scan_tree(loop)
    finally:
        filesystem_scanner_stop_event.set()  # Signal to stop the monitoring loop
        loop.call_soon_threadsafe(loop.stop)  # Ensure loop stops
        t.join()  # Wait for the thread to finish
