from monitoring.funcs import read_partitions_from_json, json_filename, gen_json, session_log, initialize_lock
from monitoring.handler import ChangeHandler, sleep
from watchdog.observers import Observer
from threading import Thread
import asyncio

def start_monitoring(paths, loop):
    """
    Start monitoring the given paths for changes.
    """
    observer = Observer()
    handler = ChangeHandler(loop=loop, debug=True, defense=True, aggressive=True)
    asyncio.run_coroutine_threadsafe(session_log('Starting monitoring for changes...'), loop).result()
    for path in paths:
        observer.schedule(handler, path, recursive=True)
    observer.start()
    try:
        while True:
            asyncio.run_coroutine_threadsafe(sleep(1), loop).result()
    except KeyboardInterrupt:
        asyncio.run_coroutine_threadsafe(session_log('Stopping monitoring...'), loop).result()
        observer.stop()
    observer.join()

def scan_tree(loop):
    """
    Start monitoring based on the JSON data.
    """
    paths = read_partitions_from_json(json_filename)
    start_monitoring(paths, loop)

def scanner():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    initialize_lock()  # Initializes the lock in the current event loop
    asyncio.run(gen_json())  # Run gen_json() after lock initialization
    t = Thread(target=loop.run_forever)
    t.start()
    try:
        scan_tree(loop)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join()
