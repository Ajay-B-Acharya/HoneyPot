import subprocess
import time
import threading
import sys

cmd_file = sys.argv[1] if len(sys.argv) > 1 else r"C:\Projects\IOT honey pot monitoring\firmware\status.jlink"

stop_watch = threading.Event()

def watcher():
    while not stop_watch.is_set():
        subprocess.run(["taskkill", "/F", "/IM", "JLinkGUIServer.exe"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.2)

p = subprocess.Popen(
    [
        r"C:\Program Files\SEGGER\JLink_V980\JLink.exe",
        "-device", "RW612",
        "-if", "SWD",
        "-speed", "1000",
        "-autoconnect", "0",
        "-CommandFile", cmd_file
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

w = threading.Thread(target=watcher, daemon=True)
w.start()

out, _ = p.communicate()
stop_watch.set()
print(out)
