import serial
import subprocess
import threading
import time

lines = []
stop_event = threading.Event()

def reader():
    try:
        with serial.Serial("COM7", 115200, timeout=0.2) as ser:
            while not stop_event.is_set():
                line = ser.readline()
                if line:
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    lines.append(decoded)
                    print(decoded, flush=True)
    except Exception as e:
        print("Reader error:", e, flush=True)

t = threading.Thread(target=reader, daemon=True)
t.start()
time.sleep(1.0)

print("Triggering reset via J-Link...")
stop_watch = threading.Event()
def watcher():
    while not stop_watch.is_set():
        subprocess.run(["taskkill", "/F", "/IM", "JLinkGUIServer.exe"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.2)

w = threading.Thread(target=watcher, daemon=True)
w.start()

p = subprocess.Popen(
    [
        r"C:\Program Files\SEGGER\JLink_V980\JLink.exe",
        "-device", "RW612",
        "-if", "SWD",
        "-speed", "1000",
        "-autoconnect", "0",
        "-CommandFile", r"C:\Projects\IOT honey pot monitoring\firmware\reset.jlink"
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

out, _ = p.communicate()
stop_watch.set()
print("Reset triggered.")

print("Listening on COM7 for 20 seconds...")
time.sleep(20.0)
stop_event.set()
t.join(timeout=2.0)

print("=== TOTAL CAPTURED LINES ===")
for l in lines:
    print(l)
