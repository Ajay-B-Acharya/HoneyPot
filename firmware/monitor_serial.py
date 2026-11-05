import serial
import time
import sys

print("Connecting to COM7 at 115200 baud...")
try:
    with serial.Serial("COM7", 115200, timeout=1.0) as ser:
        t_end = time.time() + 20.0
        while time.time() < t_end:
            line = ser.readline()
            if line:
                decoded = line.decode("utf-8", errors="replace").rstrip()
                print(decoded, flush=True)
except Exception as e:
    print("Serial error:", e)
