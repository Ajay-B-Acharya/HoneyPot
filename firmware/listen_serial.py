import serial
import time

try:
    with serial.Serial('COM7', 115200, timeout=1) as ser:
        print("[Host] Listening on COM7 for 15 seconds...")
        start = time.time()
        while time.time() - start < 15:
            line = ser.readline()
            if line:
                print(line.decode('utf-8', errors='replace'), end='', flush=True)
except Exception as e:
    print(f"Error: {e}")
