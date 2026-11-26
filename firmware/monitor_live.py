import serial
import time
import subprocess
import threading
import sys

def reader():
    try:
        ser = serial.Serial('COM7', 115200, timeout=0.1)
        while True:
            line = ser.readline()
            if line:
                try:
                    text = line.decode('utf-8', errors='replace')
                    sys.stdout.write(text)
                    sys.stdout.flush()
                except:
                    pass
    except Exception as e:
        print(f"Serial err: {e}")

t = threading.Thread(target=reader, daemon=True)
t.start()

time.sleep(1)

# Reset board via JLink
print("[Host] Resetting board...")
job_cmd = """
$job = Start-Job -ScriptBlock {
    & 'C:\\Program Files\\SEGGER\\JLink_V980\\JLink.exe' -device RW612 -if SWD -speed 1000 -autoconnect 1 -CommandFile 'C:\\Projects\\IOT honey pot monitoring\\firmware\\reset_run.jlink'
}
for ($i = 0; $i -lt 15; $i++) {
    Get-Process -Name 'JLinkGUIServer' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($job.State -ne 'Running') { break }
    Start-Sleep -Milliseconds 300
}
Receive-Job -Job $job
Remove-Job -Job $job -Force
"""
subprocess.run(["powershell", "-Command", job_cmd], capture_output=True)

for i in range(25):
    time.sleep(1)
print("\n[Host] Finished monitor.")
