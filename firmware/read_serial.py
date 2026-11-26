import serial
import time
import subprocess
import threading

output_lines = []
stop_event = threading.Event()

def reader():
    try:
        with serial.Serial('COM7', 115200, timeout=0.2) as ser:
            ser.reset_input_buffer()
            while not stop_event.is_set():
                line = ser.readline()
                if line:
                    decoded = line.decode('utf-8', errors='replace')
                    print(decoded, end='', flush=True)
                    output_lines.append(decoded)
    except Exception as e:
        print(f'Serial error: {e}')

t = threading.Thread(target=reader)
t.start()
time.sleep(0.5)

print("[Host] Resetting board and listening for 30 seconds...")
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

# Listen for 30 seconds
for sec in range(30):
    time.sleep(1)
    if sec % 5 == 0:
        print(f"[Host: {sec}s elapsed]")

stop_event.set()
t.join()
print('\n=== DONE ===')
