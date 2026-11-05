import subprocess
import time
import sys

cmd_file = sys.argv[1] if len(sys.argv) > 1 else r"C:\Projects\IOT honey pot monitoring\firmware\status.jlink"

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

for _ in range(30):
    subprocess.run(["powershell", "-Command", "Stop-Process -Name 'JLinkGUIServer' -Force -ErrorAction SilentlyContinue"], capture_output=True)
    if p.poll() is not None:
        break
    time.sleep(0.5)

out, _ = p.communicate()
print(out)
