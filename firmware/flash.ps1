$job = Start-Job -ScriptBlock {
    & "C:\Program Files\SEGGER\JLink_V980\JLink.exe" -device RW612 -if SWD -speed 1000 -autoconnect 0 -CommandFile "C:\Projects\IOT honey pot monitoring\firmware\flash.jlink"
}

for ($i = 0; $i -lt 40; $i++) {
    Get-Process -Name "JLinkGUIServer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($job.State -ne 'Running') { break }
    Start-Sleep -Milliseconds 500
}

$res = Receive-Job -Job $job
Remove-Job -Job $job -Force
Write-Output $res
