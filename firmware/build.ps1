$env:PATH = "C:\Users\ASUS\.mcuxpressotools\.mcux-venv-3.12\Scripts;C:\Users\ASUS\.mcuxpressotools\cmake-3.30.0-windows-x86_64\bin;C:\Users\ASUS\.mcuxpressotools\ninja-1.13.2;" + $env:PATH
$env:ARMGCC_DIR = "C:\Users\ASUS\.mcuxpressotools\arm-gnu-toolchain-14.2.rel1-mingw-w64-x86_64-arm-none-eabi"

Set-Location "C:\NXP\SDK_26_06_00_FRDM-RW612"

Write-Host "Starting pristine clean build with flash_release target..."
& "C:\Users\ASUS\.mcuxpressotools\.mcux-venv-3.12\Scripts\west.exe" build -b frdmrw612 -p always -d "C:\Projects\IOT honey pot monitoring\firmware\build" "C:\Projects\IOT honey pot monitoring\firmware" -- -DCMAKE_BUILD_TYPE=flash_release
