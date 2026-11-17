#Requires -RunAsAdministrator
# Removes CookieGuard completely. Run from an admin PowerShell:
#   powershell -ExecutionPolicy Bypass -File C:\ProgramData\CookieGuard\uninstall.ps1
$dst = 'C:\ProgramData\CookieGuard'
Unregister-ScheduledTask -TaskName 'CookieGuard Alert'   -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'CookieGuard Refresh' -Confirm:$false -ErrorAction SilentlyContinue
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dst\apply-sacl.ps1" -Remove
auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:disable /failure:disable | Out-Null
Set-Location $env:SystemRoot
Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'CookieGuard removed. (Your alert log in %LOCALAPPDATA%\CookieGuard was kept.)'
