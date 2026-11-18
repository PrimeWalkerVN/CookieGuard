#Requires -RunAsAdministrator
# CookieGuard installer. Run from an admin PowerShell, signed in as the user to protect:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
# To protect a different local user: -UserProfile C:\Users\<name>
param([string]$UserProfile = $env:USERPROFILE)
$ErrorActionPreference = 'Stop'
$userProfile = $UserProfile
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dst = 'C:\ProgramData\CookieGuard'

# Close any CookieGuard popups still open from an earlier version
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'CookieGuard\\alert\.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# 0. Copy the scripts somewhere only admins can change (so malware running as you can't rewrite them)
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src\alert.ps1", "$src\apply-sacl.ps1", "$src\uninstall.ps1" -Destination $dst -Force
icacls $dst /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
Write-Host "[1/5] Scripts copied to $dst (admin-only write)"

# 1. Turn on file-access auditing (the "File System" subcategory, by GUID so it works in any Windows language)
auditpol /set /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
wevtutil sl Security /ms:104857600   # Security log to 100 MB so alerts aren't rotated out quickly
Write-Host '[2/5] File-access auditing on'

# 2. Mark the browser files
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dst\apply-sacl.ps1" -UserProfile $userProfile
Write-Host '[3/5] Browser files marked'

# 3. Re-mark at startup, at logon and every 30 minutes (backup in case a browser replaces a file)
$act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dst\apply-sacl.ps1`" -UserProfile `"$userProfile`""
$trig = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -AtLogOn),
    (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30))
)
$prin = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'CookieGuard Refresh' -Action $act -Trigger $trig -Principal $prin -Settings $set -Force | Out-Null
Write-Host '[4/5] Refresh task registered'

# 4. Alert task: fires on Security event 4663 only when the reader is NOT a real browser (matched by full path)
$userSid = (Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -eq $userProfile }).SID
$browsers = @(
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe',
    'C:\Program Files\Mozilla Firefox\firefox.exe'
) | Where-Object { Test-Path -LiteralPath $_ }
$notBrowser = ($browsers | ForEach-Object { "Data[@Name='ProcessName']!='$_'" }) -join ' and '
# Only programs running as this user (stealers do); Windows Update and services run as SYSTEM/service accounts.
$xpath = "*[System[EventID=4663]] and *[EventData[Data[@Name='SubjectUserSid']='$userSid' and $notBrowser]]"
$query = "<QueryList><Query Id=`"0`" Path=`"Security`"><Select Path=`"Security`">$xpath</Select></Query></QueryList>"
$queryEsc = [System.Security.SecurityElement]::Escape($query)
$argsEsc  = [System.Security.SecurityElement]::Escape("--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$dst\alert.ps1`" -Proc `"`$(Proc)`" -ProcId `"`$(ProcId)`" -Obj `"`$(Obj)`"")

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>CookieGuard: warns when a program other than your browser opens browser cookie or password files.</Description></RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$queryEsc</Subscription>
      <ValueQueries>
        <Value name="Proc">Event/EventData/Data[@Name='ProcessName']</Value>
        <Value name="ProcId">Event/EventData/Data[@Name='ProcessId']</Value>
        <Value name="Obj">Event/EventData/Data[@Name='ObjectName']</Value>
      </ValueQueries>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>$userSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>conhost.exe</Command><Arguments>$argsEsc</Arguments></Exec>
  </Actions>
</Task>
"@
Register-ScheduledTask -TaskName 'CookieGuard Alert' -Xml $xml -Force | Out-Null
Write-Host '[5/5] Alert task registered'
Write-Host ''
Write-Host 'CookieGuard is on. Alerts are logged to %LOCALAPPDATA%\CookieGuard\alerts.log'
Write-Host 'To test it, in a NORMAL (non-admin) PowerShell run:'
Write-Host '  Get-Content "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -TotalCount 1 | Out-Null'
Write-Host 'A warning about powershell.exe should pop up within a few seconds (click No).'
