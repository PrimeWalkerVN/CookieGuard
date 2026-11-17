# CookieGuard: run by the "CookieGuard Alert" task when a non-browser program opens a browser credential file.
# Windows passes in the program path, its process ID (hex) and the file it opened.
param([string]$Proc, [string]$ProcId, [string]$Obj)

$logDir = Join-Path $env:LOCALAPPDATA 'CookieGuard'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'alerts.log'
function Log($text) { Add-Content -LiteralPath $log -Value ("[{0}] {1}" -f (Get-Date -Format 's'), $text) }

$pidNum = 0
try { $pidNum = [Convert]::ToInt32(($ProcId -replace '^0x', ''), 16) } catch { }

# Trusted readers: genuine, validly signed browsers, Defender and Windows Search, in their real install folders.
$trustedDirs = @(
    'C:\Program Files (x86)\Microsoft\Edge\',
    'C:\Program Files\Microsoft\Edge\',
    'C:\Program Files\Google\Chrome\',
    'C:\Program Files\BraveSoftware\',
    'C:\Program Files\Mozilla Firefox\',
    'C:\ProgramData\Microsoft\Windows Defender\Platform\',
    'C:\Program Files\Windows Defender\'
)
$trustedFiles = @(
    'C:\Windows\System32\SearchProtocolHost.exe',
    'C:\Windows\System32\SearchIndexer.exe',
    'C:\Windows\System32\SearchFilterHost.exe'
)
$trusted = $false
$sigText = 'unknown'
if ($Proc -and (Test-Path -LiteralPath $Proc)) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Proc
    $sigText = "$($sig.Status) $($sig.SignerCertificate.Subject -replace '^CN=([^,]+).*', '$1')"
    $inTrustedPlace = ($trustedDirs | Where-Object { $Proc.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }) -or ($trustedFiles -contains $Proc)
    if ($sig.Status -eq 'Valid' -and $inTrustedPlace) { $trusted = $true }
}

if ($trusted) { Log "ok       pid=$pidNum $Proc -> $Obj"; exit 0 }
Log "ALERT    pid=$pidNum sig=[$sigText] $Proc -> $Obj"

# One popup per process per 2 minutes; a stealer reads several files in a row.
$mark = Join-Path $logDir "seen-$pidNum.txt"
if ((Test-Path $mark) -and ((Get-Item $mark).LastWriteTime -gt (Get-Date).AddMinutes(-2))) { exit 0 }
Set-Content -LiteralPath $mark -Value $Proc

Add-Type -AssemblyName System.Windows.Forms
$msg = @"
A program that is NOT your browser just opened your browser's saved login data.

Program:     $Proc
Process ID:  $pidNum
Signature:   $sigText
File:        $Obj

This is exactly what cookie stealers do. If you don't recognise this program, click YES to stop it now, then disconnect from the internet and check the PC.

Stop this program now?
"@
$answer = [System.Windows.Forms.MessageBox]::Show($msg, 'CookieGuard: possible cookie theft', 'YesNo', 'Warning', 'Button1', 'DefaultDesktopOnly')
if ($answer -eq 'Yes' -and $pidNum -gt 0) {
    try {
        Stop-Process -Id $pidNum -Force -ErrorAction Stop
        Log "STOPPED  pid=$pidNum $Proc"
        [System.Windows.Forms.MessageBox]::Show("Stopped $Proc.`n`nDisconnect from the internet and scan the PC.", 'CookieGuard', 'OK', 'Information', 'Button1', 'DefaultDesktopOnly') | Out-Null
    } catch {
        Log "STOP FAILED pid=$pidNum : $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Couldn't stop it (it may be running as admin): $($_.Exception.Message)`n`nDisconnect from the internet now, then end it from Task Manager as admin.", 'CookieGuard', 'OK', 'Error', 'Button1', 'DefaultDesktopOnly') | Out-Null
    }
} else {
    Log "allowed  pid=$pidNum (user clicked No)"
}
