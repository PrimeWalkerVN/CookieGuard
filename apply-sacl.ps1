# CookieGuard: marks browser cookie/password files so Windows logs every program that opens them.
# Must run as admin or SYSTEM (setting audit rules needs the "Manage auditing" privilege).
# Re-run regularly: browsers sometimes replace these files, and a replaced file loses the mark.
param(
    [string]$UserProfile = $env:USERPROFILE,
    [switch]$Remove
)

$local = Join-Path $UserProfile 'AppData\Local'
$roam  = Join-Path $UserProfile 'AppData\Roaming'
$targets = New-Object System.Collections.Generic.List[string]

# Chromium browsers: the key file (Local State) plus each profile's cookies, passwords and autofill/cards
foreach ($root in "$local\Microsoft\Edge\User Data", "$local\Google\Chrome\User Data", "$local\BraveSoftware\Brave-Browser\User Data") {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $targets.Add("$root\Local State")
    Get-ChildItem -LiteralPath $root -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | ForEach-Object {
        $targets.Add("$($_.FullName)\Network\Cookies")
        $targets.Add("$($_.FullName)\Login Data")
        $targets.Add("$($_.FullName)\Web Data")
    }
}
# Firefox: cookies, saved logins and the key that decrypts them
Get-ChildItem -LiteralPath "$roam\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $targets.Add("$($_.FullName)\cookies.sqlite")
    $targets.Add("$($_.FullName)\logins.json")
    $targets.Add("$($_.FullName)\key4.db")
}

$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'None', 'None', 'Success, Failure')

# Folders whose files get replaced (Local State, logins.json): an inheritable rule so a new copy is marked as it is created.
# Applies only to files directly inside the folder (no subfolders), and not to the folder itself.
$dirRule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'ObjectInherit', 'InheritOnly, NoPropagateInherit', 'Success, Failure')
$dirs = $targets | Where-Object { $_ -match '\\(Local State|logins\.json)$' } | ForEach-Object { Split-Path -Parent $_ } | Select-Object -Unique
foreach ($d in $dirs) {
    if (-not (Test-Path -LiteralPath $d)) { continue }
    try {
        $di  = Get-Item -LiteralPath $d -Force
        $sec = $di.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        if ($Remove) { [void]$sec.RemoveAuditRule($dirRule) } else { $sec.AddAuditRule($dirRule) }
        $di.SetAccessControl($sec)
        "OK      (folder) $d"
    } catch {
        "FAILED  (folder) $d : $($_.Exception.Message)"
    }
}

$ok = 0; $failed = 0
foreach ($f in $targets) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    try {
        $fi  = Get-Item -LiteralPath $f -Force
        $sec = $fi.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        if ($Remove) { [void]$sec.RemoveAuditRule($rule) } else { $sec.AddAuditRule($rule) }
        $fi.SetAccessControl($sec)
        $ok++
        "OK      $f"
    } catch {
        $failed++
        "FAILED  $f : $($_.Exception.Message)"
    }
}
"Done: $ok file(s) $(if ($Remove) { 'unmarked' } else { 'marked' }), $failed failed."
