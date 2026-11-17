# CookieGuard

Get a Windows popup when a program that isn't your browser opens your browser's cookie or password files, with a button to stop that program.

Cookie stealers ("infostealers") copy your browser's cookie and password files and send them to an attacker. With your session cookies, the attacker can log in as you, even if you have two-factor sign-in (2FA) turned on. CookieGuard uses Windows' own file-access auditing to catch the moment another program opens those files.

No extra software is needed: just PowerShell, Windows auditing and Task Scheduler.

## What it watches

| Browser | Files |
|---|---|
| Edge, Chrome, Brave | `Local State` (holds the cookie decryption key), and in each profile `Network\Cookies`, `Login Data`, `Web Data` |
| Firefox | `cookies.sqlite`, `logins.json`, `key4.db` in each profile |

The following programs are trusted and never raise an alert. Each one counts only when it runs from its real install folder **and** has a valid digital signature, so a fake `msedge.exe` in AppData still triggers an alert:
- the real browsers
- Microsoft Defender
- Windows Search

## How it works

1. **Turns on file-access auditing.** Install switches on the Windows audit category "File System", then adds an audit rule to the files above, and to the folders that hold `Local State` and `logins.json`, so Windows logs a Security event (4663) whenever they're opened.
2. **Fires on reads by anything other than a browser.** The scheduled task **CookieGuard Alert** runs whenever that event comes from a program other than a real browser, and starts `alert.ps1` with the program's path, its process ID and the file it opened.
3. **Shows the popup.** `alert.ps1` checks the trust list. For anything not on it, it logs the event and shows a warning that asks **Stop this program now?**, with **Yes** and **No** buttons. If one program opens several files, you get one popup per 2 minutes, not one per file.
4. **Keeps the audit rules in place.** The scheduled task **CookieGuard Refresh** runs under Windows' built-in SYSTEM account at startup, at logon and every 30 minutes, and re-applies the audit rules in case a browser replaced a file.

The scripts are copied to `C:\ProgramData\CookieGuard`, where only admins can change them. Alerts are logged to `%LOCALAPPDATA%\CookieGuard\alerts.log`.

## Install

Open PowerShell as administrator (right-click PowerShell and choose **Run as administrator**) while signed in as the user you want to protect. Go to the folder that holds `install.ps1`, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
# or, for another local user:
powershell -ExecutionPolicy Bypass -File .\install.ps1 -UserProfile C:\Users\<name>
```

`-ExecutionPolicy Bypass` lets this one PowerShell run start an unsigned script. It doesn't change your execution policy setting.

Re-run it after adding a new browser or browser profile.

## Test

This starts a hidden PowerShell window that reads the first line of Edge's `Local State` file and then waits 60 seconds, so there's time to stop it from the popup.

```powershell
$cmd = 'Get-Content -LiteralPath "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -TotalCount 1 | Out-Null; Start-Sleep 60'
Start-Process powershell.exe -ArgumentList "-NoProfile -EncodedCommand $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)))" -WindowStyle Hidden
```

A warning about `powershell.exe` should pop up within a second or two. Click **Yes** to check that the stop button kills it.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\CookieGuard\uninstall.ps1
```

This removes both tasks and the audit rules, and turns file-system auditing back off. Your alert log is kept.

## Limits

- **It warns, it doesn't block.** The popup appears after the file has been opened. Clicking **Yes** quickly can kill the stealer before it sends anything, but there's no guarantee.
- **Admin-level malware can turn it off.** CookieGuard catches stealers that run as you. Anything you allow at a Windows "Do you want to allow this app to make changes to your device?" (UAC) prompt can disable auditing or delete the tasks.
- **Not covered:** Discord and Telegram tokens, crypto wallets, and any other app's data.
- **Possible false alarms:** password-manager imports, backup tools, forensics or cleanup scripts. Click **No** for anything you recognise.
- **Managed devices:** company policy (Intune, JumpCloud, GPO) may override the audit setting. Check with IT.
