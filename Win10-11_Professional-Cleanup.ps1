<# 
.SYNOPSIS
 Professionelles Windows 10/11 Cleanup-Skript für den Einsatz in produktiven Umgebungen.

.BESCHREIBUNG
 Dieses Skript bereinigt Windows 10/11 gründlich und sicher, ohne Neustart und ohne Benutzerinteraktion.
 Es entfernt unnötige Dateien, Caches und Logs, und prüft/repariert Windows-Systemdateien.
 Standardmäßig wird immer eine Integritätsprüfung (DeepRepair) durchgeführt.

.ANWENDUNG
 1. PowerShell als Administrator starten.
 2. In den Ordner wechseln, in dem das Skript liegt.
 3. Skript starten mit:
    .\Win10-11_Admin-Cleanup.ps1

OPTIONALE PARAMETER:
 -IncludePrefetch
    Leert den Prefetch-Ordner (Programme starten beim ersten Mal etwas langsamer).
 -BrowserCacheHard
    Löscht Browser-Caches (Edge, Chrome, Firefox), ohne Cookies oder Passwörter.
 -ResetWU
    Setzt den Windows Update-Cache zurück (Updates werden ggf. neu geladen).
 -DryRun
    Simulation – es wird nichts gelöscht, nur angezeigt, was gelöscht würde.
 -KeepLogsDays <Zahl>
    Legt fest, wie viele Tage alte Log-Dateien im Ordner C:\ProgramData\SSIG\Cleanup behalten werden.

BEISPIELE:
 • Standardlauf (empfohlen):
   .\Win10-11_Admin-Cleanup.ps1

 • Mit Prefetch- und Browser-Cache-Löschung:
   .\Win10-11_Admin-Cleanup.ps1 -IncludePrefetch -BrowserCacheHard

 • Nur Simulation, keine Löschung:
   .\Win10-11_Admin-Cleanup.ps1 -DryRun

.HINWEISE
 - Das Skript ist für Windows 10 und Windows 11 geeignet.
 - Es werden keine persönlichen Dateien oder Programme entfernt.
 - Nutzer können während der Ausführung weiterarbeiten.
 - Dauer hängt von Systemzustand und PC-Leistung ab (DeepRepair kann mehrere Minuten beanspruchen).
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
param(
  [switch]$IncludePrefetch,
  [switch]$BrowserCacheHard,
  [switch]$CloseBrowsers,
  [switch]$ResetWU,
  [switch]$SkipCleanmgr,
  [switch]$SkipDeepRepair,
  [switch]$DryRun,
  [int]$KeepLogsDays = 14
)

# -------------------- Basissetup --------------------
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'  # Fehler gezielt abfangen

# Admin-Check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Dieses Skript muss als Administrator ausgeführt werden." -ForegroundColor Yellow
  exit 1
}

# Mutex gegen Doppelstart
$mutexName = "Global\SSIG_CustomerSafe_Cleanup"
$mutex = New-Object System.Threading.Mutex($false, $mutexName, [ref]$createdNew)
if (-not $mutex.WaitOne(0)) {
  Write-Host "Cleanup läuft bereits. Abbruch." -ForegroundColor Yellow
  exit 2
}

# Logging
$StartTime = Get-Date
$LogRoot = "$env:ProgramData\SSIG\Cleanup"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$LogFile = Join-Path $LogRoot ("Cleanup_{0:yyyy-MM-dd_HH-mm-ss}.log" -f $StartTime)
try { Start-Transcript -Path $LogFile -Force | Out-Null } catch {}

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
  $line = "{0:u} [{1}] {2}" -f (Get-Date), $Level, $Message
  try { Write-Host $line } catch {}
  try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

function Remove-PathSafe {
  param([string]$Path)
  $hasWildcard = ($Path -like '*[*?]*')

  if ($hasWildcard) {
    $exists = Test-Path -Path $Path
  } else {
    $exists = Test-Path -LiteralPath $Path
  }

  if (-not $exists) {
    Write-Log "Pfad nicht gefunden: $Path"
    return
  }

  if ($DryRun) {
    Write-Log "DRYRUN: würde löschen -> $Path"
    return
  }

  try {
    if ($hasWildcard) {
      Get-ChildItem -Path $Path -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Attributes='Normal' } catch {} }
      Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    } else {
      Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { try { $_.Attributes='Normal' } catch {} }
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Gelöscht: $Path"
  } catch {
    Write-Log "Fehler beim Löschen: $Path => $($_.Exception.Message)" 'WARN'
  }
}

function Invoke-External {
  param(
    [Parameter(Mandatory)] [string]$FilePath,
    [string[]]$Arguments = @()
  )
  if ($DryRun) { Write-Log "DRYRUN: würde starten -> $FilePath $($Arguments -join ' ')"; return 0 }
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($Arguments -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($out) { Write-Log $out.Trim() }
    if ($err) { Write-Log $err.Trim() 'WARN' }
    return $p.ExitCode
  } catch {
    Write-Log "Startfehler: $FilePath => $($_.Exception.Message)" 'ERROR'
    return -1
  }
}

function Get-FreeBytes($drive='C') {
  try { (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${drive}:'").FreeSpace } catch { 0 }
}

# -------------------- Startinfo --------------------
Write-Log "== Cleanup gestartet | Computer: $env:COMPUTERNAME | User: $env:USERNAME | DryRun=$DryRun =="
$FreeBefore = Get-FreeBytes 'C'

# Benutzerordner ermitteln (nur echte Profile)
$UserDirs = @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -notin @('All Users','Default','Default User','Public','DefaultAppPool')
})

# -------------------- 1) Benutzer- und System-Temp --------------------
Write-Log "[1] Benutzer-Temp & INetCache"
foreach ($U in $UserDirs) {
  Remove-PathSafe "$($U.FullName)\AppData\Local\Temp\*"
  Remove-PathSafe "$($U.FullName)\AppData\Local\Microsoft\Windows\INetCache\*"
}

Write-Log "[2] System-Temp"
Remove-PathSafe "$env:windir\Temp\*"
Remove-PathSafe "$env:TEMP\*"

# -------------------- 2) Delivery Optimization Cache --------------------
Write-Log "[3] Delivery Optimization Cache"
Remove-PathSafe "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache\*"

# -------------------- 3) Windows- und Setup-Logs --------------------
Write-Log "[4] Windows-/Setup-Logs"
Remove-PathSafe "$env:windir\Logs\CBS\*"
Remove-PathSafe "$env:windir\Logs\DISM\*"
Remove-PathSafe "$env:windir\Panther\*"
Remove-PathSafe "$env:windir\inf\*.log"

# -------------------- 4) Caches (Shader/Thumbnail/Icon) profilübergreifend --------------------
Write-Log "[5] Shader-, Thumbnail- und Icon-Cache (alle Profile)"
foreach ($U in $UserDirs) {
  $LocalApp = Join-Path $U.FullName "AppData\Local"
  Remove-PathSafe "$LocalApp\Microsoft\Windows\ShaderCache\*"
  Remove-PathSafe "$LocalApp\Microsoft\Windows\Explorer\thumbcache_*.db"
  Remove-PathSafe "$LocalApp\IconCache.db"
}

# -------------------- 5) Cleanmgr (Standard: an) --------------------
if (-not $SkipCleanmgr) {
  Write-Log "[6] Cleanmgr SAGERUN"
  $SageId = 20250
  $handlers = @(
    'Temporary Files','Temporary Setup Files','Old ChkDsk Files','Setup Log Files',
    'Windows Error Reporting Files','DirectX Shader Cache','Thumbnail Cache',
    'Update Cleanup','Device Driver Packages','Delivery Optimization Files'
  )
  $vcBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
  foreach ($h in $handlers) {
    $path = Join-Path $vcBase $h
    if (Test-Path $path -PathType Container -ErrorAction SilentlyContinue) {
      if (-not $DryRun) {
        try { New-ItemProperty -Path $path -Name "StateFlags$SageId" -Value 2 -PropertyType DWord -Force | Out-Null } catch {}
      }
    }
  }
  if (-not $DryRun) { [void](Invoke-External -FilePath "cleanmgr.exe" -Arguments @("/sagerun:$SageId")) }
} else {
  Write-Log "[6] Cleanmgr deaktiviert (SkipCleanmgr)"
}

# -------------------- 6) Prefetch (optional) --------------------
if ($IncludePrefetch) {
  Write-Log "[7] Prefetch leeren"
  if (-not $DryRun) {
    try { Stop-Service SysMain -Force -ErrorAction SilentlyContinue } catch {}
    Remove-PathSafe "$env:windir\Prefetch\*"
    try { Start-Service SysMain -ErrorAction SilentlyContinue } catch {}
  }
} else {
  Write-Log "[7] Prefetch übersprungen (Default: aus)"
}

# -------------------- 7) Windows Update Reset (optional) --------------------
if ($ResetWU) {
  Write-Log "[8] Windows Update-Cache zurücksetzen"
  if (-not $DryRun) {
    Invoke-External -FilePath "net.exe" -Arguments @("stop","wuauserv") | Out-Null
    Invoke-External -FilePath "net.exe" -Arguments @("stop","bits") | Out-Null
    Invoke-External -FilePath "net.exe" -Arguments @("stop","cryptsvc") | Out-Null
    try { Rename-Item "$env:windir\SoftwareDistribution" "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue } catch { Write-Log $_.Exception.Message 'WARN' }
    try { Rename-Item "$env:windir\System32\catroot2" "catroot2.old" -Force -ErrorAction SilentlyContinue } catch { Write-Log $_.Exception.Message 'WARN' }
    Invoke-External -FilePath "net.exe" -Arguments @("start","wuauserv") | Out-Null
    Invoke-External -FilePath "net.exe" -Arguments @("start","bits") | Out-Null
    Invoke-External -FilePath "net.exe" -Arguments @("start","cryptsvc") | Out-Null
  }
} else {
  Write-Log "[8] Windows Update-Reset übersprungen (Default: aus)"
}

# -------------------- 8) Browser-Caches (optional, profilübergreifend) --------------------
if ($BrowserCacheHard) {
  Write-Log "[9] Browser-Caches leeren (Hard)"
  if ($CloseBrowsers) {
    try { Get-Process chrome, msedge, firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 } catch {}
  } else {
    Write-Log "Browser werden nicht geschlossen (-CloseBrowsers nicht gesetzt). Gesperrte Dateien werden ggf. übersprungen." "WARN"
  }
  foreach ($U in $UserDirs) {
    $LocalApp = Join-Path $U.FullName "AppData\Local"
    $RoamApp  = Join-Path $U.FullName "AppData\Roaming"
    $paths = @(
      "$LocalApp\Microsoft\Edge\User Data\*\Cache\*",
      "$LocalApp\Google\Chrome\User Data\*\Cache\*",
      "$RoamApp\Mozilla\Firefox\Profiles\*\cache2\*"
    )
    foreach ($p in $paths) { Remove-PathSafe $p }
  }
} else {
  Write-Log "[9] Browser-Hard-Clean übersprungen (Default: aus)"
}

# -------------------- 9) DeepRepair (Standard: an, ohne Neustart) --------------------
if (-not $SkipDeepRepair) {
  Write-Log "[10] DeepRepair gestartet (DISM/SFC, kein automatischer Neustart)"
  if (-not $DryRun) {
    $code = Invoke-External -FilePath "dism.exe" -Arguments @("/Online","/Cleanup-Image","/ScanHealth")
    if ($code -eq 0) {
      [void](Invoke-External -FilePath "dism.exe" -Arguments @("/Online","/Cleanup-Image","/RestoreHealth","/NoRestart"))
    } else {
      Write-Log "DISM ScanHealth meldete Fehlercode $code – RestoreHealth wird übersprungen." "WARN"
    }

    # SFC: Neustart-Hinweise nur loggen, keinen Neustart auslösen
    $sfcLogTmp = Join-Path $env:TEMP ("sfc_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
    try {
      $psi = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -RedirectStandardOutput $sfcLogTmp -NoNewWindow -PassThru -ErrorAction SilentlyContinue
      $psi.WaitForExit()
      if (Test-Path $sfcLogTmp) {
        $content = Get-Content $sfcLogTmp -ErrorAction SilentlyContinue
        if ($content -match '(restart|Neustart|pending|ausstehend)') {
          Write-Log "SFC meldet, dass ein Neustart für vollständige Reparaturen empfohlen/erforderlich ist. Kein Neustart wird ausgelöst." "WARN"
        }
        Remove-Item $sfcLogTmp -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Write-Log "SFC-Ausführung: $($_.Exception.Message)" "WARN"
    }
  }
} else {
  Write-Log "[10] DeepRepair übersprungen (SkipDeepRepair)"
}

# -------------------- 10) DNS-Cache --------------------
Write-Log "[11] DNS-Cache leeren"
if (-not $DryRun) {
  try { ipconfig /flushdns | Out-Null } catch { Write-Log "ipconfig/flushdns: $($_.Exception.Message)" "WARN" }
}

# -------------------- Abschluss --------------------
$FreeAfter = Get-FreeBytes 'C'
$freed = [math]::Max(0, ($FreeAfter - $FreeBefore))
$freedMB = [math]::Round($freed/1MB,2)
$dur = (Get-Date) - $StartTime
Write-Log ("== Fertig | Dauer: {0:hh\:mm\:ss} | Frei vorher: {1:N0} MB | Frei nachher: {2:N0} MB | Gewinn: {3:N2} MB ==" -f $dur, ($FreeBefore/1MB), ($FreeAfter/1MB), $freedMB)

# Log-Hygiene
try {
  Get-ChildItem $LogRoot -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepLogsDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
} catch {}

# Cleanup Mutex & Transcript
try { Stop-Transcript | Out-Null } catch {}
try { $mutex.ReleaseMutex() | Out-Null } catch {}

