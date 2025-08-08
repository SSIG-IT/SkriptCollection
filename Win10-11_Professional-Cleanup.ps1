<# 
.SYNOPSIS
 Professionelles Windows 10/11 Cleanup – sicher, ohne Neustart, ohne Benutzerinteraktion.
 Mit fest integriertem DeepRepair (DISM + SFC) im Standardlauf.

.DESCRIPTION
 Entfernt alle sicheren, unnötigen Dateien, Caches und Logs.
 Führt immer eine Integritätsprüfung und -reparatur durch (DISM/SFC).
 Nutzer können direkt weiterarbeiten. Funktioniert auf Win10/11.

.PARAMETER IncludePrefetch
 Leert Prefetch-Ordner (SysMain wird kurz gestoppt/gestartet).

.PARAMETER ResetWU
 Setzt Windows Update-Cache zurück (SoftwareDistribution & Catroot2 umbenennen).

.PARAMETER BrowserCacheHard
 Entfernt Browser-Caches (Edge, Chrome, Firefox) ohne Cookies/Passwörter.

.PARAMETER DryRun
 Nur simulieren – nichts wird gelöscht.

.PARAMETER KeepLogsDays
 Log-Aufbewahrung in Tagen (Default 14).
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
param(
    [switch]$IncludePrefetch,
    [switch]$ResetWU,
    [switch]$BrowserCacheHard,
    [switch]$DryRun,
    [int]$KeepLogsDays = 14
)

# --- Setup & Logging ---
$ErrorActionPreference = 'SilentlyContinue'
$PSDefaultParameterValues['*:ErrorAction'] = 'SilentlyContinue'
$StartTime = Get-Date
$LogRoot = "$env:ProgramData\SSIG\Cleanup"
$null = New-Item -ItemType Directory -Force -Path $LogRoot
$LogFile = Join-Path $LogRoot ("Cleanup_{0:yyyy-MM-dd_HH-mm-ss}.log" -f $StartTime)
Start-Transcript -Path $LogFile -Force | Out-Null

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    $line = "{0:u} [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

function Get-FreeBytes($drive='C') {
    try { (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${drive}:'").FreeSpace } catch { 0 }
}

function Remove-PathSafe {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        if ($DryRun) { Write-Log "DRYRUN: würde löschen -> $Path" }
        else {
            try {
                Get-ChildItem -LiteralPath $Path -Force -Recurse | ForEach-Object { try { $_.Attributes='Normal' } catch {} }
                Remove-Item -LiteralPath $Path -Recurse -Force
                Write-Log "Gelöscht: $Path"
            } catch { Write-Log "Fehler beim Löschen: $Path => $($_.Exception.Message)" 'WARN' }
        }
    } else { Write-Log "Pfad nicht gefunden: $Path" 'INFO' }
}

Write-Log "== Cleanup gestartet auf $env:COMPUTERNAME | User: $env:USERNAME | DryRun=$DryRun =="
$FreeBefore = Get-FreeBytes 'C'

# --- 1) Benutzer-Temp ---
Write-Log "[1] Benutzer-Temp & INetCache"
Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object {
    Remove-PathSafe "$($_.FullName)\AppData\Local\Temp\*"
    Remove-PathSafe "$($_.FullName)\AppData\Local\Microsoft\Windows\INetCache\*"
}

# --- 2) System-Temp ---
Write-Log "[2] System-Temp"
Remove-PathSafe "$env:windir\Temp\*"
Remove-PathSafe "$env:TEMP\*"

# --- 3) Delivery Optimization Cache ---
Write-Log "[3] Delivery Optimization Cache"
Remove-PathSafe "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache\*"

# --- 4) Windows-Logs & Setup-Logs ---
Write-Log "[4] Windows-Logs"
Remove-PathSafe "$env:windir\Logs\CBS\*"
Remove-PathSafe "$env:windir\Logs\DISM\*"
Remove-PathSafe "$env:windir\Panther\*"
Remove-PathSafe "$env:windir\inf\*.log"

# --- 5) Shader-, Thumbnail- und Icon-Cache ---
Write-Log "[5] Shader-, Thumbnail- und Icon-Cache"
Remove-PathSafe "$env:localappdata\Microsoft\Windows\ShaderCache\*"
Remove-PathSafe "$env:localappdata\Microsoft\Windows\Explorer\thumbcache_*.db"
Remove-PathSafe "$env:localappdata\IconCache.db"

# --- 6) Cleanmgr (silent) ---
Write-Log "[6] Cleanmgr SAGERUN (silent)"
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
        if (-not $DryRun) { New-ItemProperty -Path $path -Name "StateFlags$SageId" -Value 2 -PropertyType DWord -Force | Out-Null }
    }
}
if (-not $DryRun) { & cleanmgr.exe /sagerun:$SageId }

# --- 7) DISM StartComponentCleanup ---
Write-Log "[7] DISM StartComponentCleanup"
if (-not $DryRun) { & dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet }

# --- 8) Optional: Prefetch ---
if ($IncludePrefetch) {
    Write-Log "[8] Prefetch leeren"
    if (-not $DryRun) {
        try { Stop-Service SysMain -Force } catch {}
        Remove-PathSafe "$env:windir\Prefetch\*"
        try { Start-Service SysMain } catch {}
    }
}

# --- 9) Optional: Windows Update Reset ---
if ($ResetWU) {
    Write-Log "[9] Windows Update-Cache zurücksetzen"
    if (-not $DryRun) {
        net stop wuauserv
        net stop bits
        net stop cryptsvc
        Rename-Item "$env:windir\SoftwareDistribution" "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue
        Rename-Item "$env:windir\System32\catroot2" "catroot2.old" -Force -ErrorAction SilentlyContinue
        net start wuauserv
        net start bits
        net start cryptsvc
    }
}

# --- 10) Optional: Browser-Caches ---
if ($BrowserCacheHard) {
    Write-Log "[10] Browser-Caches leeren"
    $paths = @(
        "$env:localappdata\Microsoft\Edge\User Data\Default\Cache\*",
        "$env:localappdata\Google\Chrome\User Data\Default\Cache\*",
        "$env:appdata\Mozilla\Firefox\Profiles\*\cache2\*"
    )
    foreach ($p in $paths) { Remove-PathSafe $p }
}

# --- 11) DeepRepair (immer aktiv) ---
$DeepRepairStart = Get-Date
Write-Log "[11] DeepRepair gestartet"
if (-not $DryRun) {
    & dism.exe /Online /Cleanup-Image /ScanHealth
    & dism.exe /Online /Cleanup-Image /RestoreHealth
    & sfc.exe /scannow
}
$DeepRepairDur = (Get-Date) - $DeepRepairStart
Write-Log ("[11] DeepRepair beendet – Dauer: {0:mm\:ss}" -f $DeepRepairDur)

# --- 12) DNS-Cache ---
Write-Log "[12] DNS-Cache leeren"
if (-not $DryRun) { ipconfig /flushdns | Out-Null }

# --- Abschluss ---
$FreeAfter = Get-FreeBytes 'C'
$freed = [math]::Max(0, ($FreeAfter - $FreeBefore))
$freedMB = [math]::Round($freed/1MB,2)
$dur = (Get-Date) - $StartTime
Write-Log ("== Fertig | Gesamtdauer: {0:mm\:ss} | Vorher: {1:N0} MB frei | Nachher: {2:N0} MB frei | Gewinn: {3:N2} MB ==" -f $dur, ($FreeBefore/1MB), ($FreeAfter/1MB), $freedMB)

# Log-Hygiene
Get-ChildItem $LogRoot -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepLogsDays) } | Remove-Item -Force -ErrorAction SilentlyContinue
Stop-Transcript | Out-Null
