<#
.SYNOPSIS
    Cyber Security Report — Settembre 2026 | Exposure Check (read-only)

.DESCRIPTION
    Controllo locale e non invasivo di configurazioni Windows rilevanti rispetto
    alle tecniche documentate per il gruppo ransomware The Gentlemen
    (fonti: Trend Micro, Group-IB).

    - NON modifica alcuna configurazione
    - NON scansiona host o IP terzi
    - NON invia dati all'esterno (export CSV solo locale e opzionale)
    - NON contiene exploit

    Eseguire in PowerShell (5.1 o 7+) come amministratore per risultati completi.

    Un esito "VERIFY" non significa che il sistema sia vulnerabile:
    il sistema presenta configurazioni che meritano verifica rispetto alle
    tecniche osservate nel gruppo The Gentlemen.

.EXAMPLE
    .\Exposure-Check-Settembre2026.ps1
    .\Exposure-Check-Settembre2026.ps1 -CsvPath .\exposure-check.csv
#>
[CmdletBinding()]
param(
    [int]$PatchAgeDays   = 45,
    [int]$MaxLocalAdmins = 2,
    [string]$CsvPath
)

$RunOn    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Hostname = $env:COMPUTERNAME
$Results  = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Area, [string]$Check, [string]$Value,
        [ValidateSet('OK','VERIFY','INFO','UNKNOWN','INVESTIGATE')][string]$Status,
        [int]$Points, [string]$Ttp
    )
    $Results.Add([pscustomobject]@{
        RunOn      = $RunOn
        Hostname   = $Hostname
        Area       = $Area
        Check      = $Check
        Value      = $Value
        Status     = $Status
        Points     = $Points
        RelatedTTP = $Ttp
    })
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# ---------------------------------------------------------------------------
# 1. RDP e NLA  (T1021.001)
# ---------------------------------------------------------------------------
$rdpDeny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$rdpOn   = ($rdpDeny -eq 0)
Add-Check -Area 'Remote access' -Check 'RDP abilitato' `
    -Value $(if ($rdpOn) { 'Si' } else { 'No' }) `
    -Status $(if ($rdpOn) { 'VERIFY' } else { 'OK' }) `
    -Points $(if ($rdpOn) { 10 } else { 0 }) -Ttp 'T1021.001'

if ($rdpOn) {
    $nla   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $nlaOn = ($nla -eq 1)
    Add-Check -Area 'Remote access' -Check 'RDP con NLA' `
        -Value $(if ($nlaOn) { 'Si' } else { 'No' }) `
        -Status $(if ($nlaOn) { 'OK' } else { 'VERIFY' }) `
        -Points $(if ($nlaOn) { 0 } else { 15 }) -Ttp 'T1021.001'
}

# Membri del gruppo Remote Desktop Users (informativo)
try {
    $rduGroup   = Get-LocalGroup -SID 'S-1-5-32-555' -ErrorAction Stop
    $rduMembers = @(Get-LocalGroupMember -Group $rduGroup -ErrorAction Stop)
    Add-Check -Area 'Remote access' -Check 'Membri Remote Desktop Users' `
        -Value ("{0}: {1}" -f $rduMembers.Count, (($rduMembers.Name) -join ', ')) `
        -Status 'INFO' -Points 0 -Ttp 'T1021.001'
} catch {
    Add-Check -Area 'Remote access' -Check 'Membri Remote Desktop Users' -Value 'Non determinabile' -Status 'UNKNOWN' -Points 0 -Ttp 'T1021.001'
}

# ---------------------------------------------------------------------------
# 2. SMBv1  (T1021.002)
# ---------------------------------------------------------------------------
$smb1 = $null
try   { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol }
catch {
    $reg = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    if ($null -ne $reg) { $smb1 = ($reg -ne 0) }
}
if ($null -eq $smb1) {
    Add-Check -Area 'SMB' -Check 'SMBv1 server' -Value 'Non determinabile' -Status 'UNKNOWN' -Points 0 -Ttp 'T1021.002'
} else {
    Add-Check -Area 'SMB' -Check 'SMBv1 server' `
        -Value $(if ($smb1) { 'Abilitato' } else { 'Disabilitato' }) `
        -Status $(if ($smb1) { 'VERIFY' } else { 'OK' }) `
        -Points $(if ($smb1) { 20 } else { 0 }) -Ttp 'T1021.002'
}

# ---------------------------------------------------------------------------
# 3. Windows Firewall  (T1562.004)
# ---------------------------------------------------------------------------
try {
    $disabledProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
    $fwOk = ($disabledProfiles.Count -eq 0)
    Add-Check -Area 'Firewall' -Check 'Profili firewall disabilitati' `
        -Value $(if ($fwOk) { 'Nessuno' } else { $disabledProfiles -join ', ' }) `
        -Status $(if ($fwOk) { 'OK' } else { 'VERIFY' }) `
        -Points $(if ($fwOk) { 0 } else { 15 }) -Ttp 'T1562.004'
} catch {
    Add-Check -Area 'Firewall' -Check 'Profili firewall disabilitati' -Value 'Non determinabile' -Status 'UNKNOWN' -Points 0 -Ttp 'T1562.004'
}

# ---------------------------------------------------------------------------
# 4. Antivirus / EDR  (T1562.001)
# ---------------------------------------------------------------------------
$mp = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
$defenderRtp = ($null -ne $mp -and [bool]$mp.RealTimeProtectionEnabled)

$thirdParty = @()
$scAvailable = $false
try {
    $thirdParty = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop |
        Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
        Select-Object -ExpandProperty displayName)
    $scAvailable = $true
} catch { }  # SecurityCenter2 non esiste su Windows Server

if ($defenderRtp -or $thirdParty.Count -gt 0) {
    $val = @()
    if ($defenderRtp)            { $val += 'Defender RTP attivo' }
    if ($thirdParty.Count -gt 0) { $val += ('Altro AV/EDR: ' + ($thirdParty -join ', ')) }
    Add-Check -Area 'Endpoint' -Check 'Protezione AV/EDR attiva' -Value ($val -join ' | ') -Status 'OK' -Points 0 -Ttp 'T1562.001'
} elseif ($null -eq $mp -and -not $scAvailable) {
    Add-Check -Area 'Endpoint' -Check 'Protezione AV/EDR attiva' -Value 'Non determinabile localmente (verificare console EDR)' -Status 'UNKNOWN' -Points 0 -Ttp 'T1562.001'
} else {
    Add-Check -Area 'Endpoint' -Check 'Protezione AV/EDR attiva' -Value 'Nessuna protezione real-time rilevata' -Status 'VERIFY' -Points 20 -Ttp 'T1562.001'
}

if ($null -ne $mp) {
    Add-Check -Area 'Endpoint' -Check 'Defender Tamper Protection' `
        -Value $(if ($mp.IsTamperProtected) { 'Attiva' } else { 'Non attiva / gestita da altro prodotto' }) `
        -Status 'INFO' -Points 0 -Ttp 'T1562.001'
}

# Driver vulnerabili citati nelle analisi (indicatore debole: i file possono essere rinominati)
$driverNames = @('ThrottleBlood.sys', 'viragt64.sys')
$driverDir   = Join-Path $env:SystemRoot 'System32\drivers'
$foundDrivers = @($driverNames | Where-Object { Test-Path (Join-Path $driverDir $_) })
Add-Check -Area 'Endpoint' -Check 'Driver BYOVD noti (per nome file)' `
    -Value $(if ($foundDrivers.Count -gt 0) { $foundDrivers -join ', ' } else { 'Non trovati' }) `
    -Status $(if ($foundDrivers.Count -gt 0) { 'INVESTIGATE' } else { 'OK' }) `
    -Points 0 -Ttp 'T1562.001 / T1014'

# ---------------------------------------------------------------------------
# 5. Patch age (indicativo, basato sugli hotfix registrati)
# ---------------------------------------------------------------------------
try {
    $lastHf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastHf) {
        $age = [int]((Get-Date) - [datetime]$lastHf.InstalledOn).TotalDays
        $old = ($age -gt $PatchAgeDays)
        Add-Check -Area 'Patching' -Check "Ultimo hotfix (soglia $PatchAgeDays gg)" `
            -Value ("{0} — {1} giorni fa" -f $lastHf.HotFixID, $age) `
            -Status $(if ($old) { 'VERIFY' } else { 'OK' }) `
            -Points $(if ($old) { 15 } else { 0 }) -Ttp 'T1068 / T1190'
    } else {
        Add-Check -Area 'Patching' -Check 'Ultimo hotfix' -Value 'Nessuna data disponibile' -Status 'UNKNOWN' -Points 0 -Ttp 'T1068 / T1190'
    }
} catch {
    Add-Check -Area 'Patching' -Check 'Ultimo hotfix' -Value 'Non determinabile' -Status 'UNKNOWN' -Points 0 -Ttp 'T1068 / T1190'
}

# ---------------------------------------------------------------------------
# 6. Amministratori locali  (T1078)
# ---------------------------------------------------------------------------
try {
    $adminGroup   = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $adminMembers = @(Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop)
    $tooMany = ($adminMembers.Count -gt $MaxLocalAdmins)
    Add-Check -Area 'Account' -Check "Membri Administrators (soglia $MaxLocalAdmins)" `
        -Value ("{0}: {1}" -f $adminMembers.Count, (($adminMembers.Name) -join ', ')) `
        -Status $(if ($tooMany) { 'VERIFY' } else { 'OK' }) `
        -Points $(if ($tooMany) { 10 } else { 0 }) -Ttp 'T1078'
} catch {
    Add-Check -Area 'Account' -Check 'Membri Administrators' -Value 'Non determinabile (es. domain controller o SID orfani)' -Status 'UNKNOWN' -Points 0 -Ttp 'T1078'
}

# ---------------------------------------------------------------------------
# 7. WinRM  (T1021.006)
# ---------------------------------------------------------------------------
$winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
$winrmOn = ($winrm -and $winrm.Status -eq 'Running')
Add-Check -Area 'Remote access' -Check 'Servizio WinRM in esecuzione' `
    -Value $(if ($winrmOn) { 'Si' } else { 'No' }) `
    -Status $(if ($winrmOn) { 'VERIFY' } else { 'OK' }) `
    -Points $(if ($winrmOn) { 5 } else { 0 }) -Ttp 'T1021.006'

# ---------------------------------------------------------------------------
# 8. LLMNR  (T1557.001 — usato da The Gentlemen per credential relay)
# ---------------------------------------------------------------------------
$llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$llmnrOff = ($llmnr -eq 0)
Add-Check -Area 'Rete' -Check 'LLMNR disabilitato via policy' `
    -Value $(if ($llmnrOff) { 'Si' } else { 'No / non configurato' }) `
    -Status $(if ($llmnrOff) { 'OK' } else { 'VERIFY' }) `
    -Points $(if ($llmnrOff) { 0 } else { 5 }) -Ttp 'T1557.001'

# ---------------------------------------------------------------------------
# 9. PowerShell Script Block Logging (visibilità)
# ---------------------------------------------------------------------------
$sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Add-Check -Area 'Logging' -Check 'PowerShell Script Block Logging' `
    -Value $(if ($sbl -eq 1) { 'Attivo' } else { 'Non attivo' }) `
    -Status 'INFO' -Points 0 -Ttp 'T1059.001'

# ---------------------------------------------------------------------------
# 10. Strumenti di accesso remoto installati (T1219) — informativo
# ---------------------------------------------------------------------------
$ratPattern = 'AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|MeshAgent'
$rats = @(Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $ratPattern -or $_.DisplayName -match $ratPattern } |
    Select-Object -ExpandProperty DisplayName -Unique)
Add-Check -Area 'Remote access' -Check 'Servizi RMM/remote access' `
    -Value $(if ($rats.Count -gt 0) { $rats -join ', ' } else { 'Nessuno rilevato' }) `
    -Status $(if ($rats.Count -gt 0) { 'VERIFY' } else { 'OK' }) `
    -Points 0 -Ttp 'T1219'

# ---------------------------------------------------------------------------
# 11. Visibilità backup (Veeam — credenziali bersaglio, T1555 / T1490)
# ---------------------------------------------------------------------------
$veeam = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName)
Add-Check -Area 'Backup' -Check 'Servizi Veeam su questo host' `
    -Value $(if ($veeam.Count -gt 0) { "Presenti ($($veeam.Count)) — verificare isolamento credenziali e immutabilità" } else { 'Non presenti' }) `
    -Status 'INFO' -Points 0 -Ttp 'T1555 / T1490'

# ---------------------------------------------------------------------------
# Score deterministico
# ---------------------------------------------------------------------------
$Score = ($Results | Measure-Object -Property Points -Sum).Sum
$Level = if ($Score -ge 50) { 'HIGH' } elseif ($Score -ge 20) { 'MEDIUM' } else { 'LOW' }

Write-Host ''
Write-Host "Cyber Security Report — Settembre 2026 | Exposure Check" -ForegroundColor Cyan
Write-Host "RunOn: $RunOn    Hostname: $Hostname"
Write-Host ''
$Results | Format-Table Area, Check, Value, Status, Points, RelatedTTP -AutoSize -Wrap
Write-Host ("Exposure score: {0}  ->  {1}" -f $Score, $Level) -ForegroundColor Yellow
Write-Host 'Questo score non predice la probabilità di un attacco. Evidenzia configurazioni che richiedono attenzione.'
Write-Host 'Pesi: RDP +10 | RDP senza NLA +15 | SMBv1 +20 | Firewall off +15 | No AV/EDR +20 | Patch vecchie +15 | Troppi admin locali +10 | WinRM +5 | LLMNR attivo +5'
Write-Host 'Soglie: 0-19 LOW | 20-49 MEDIUM | 50+ HIGH'

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Risultati salvati localmente in: $CsvPath"
}
