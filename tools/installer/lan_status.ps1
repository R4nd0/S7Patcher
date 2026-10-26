param([Parameter(Mandatory=$true)][string]$Bundle)
$ErrorActionPreference = 'Stop'
# Read-only. No account caches, packet contents, registry or firewall changes.
$bundleRoot = (Resolve-Path -LiteralPath $Bundle).Path
$gamePath = Join-Path $bundleRoot 'Base\Bin\Settlers7R.exe'
if (!(Test-Path -LiteralPath $gamePath -PathType Leaf)) { throw 'Kein installierter Testordner.' }
Write-Output 'S7 LAN-Status (nur lesend)'
try {
    $games = @(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq $gamePath})
    Write-Output ('Laufende Testspiele: ' + $games.Count)
    if ($games.Count -eq 1) {
        $ports = @(Get-NetUDPEndpoint -OwningProcess $games[0].ProcessId | Select-Object -ExpandProperty LocalPort)
        foreach ($port in @(3074,6200,9103)) { Write-Output ('UDP ' + $port + ' gebunden: ' + ($ports -contains $port)) }
    }
} catch { Write-Output 'Prozess-/Portstatus nicht lesbar.' }
try {
    Get-NetConnectionProfile | ForEach-Object {Write-Output ('Netzwerkprofil: ' + $_.NetworkCategory)}
    $rules = @(Get-NetFirewallApplicationFilter -Program $gamePath | Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'})
    Write-Output ('Explizite eingehende Spielregeln: ' + $rules.Count)
    foreach ($rule in $rules) {
        $portFilter = $rule | Get-NetFirewallPortFilter
        Write-Output ('Spielregel: ' + $rule.Action + '; ' + $portFilter.Protocol + '; Profil ' + $rule.Profile)
    }
} catch { Write-Output 'Firewallstatus nicht lesbar (keine Aenderung vorgenommen).' }
$status = Join-Path $bundleRoot 'LocalData\native-status.txt'
if (!(Test-Path -LiteralPath $status -PathType Leaf)) { throw 'native-status.txt fehlt.' }
$lines = @(Get-Content -LiteralPath $status -Tail 1000)
$start = -1
for ($index = 0; $index -lt $lines.Count; ++$index) {
    if ($lines[$index] -eq 'local-platform-start-requested') { $start = $index }
}
if ($start -lt 0) { throw 'Keine aktuelle Startmarkierung im begrenzten Diagnoseausschnitt.' }
Write-Output 'Diagnose des letzten Starts:'
for ($index = $start; $index -lt $lines.Count; ++$index) {
    if ($lines[$index] -cmatch '^[a-z][a-z0-9-]{0,119}$') { Write-Output $lines[$index] }
}
