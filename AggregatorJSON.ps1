New-Item -ItemType Directory -Force -Path "/home/sandbox/Desktop/Collector"

### --- Event Log Extractor (ELExtractv2.ps1) --- ###
<# 
Exports Windows logs (Application, Security, Setup, System) to EVTX and Splunk-friendly JSONL.
Run in elevated PowerShell for Security log access.
#>

[CmdletBinding()]
param(
    [string[]]$Channels = @('Application','Security','Setup','System'),
    [int]$Days = 6,
    [string]$OutDir = 'C:\Logs'
)

# Create output folder
if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

$StartTime = (Get-Date).AddDays(-1 * [math]::Abs($Days))
$EndTime   = Get-Date

foreach ($ch in $Channels) {
    Write-Host "`nChannel: $ch"

    # 1) EVTX archive (exact copy of the channel)
    $evtx = Join-Path $OutDir "$ch.evtx"
    try {
        wevtutil epl $ch $evtx
        Write-Host "EVTX exported: $evtx"
    } catch {
        Write-Host ("EVTX export failed for {0}: {1}" -f $ch, $_.Exception.Message)
    }

    # 2) JSONL for Splunk (one JSON object per line)
    $jsonPath = Join-Path $OutDir "$ch.json"
    try {
        # Pull events in the time range
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $ch
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop

        # Build JSON objects with expanded EventData
        $out = New-Object System.Collections.Generic.List[string]
        $i = 0
        $total = $events.Count

        foreach ($ev in $events) {
            $i++
            if ($i % 1000 -eq 0) {
                Write-Progress -Activity "Building JSON ($ch)" -Status "$i / $total" -PercentComplete (($i/$total)*100)
            }

            $xml = [xml]$ev.ToXml()
            $kv = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $name = [string]$d.Name
                if ($name) { $kv[$name] = [string]$d.'#text' }
            }

            $obj = [pscustomobject]@{
                TimeCreatedISO   = $ev.TimeCreated.ToString("o")  # Splunk-friendly timestamp
                EventID          = $ev.Id
                Level            = $ev.Level
                LevelDisplayName = $ev.LevelDisplayName
                ProviderName     = $ev.ProviderName
                Computer         = $ev.MachineName
                Channel          = $ev.LogName
                RecordId         = $ev.RecordId
                Task             = $ev.Task
                Opcode           = $ev.Opcode
                Keywords         = $ev.Keywords
                ProcessId        = $ev.ProcessId
                ThreadId         = $ev.ThreadId
                UserSid          = $ev.UserId
                Message          = $ev.Message
                SourceLog        = $ch
                EventData        = $kv            # nested dict of all EventData keys/values
            }

            # One JSON object per line
            $out.Add( ($obj | ConvertTo-Json -Depth 6 -Compress) )
        }

        # Write JSONL
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($jsonPath, $out, $utf8NoBom)
        Write-Host "JSON exported:  $jsonPath  ($($events.Count) events)"
    } catch {
        Write-Host ("JSON export failed for {0}: {1}" -f $ch, $_.Exception.Message)
    }
}


### --- DNS Log Extractor (DNSLogExtractv2.ps1) --- ###
# Extract-DnsClient-Jsonl.ps1
param(
  [string]$Evtx = 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-DNS-Client%4Operational.evtx',
  [string]$Out  = "$env:USERPROFILE\Desktop\dns_client_operational.jsonl",
  [int[]] $EventIds = @(3008,3009,3010)  # query sent/completed/summary
)

# Lookup maps for better analytics
$DnsType = @{
  1='A'; 2='NS'; 5='CNAME'; 6='SOA'; 12='PTR'; 15='MX'; 16='TXT'; 28='AAAA'; 33='SRV'; 255='ANY'
}
$Rcode = @{
  0='NOERROR'; 1='FORMERR'; 2='SERVFAIL'; 3='NXDOMAIN'; 4='NOTIMP'; 5='REFUSED'
}

# Stream -> parse -> write JSON lines
$sw = [System.IO.StreamWriter]::new($Out, $false, [System.Text.UTF8Encoding]::new($true))
try {
  Get-WinEvent -Path $Evtx -Oldest | Where-Object { $EventIds -contains $_.Id } | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $kv  = @{}
    foreach ($d in $xml.Event.EventData.Data) { $kv[$d.Name] = [string]$d.'#text' }

    # Normalize
    $iso   = $_.TimeCreated.ToString('o')                 # ISO8601
    $epoch = [int][Math]::Floor((Get-Date $_.TimeCreated -UFormat %s)) # _time for Splunk

    $qtNum = [int]($kv['QueryType']   | ForEach-Object { $_ })  # safe cast
    $rcNum = [int]($kv['ResponseCode']| ForEach-Object { $_ })

    $rec = [ordered]@{
      # Splunk-friendly metadata
      _time          = $epoch                    # Splunk will use this if props allow, or via HEC
      host           = $_.MachineName
      source         = $Evtx
      sourcetype     = 'msdns:client'            # pick a stable sourcetype

      # Useful headers
      TimeCreated    = $iso
      EventID        = $_.Id
      Provider       = $_.ProviderName
      Level          = $_.LevelDisplayName
      Opcode         = $_.OpcodeDisplayName
      Task           = $_.TaskDisplayName
      ActivityId     = "$($_.ActivityId)"

      # DNS specifics (CIM-ish)
      query          = $kv['QueryName']          # CIM: query
      query_normalized = ($kv['QueryName'] -as [string]).ToLowerInvariant()
      query_type_num = $qtNum
      query_type     = $(if ($DnsType.ContainsKey($qtNum)) { $DnsType[$qtNum] } else { "$qtNum" })
      response_code_num = $rcNum
      response_code  = $(if ($Rcode.ContainsKey($rcNum)) { $Rcode[$rcNum] } else { "$rcNum" })

      # Derive outcome/action for quick stats
      action         = $(if ($rcNum -eq 0) { 'allowed' } elseif ($rcNum -eq 3) { 'nxdomain' } else { 'other' })
      result         = $(if ($rcNum -eq 0) { 'success' } else { 'failure' })

      # Networkish hints (present if log includes them)
      dns_server     = $kv['ServerAddress']
      address_family = $kv['AddressFamily']      # 2=AF_INET, 23=AF_INET6 (if present)
      protocol       = $kv['Protocol']           # e.g., UDP/TCP if present
      query_options  = $kv['QueryOptions']

      # Original payloads for completeness
      eventdata      = $kv
      message        = $_.Message
    }

    $sw.WriteLine(($rec | ConvertTo-Json -Depth 5 -Compress))
  }
}
finally { $sw.Close() }

Write-Host "JSONL written -> $Out"


### --- Firewall Log Extractor (FExtract.ps1) --- ###
# --- auto-elevate ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
   [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}

# --- SETTINGS ---
$logPathRaw = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
$logPath    = [Environment]::ExpandEnvironmentVariables($logPathRaw)
$outFile    = Join-Path $env:USERPROFILE "Desktop\firewall_with_process.json"
$RelocateIfDenied = $true

function Read-FwLog {
  param([string]$Path)
  try {
    return Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
  } catch {
    Write-Warning "Direct read failed ($($_.Exception.Message)). Trying backup-mode copy…"
    $temp = Join-Path $env:TEMP "pfirewall_copy.log"
    $srcDir = Split-Path $Path -Parent
    $dstDir = Split-Path $temp -Parent
    $file   = Split-Path $Path -Leaf
    $null = New-Item -ItemType Directory -Path $dstDir -Force -ErrorAction SilentlyContinue
    $roc = Start-Process -FilePath robocopy.exe `
      -ArgumentList "`"$srcDir`" `"$dstDir`" `"$file`" /B /R:0 /W:0 /NFL /NDL /NJH /NJS /NC /NS" `
      -PassThru -NoNewWindow -Wait
    if ($roc.ExitCode -ge 8) { throw "Robocopy failed with code $($roc.ExitCode)" }
    return Get-Content -LiteralPath $temp -Encoding UTF8 -ErrorAction Stop
  }
}

if (-not (Test-Path -LiteralPath $logPath)) {
  Write-Error "Firewall log not found: $logPath"
  exit 1
}

$all = $null
try { $all = Read-FwLog -Path $logPath }
catch {
  if ($RelocateIfDenied) {
    Write-Warning "Relocating firewall log to a readable path…"
    $newDir = "C:\FirewallLogs"
    $newLog = Join-Path $newDir "pfirewall.log"
    New-Item -ItemType Directory -Path $newDir -Force | Out-Null
    icacls $newDir /grant "*S-1-5-32-544:(OI)(CI)(F)" /T | Out-Null
    icacls $newDir /grant "Users:(OI)(CI)(RX)" /T | Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName $newLog
    Write-Host "Log path changed. Generate some traffic and re-run after a few seconds."
    exit
  } else {
    Write-Error "Unable to read firewall log: $($_.Exception.Message)"
    exit 2
  }
}

$headerLine = $all | Where-Object { $_ -match '^\s*#Fields:' } | Select-Object -First 1
if ($headerLine) {
  $cols = ($headerLine -replace '^\s*#Fields:\s*','') -split '\s+' | Where-Object { $_ }
} else {
  $cols = @('date','time','action','protocol','src-ip','dst-ip','src-port','dst-port',
            'size','tcpflags','tcpsyn','tcpack','tcpwin','icmptype','icmpcode','info','path','pid')
  Write-Warning "No '#Fields:' header found. Using default FW 1.5 fields."
}

$idx = @{}; for ($i=0; $i -lt $cols.Count; $i++) { $idx[$cols[$i]] = $i }
function NF([string]$v) { if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '-') { $null } else { $v } }

$dataLines = $all | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
if (Test-Path $outFile) { Remove-Item $outFile -Force }

foreach ($line in $dataLines) {
  $parts = ($line.TrimStart()) -split '\s+'
  if ($parts.Count -lt $cols.Count) { $parts = $parts + (,@('') * ($cols.Count - $parts.Count)) }

  $get = { param($n) if ($idx.ContainsKey($n)) { NF $parts[$idx[$n]] } else { $null } }

  $date     = & $get 'date'
  $time     = & $get 'time'
  $action   = & $get 'action'
  $protocol = & $get 'protocol'
  $src_ip   = & $get 'src-ip'
  $dst_ip   = & $get 'dst-ip'
  $src_port = & $get 'src-port'
  $dst_port = & $get 'dst-port'
  $size     = & $get 'size'
  $tcpflags = & $get 'tcpflags'
  $tcpsyn   = & $get 'tcpsyn'
  $tcpack   = & $get 'tcpack'
  $tcpwin   = & $get 'tcpwin'
  $icmptype = & $get 'icmptype'
  $icmpcode = & $get 'icmpcode'
  $info     = & $get 'info'
  $image    = & $get 'path'
  $pidField = & $get 'pid'   # raw field text

  # Use a different variable name to avoid colliding with automatic $PID
  $procId = if ($pidField -and ($pidField -as [int])) { [int]$pidField } else { $null }
  $procName = "N/A"
  if ($procId) { try { $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $procName = "N/A" } }

  $ts = $null
  if ($date -and $time) { try { $ts = ([datetime]::Parse("$date $time")).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz") } catch { } }

  $obj = [ordered]@{
    ts            = $ts
    date          = $date
    time          = $time
    action        = $action
    protocol      = $protocol
    src_ip        = $src_ip
    dest_ip       = $dst_ip
    src_port      = $src_port
    dest_port     = $dst_port
    bytes         = $size
    tcp_flags     = $tcpflags
    tcp_syn       = $tcpsyn
    tcp_ack       = $tcpack
    tcp_win       = $tcpwin
    icmp_type     = $icmptype
    icmp_code     = $icmpcode
    direction     = $info
    image_path    = $image
    pid           = $procId       # JSON field remains "pid"
    process_name  = $procName
    host          = $env:COMPUTERNAME
    source        = "WindowsFirewall"
    sourcetype    = "windows:firewall:w3c"
    log_path      = $logPath
  }

  ($obj | ConvertTo-Json -Compress) | Out-File -FilePath $outFile -Encoding UTF8 -Append
}

Write-Host "Wrote NDJSON to: $outFile"

