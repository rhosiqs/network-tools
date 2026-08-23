#requires -Version 5.1
<#
.SYNOPSIS
    Self-test for the TCP/53 watch: verifies the DNS codec, the block
    classifier, and the logging pipeline without needing a real block.

.DESCRIPTION
    A monitor for a rare fault is untestable in the field -- by the time
    the block happens you need to already trust the tool. So the decision
    table is exercised here against synthetic probe results, one case per
    block type, and the records are written through the real logger so the
    on-disk shape is the same one a genuine incident would produce.

    Exits non-zero if any case fails, so it can gate a scheduled rollout.

.EXAMPLE
    .\Test-Tcp53SelfTest.ps1
#>

[CmdletBinding()]
param([string]$LogDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
. (Join-Path $ScriptRoot 'lib\Dns.Codec.ps1')
. (Join-Path $ScriptRoot 'lib\Net.Probe.ps1')
. (Join-Path $ScriptRoot 'lib\Host.Context.ps1')
. (Join-Path $ScriptRoot 'lib\Block.Classify.ps1')
. (Join-Path $ScriptRoot 'lib\Log.Writer.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-Equal {
    param([string]$Case, $Expected, $Actual)
    if ([string]$Expected -eq [string]$Actual) {
        $script:Passed++
        Write-Host ("  PASS  {0,-42} -> {1}" -f $Case, $Actual) -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host ("  FAIL  {0,-42} expected [{1}] got [{2}]" -f $Case, $Expected, $Actual) -ForegroundColor Red
    }
}

function New-FakeProbe {
    param(
        [string]$Protocol, [bool]$Success, [string]$Phase, [string]$Outcome,
        [string]$SocketError, [int]$ElapsedMs = 100, $Response = $null
    )
    return [pscustomobject]@{
        Protocol = $Protocol; Server = '203.0.113.53'; Port = $(if ($Protocol -eq 'TCP') { 53 } else { 53 })
        Success = $Success; Phase = $Phase; Outcome = $Outcome
        SocketError = $SocketError; SocketCode = $null
        ConnectMs = $null; ElapsedMs = $ElapsedMs; BytesReceived = 0
        Response = $Response; Detail = 'synthetic'
    }
}

$goodUdp = New-FakeProbe -Protocol 'UDP' -Success $true -Phase 'Receive' -Outcome 'Answered' -SocketError $null -Response ([pscustomobject]@{
    Valid = $true; RcodeName = 'NOERROR'; Truncated = $false; AnswerCount = 1; TransactionId = 1
})
$deadUdp = New-FakeProbe -Protocol 'UDP' -Success $false -Phase 'Receive' -Outcome 'ReadTimeout' -SocketError 'TimedOut'

Write-Host ''
Write-Host '=== 1. DNS codec round-trip ===' -ForegroundColor Cyan

$q = New-DnsQueryPacket -Name 'www.example.com' -Type 'A' -TransactionId 0x1234
Assert-Equal 'query transaction id preserved' 4660 $q.TransactionId
# Parenthesised: in argument mode a bare 0x12 is passed as the string "0x12".
Assert-Equal 'query header byte 0'            (0x12) $q.Bytes[0]
Assert-Equal 'query header byte 1'            (0x34) $q.Bytes[1]
# The byte -shl 8 trap: if the high byte were dropped this would read 0x34.
Assert-Equal 'parsed id survives 16-bit assembly' 4660 (Read-DnsResponse -Buffer $q.Bytes).TransactionId

# A hand-built response: same id, QR=1, one A record answer of 93.184.216.34.
$resp = New-Object 'System.Collections.Generic.List[byte]'
$resp.AddRange([byte[]]@(0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00))
# [byte[]] cast: a PowerShell array slice comes back as Object[], which
# List[byte].AddRange refuses.
$resp.AddRange([byte[]]$q.Bytes[12..($q.Bytes.Length - 1)])   # echo the question
$resp.AddRange([byte[]]@(0xC0,0x0C))                          # name pointer to offset 12
$resp.AddRange([byte[]]@(0x00,0x01, 0x00,0x01))               # TYPE A, CLASS IN
$resp.AddRange([byte[]]@(0x00,0x00,0x01,0x2C))                # TTL 300
$resp.AddRange([byte[]]@(0x00,0x04))                          # RDLENGTH 4
$resp.AddRange([byte[]]@(93,184,216,34))
$parsed = Read-DnsResponse -Buffer $resp.ToArray()

Assert-Equal 'response parses as valid'   $true    $parsed.Valid
Assert-Equal 'response rcode'             'NOERROR' $parsed.RcodeName
Assert-Equal 'response answer count'      1        $parsed.AnswerCount
Assert-Equal 'compressed name decoded'    'www.example.com' $parsed.Answers[0].Name
Assert-Equal 'A record rdata decoded'     '93.184.216.34'   $parsed.Answers[0].Data
Assert-Equal 'TTL survives 32-bit assembly' 300    $parsed.Answers[0].Ttl

Write-Host ''
Write-Host '=== 2. MAC normalisation ===' -ForegroundColor Cyan
# Guards the NetAdapter.Format.Helper collision: this must stay correct
# after Get-NetAdapter has auto-loaded that module.
$null = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1
Assert-Equal 'dashed input round-trips'  '40-B5-C1-A2-68-53' (ConvertTo-NormalizedMac '40-B5-C1-A2-68-53')
Assert-Equal 'bare hex is formatted'     'AA-BB-CC-DD-EE-FF' (ConvertTo-NormalizedMac 'aabbccddeeff')
Assert-Equal 'colon form is normalised'  '01-23-45-67-89-AB' (ConvertTo-NormalizedMac '01:23:45:67:89:ab')

Write-Host ''
Write-Host '=== 3. Block classification decision table ===' -ForegroundColor Cyan

$cases = @(
    @{ Case = 'healthy TCP/53';              Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $true  'Receive' 'Answered'              $null              20); Expect = 'None' }
    @{ Case = 'RST on connect';              Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Connect' 'Refused'               'ConnectionRefused' 3); Expect = 'TcpRejected' }
    @{ Case = 'SYN dropped';                 Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Connect' 'ConnectTimeout'        'TimedOut'       3000); Expect = 'TcpSilentDrop' }
    @{ Case = 'ICMP unreachable';            Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Connect' 'HostUnreachable'       'HostUnreachable'  40); Expect = 'TcpUnreachable' }
    @{ Case = 'handshake then silence';      Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Receive' 'ReadTimeout'           'TimedOut'       4000); Expect = 'TcpHandshakeThenNoData' }
    @{ Case = 'RST after query (DPI)';       Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Receive' 'Reset'                 'ConnectionReset'  60); Expect = 'TcpResetAfterQuery' }
    @{ Case = 'clean close, no answer';      Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Receive' 'ClosedWithoutAnswer'   $null              55); Expect = 'TcpClosedWithoutAnswer' }
    @{ Case = 'reply id mismatch';           Udp = $goodUdp; Tcp = (New-FakeProbe 'TCP' $false 'Receive' 'TransactionIdMismatch' $null              30); Expect = 'TcpAnswerSuspect' }
    @{ Case = 'UDP filtered, TCP fine';      Udp = $deadUdp; Tcp = (New-FakeProbe 'TCP' $true  'Receive' 'Answered'              $null              25); Expect = 'UdpBlockedTcpOk' }
    @{ Case = 'both transports dead';        Udp = $deadUdp; Tcp = (New-FakeProbe 'TCP' $false 'Connect' 'ConnectTimeout'        'TimedOut'       3000); Expect = 'DnsServerUnreachable' }
)

foreach ($c in $cases) {
    $result = Get-BlockClassification -UdpResult $c.Udp -TcpResult $c.Tcp
    Assert-Equal $c.Case $c.Expect $result.BlockType
}

Write-Host ''
Write-Host '=== 4. Confidence from the control port ===' -ForegroundColor Cyan

$blockedTcp = New-FakeProbe 'TCP' $false 'Connect' 'ConnectTimeout' 'TimedOut' 3000
$ctlOpen    = [pscustomobject]@{ Server = '203.0.113.53'; Port = 443; Connected = $true;  Outcome = 'Connected';      ElapsedMs = 12 }
$ctlShut    = [pscustomobject]@{ Server = '203.0.113.53'; Port = 443; Connected = $false; Outcome = 'ConnectTimeout'; ElapsedMs = 3000 }

$withOpen = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -ControlPortResult $ctlOpen
Assert-Equal 'control port open => port-specific' $true   $withOpen.PortSpecific
Assert-Equal 'control port open => high confidence' 'High' $withOpen.Confidence

$withShut = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -ControlPortResult $ctlShut
Assert-Equal 'control port shut => not port-specific' $false $withShut.PortSpecific
Assert-Equal 'control port shut => low confidence'    'Low'  $withShut.Confidence

Write-Host ''
Write-Host '=== 5. Scope attribution ===' -ForegroundColor Cyan

$localRule = @([pscustomobject]@{ DisplayName = 'Synthetic block 53'; Direction = 'Outbound'; Protocol = 'TCP'; LocalPort = 'Any'; RemotePort = '53' })
$scoped = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -LocalFirewallRules $localRule
Assert-Equal 'local firewall rule pins scope' 'LocalHost' $scoped.Scope

$edge = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -AllTargetsBlocked $true
Assert-Equal 'all servers blocked => edge'    'NetworkEdge'  $edge.Scope

$one = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -AllTargetsBlocked $false
Assert-Equal 'one server blocked => server'   'ServerOrPath' $one.Scope

Write-Host ''
Write-Host '=== 6. Logging pipeline ===' -ForegroundColor Cyan

if (-not $LogDirectory) { $LogDirectory = Join-Path $env:TEMP ("tcp53-selftest-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$log = New-LogContext -Directory $LogDirectory -LogSuccessEveryNCycles 0 -Quiet
$hostCtx = Get-HostNetworkContext -TargetIp '8.8.8.8'
$target  = [pscustomobject]@{ Name = 'SelfTest'; Server = '203.0.113.53'; Note = 'synthetic' }

$cls = Get-BlockClassification -UdpResult $goodUdp -TcpResult $blockedTcp -ControlPortResult $ctlOpen
$evt = Test-ShouldLog -Log $log -TargetKey 'SelfTest' -BlockType $cls.BlockType -Blocked $cls.Blocked
$rec = New-LogRecord -HostContext $hostCtx -Target $target -UdpResult $goodUdp -TcpResult $blockedTcp `
                     -Classification $cls -ControlPortResult $ctlOpen -Event $evt
Write-LogRecord -Log $log -Record $rec

# 'Blocked' rather than 'Baseline': a first sample that is already failing
# is labelled by its state, since "Baseline" is reserved for a clean start.
Assert-Equal 'first sample is logged'        'Blocked'       $evt
Assert-Equal 'jsonl file written'            $true           (Test-Path $log.JsonlPath)
Assert-Equal 'csv file written'              $true           (Test-Path $log.CsvPath)

$readBack = Get-Content $log.JsonlPath -Tail 1 | ConvertFrom-Json
Assert-Equal 'logged block type'   'TcpSilentDrop' $readBack.BlockType
Assert-Equal 'logged target'       'SelfTest'      $readBack.TargetName
Assert-Equal 'timestamp present'   $true           ([bool]$readBack.Timestamp)
Assert-Equal 'adapter MAC present' $true           ($readBack.AdapterMac -match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$')

# A transition must always be recorded even when successes are sampled out.
$okCls = Get-BlockClassification -UdpResult $goodUdp -TcpResult (New-FakeProbe 'TCP' $true 'Receive' 'Answered' $null 20)
$evt2  = Test-ShouldLog -Log $log -TargetKey 'SelfTest' -BlockType $okCls.BlockType -Blocked $okCls.Blocked
Assert-Equal 'recovery is recorded as a transition' 'BlockCleared' $evt2

$csvLines = @(Get-Content $log.CsvPath)
Assert-Equal 'csv has header + 1 row' 2 $csvLines.Count

Write-Host ''
Write-Host '=========================================================' -ForegroundColor Cyan
Write-Host ("  Passed: {0}    Failed: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
Write-Host ("  Test logs: {0}" -f $LogDirectory) -ForegroundColor DarkGray
Write-Host '=========================================================' -ForegroundColor Cyan

if ($script:Failed -gt 0) { exit 1 }
exit 0
