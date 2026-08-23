#requires -Version 5.1
<#
    Dns.Codec.ps1
    ------------------------------------------------------------------
    Minimal DNS wire-format encoder/decoder written in pure PowerShell.

    Why hand-roll this instead of using Resolve-DnsName?
      Resolve-DnsName hides the transport. It will silently retry over a
      different protocol, use the local resolver cache, and it collapses
      "no answer" and "refused" into the same terminating error. To prove
      that *TCP* port 53 specifically is being blocked we must own the
      socket and read the raw bytes ourselves.

    Only the subset of RFC 1035 needed for diagnosis is implemented:
    a single question, header flag extraction, and answer walking with
    label-compression support.
#>

Set-StrictMode -Version Latest

$script:DnsTypeByName = @{
    'A'      = 1
    'NS'     = 2
    'CNAME'  = 5
    'SOA'    = 6
    'PTR'    = 12
    'MX'     = 15
    'TXT'    = 16
    'AAAA'   = 28
    'DNSKEY' = 48
    'ANY'    = 255
}

$script:DnsTypeByCode = @{}
foreach ($k in $script:DnsTypeByName.Keys) { $script:DnsTypeByCode[$script:DnsTypeByName[$k]] = $k }

$script:DnsRcodeByCode = @{
    0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'
    4 = 'NOTIMP';  5 = 'REFUSED'; 6 = 'YXDOMAIN'; 7 = 'YXRRSET'
    8 = 'NXRRSET'; 9 = 'NOTAUTH';  10 = 'NOTZONE'
}

function ConvertTo-DnsTypeCode {
    param([Parameter(Mandatory)][string]$Type)
    if ($script:DnsTypeByName.ContainsKey($Type.ToUpperInvariant())) {
        return [int]$script:DnsTypeByName[$Type.ToUpperInvariant()]
    }
    throw "Unsupported DNS record type '$Type'."
}

function New-DnsQueryPacket {
<#
    .SYNOPSIS
        Builds a raw DNS query message (without the TCP length prefix).
    .PARAMETER EnableEdns
        Appends an OPT pseudo-record advertising a small UDP payload size.
        Advertising 512 bytes makes servers set the TC (truncated) bit on
        large answers, which is exactly the condition that forces a client
        to retry over TCP -- the failure mode this project hunts for.
#>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Type = 'A',
        [int]$TransactionId = -1,
        [switch]$NoRecursion,
        [switch]$EnableEdns,
        [int]$UdpPayloadSize = 512
    )

    if ($TransactionId -lt 0) { $TransactionId = Get-Random -Minimum 1 -Maximum 65535 }

    $bytes = New-Object 'System.Collections.Generic.List[byte]'

    # --- Header ---
    $bytes.Add([byte](($TransactionId -shr 8) -band 0xFF))
    $bytes.Add([byte]($TransactionId -band 0xFF))

    $flagsHi = 0x00
    if (-not $NoRecursion) { $flagsHi = $flagsHi -bor 0x01 }   # RD
    $bytes.Add([byte]$flagsHi)
    $bytes.Add([byte]0x00)

    $bytes.AddRange([byte[]]@(0x00, 0x01))                     # QDCOUNT = 1
    $bytes.AddRange([byte[]]@(0x00, 0x00))                     # ANCOUNT
    $bytes.AddRange([byte[]]@(0x00, 0x00))                     # NSCOUNT
    if ($EnableEdns) {
        $bytes.AddRange([byte[]]@(0x00, 0x01))                 # ARCOUNT = 1 (OPT)
    } else {
        $bytes.AddRange([byte[]]@(0x00, 0x00))
    }

    # --- Question ---
    foreach ($label in ($Name.TrimEnd('.') -split '\.')) {
        if ($label.Length -eq 0) { continue }
        if ($label.Length -gt 63) { throw "DNS label '$label' exceeds 63 bytes." }
        $bytes.Add([byte]$label.Length)
        $bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
    }
    $bytes.Add([byte]0x00)

    $qtype = ConvertTo-DnsTypeCode -Type $Type
    $bytes.Add([byte](($qtype -shr 8) -band 0xFF))
    $bytes.Add([byte]($qtype -band 0xFF))
    $bytes.AddRange([byte[]]@(0x00, 0x01))                     # QCLASS = IN

    # --- Additional: OPT pseudo-RR (RFC 6891) ---
    if ($EnableEdns) {
        $bytes.Add([byte]0x00)                                 # root name
        $bytes.AddRange([byte[]]@(0x00, 0x29))                 # TYPE = OPT (41)
        $bytes.Add([byte](($UdpPayloadSize -shr 8) -band 0xFF))# CLASS = UDP payload size
        $bytes.Add([byte]($UdpPayloadSize -band 0xFF))
        $bytes.AddRange([byte[]]@(0x00, 0x00, 0x00, 0x00))     # extended RCODE + version + flags
        $bytes.AddRange([byte[]]@(0x00, 0x00))                 # RDLENGTH = 0
    }

    return [pscustomobject]@{
        TransactionId = $TransactionId
        QueryName     = $Name
        QueryType     = $Type.ToUpperInvariant()
        Bytes         = $bytes.ToArray()
    }
}

function Read-DnsName {
<#
    .SYNOPSIS
        Decodes a (possibly compressed) domain name starting at $Offset.
    .OUTPUTS
        Name plus how many bytes were consumed *in the original stream*,
        which is not the same as how far we walked once a pointer is taken.
#>
    param(
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][int]$Offset
    )

    $labels   = New-Object 'System.Collections.Generic.List[string]'
    $pos      = $Offset
    $jumped   = $false
    $consumed = 0
    $guard    = 0

    while ($true) {
        if ($guard++ -gt 128) { throw 'DNS name decoding aborted: compression pointer loop.' }
        if ($pos -ge $Buffer.Length) { throw 'DNS name decoding aborted: truncated message.' }

        $len = $Buffer[$pos]

        if ($len -eq 0) {
            $pos++
            if (-not $jumped) { $consumed = $pos - $Offset }
            break
        }

        if (($len -band 0xC0) -eq 0xC0) {
            if ($pos + 1 -ge $Buffer.Length) { throw 'DNS name decoding aborted: truncated pointer.' }
            # [int] casts are load-bearing: PowerShell keeps the result of a
            # shift in the left operand's type, so [byte] -shl 8 is always 0.
            $target = (((([int]$len) -band 0x3F) -shl 8) -bor [int]$Buffer[$pos + 1])
            if (-not $jumped) { $consumed = ($pos + 2) - $Offset; $jumped = $true }
            $pos = $target
            continue
        }

        $pos++
        if ($pos + $len -gt $Buffer.Length) { throw 'DNS name decoding aborted: label runs past end.' }
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Buffer, $pos, $len))
        $pos += $len
    }

    return [pscustomobject]@{
        Name          = ($labels -join '.')
        BytesConsumed = $consumed
    }
}

function Read-DnsResponse {
<#
    .SYNOPSIS
        Parses a raw DNS response message into a diagnosable object.
    .DESCRIPTION
        Never throws on a malformed body: the header is parsed first and any
        later failure is recorded in ParseError. A mangled answer section is
        itself evidence (middlebox tampering), so it must survive as data.
#>
    param([Parameter(Mandatory)][byte[]]$Buffer)

    if ($Buffer.Length -lt 12) {
        return [pscustomobject]@{
            Valid = $false; ParseError = "Response shorter than a DNS header ($($Buffer.Length) bytes)."
            TransactionId = $null; Truncated = $null; Rcode = $null; RcodeName = 'UNPARSEABLE'
            AnswerCount = 0; Answers = @(); Authoritative = $null; RecursionAvailable = $null
            MessageLength = $Buffer.Length
        }
    }

    # Every byte is widened to [int] before shifting. PowerShell evaluates a
    # shift in the type of its left operand, so [byte]0x12 -shl 8 yields 0
    # rather than 0x1200 and the high half of every 16-bit field vanishes.
    $id     = (([int]$Buffer[0]) -shl 8) -bor [int]$Buffer[1]
    $flagHi = [int]$Buffer[2]
    $flagLo = [int]$Buffer[3]
    $qd     = (([int]$Buffer[4]) -shl 8) -bor [int]$Buffer[5]
    $an     = (([int]$Buffer[6]) -shl 8) -bor [int]$Buffer[7]
    $rcode  = $flagLo -band 0x0F

    $result = [ordered]@{
        Valid              = $true
        ParseError         = $null
        TransactionId      = $id
        IsResponse         = [bool](($flagHi -shr 7) -band 1)
        Opcode             = (($flagHi -shr 3) -band 0x0F)
        Authoritative      = [bool](($flagHi -shr 2) -band 1)
        Truncated          = [bool](($flagHi -shr 1) -band 1)
        RecursionDesired   = [bool]($flagHi -band 1)
        RecursionAvailable = [bool](($flagLo -shr 7) -band 1)
        Rcode              = $rcode
        RcodeName          = $(if ($script:DnsRcodeByCode.ContainsKey($rcode)) { $script:DnsRcodeByCode[$rcode] } else { "RCODE$rcode" })
        QuestionCount      = $qd
        AnswerCount        = $an
        Answers            = @()
        MessageLength      = $Buffer.Length
    }

    try {
        $pos = 12
        for ($i = 0; $i -lt $qd; $i++) {
            $q = Read-DnsName -Buffer $Buffer -Offset $pos
            $pos += $q.BytesConsumed + 4
        }

        $answers = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $an; $i++) {
            if ($pos + 10 -gt $Buffer.Length) { break }

            $owner = Read-DnsName -Buffer $Buffer -Offset $pos
            $pos += $owner.BytesConsumed

            $rrType  = (([int]$Buffer[$pos])     -shl 8)  -bor [int]$Buffer[$pos + 1]
            $ttl     = (([int]$Buffer[$pos + 4]) -shl 24) -bor (([int]$Buffer[$pos + 5]) -shl 16) -bor (([int]$Buffer[$pos + 6]) -shl 8) -bor [int]$Buffer[$pos + 7]
            $rdLen   = (([int]$Buffer[$pos + 8]) -shl 8)  -bor [int]$Buffer[$pos + 9]
            $pos    += 10

            if ($pos + $rdLen -gt $Buffer.Length) { break }

            $data = switch ($rrType) {
                1  { ($Buffer[$pos..($pos + 3)] -join '.') }
                28 {
                    $groups = for ($g = 0; $g -lt 16; $g += 2) {
                        '{0:x}' -f ((([int]$Buffer[$pos + $g]) -shl 8) -bor [int]$Buffer[$pos + $g + 1])
                    }
                    ($groups -join ':')
                }
                5  { (Read-DnsName -Buffer $Buffer -Offset $pos).Name }
                2  { (Read-DnsName -Buffer $Buffer -Offset $pos).Name }
                16 {
                    $txt = ''
                    $p = $pos
                    while ($p -lt $pos + $rdLen) {
                        $sl = $Buffer[$p]; $p++
                        $txt += [System.Text.Encoding]::ASCII.GetString($Buffer, $p, $sl)
                        $p += $sl
                    }
                    $txt
                }
                default { '<' + $rdLen + ' bytes>' }
            }

            $answers.Add([pscustomobject]@{
                Name     = $owner.Name
                Type     = $(if ($script:DnsTypeByCode.ContainsKey($rrType)) { $script:DnsTypeByCode[$rrType] } else { "TYPE$rrType" })
                TypeCode = $rrType
                Ttl      = $ttl
                Data     = $data
            })

            $pos += $rdLen
        }
        $result.Answers = $answers.ToArray()
    }
    catch {
        $result.ParseError = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Get-DnsAnswerSummary {
    param($Response)
    if ($null -eq $Response -or -not $Response.Valid) { return '' }
    if ($Response.AnswerCount -eq 0) { return "($($Response.RcodeName), 0 answers)" }
    $shown = @($Response.Answers | Select-Object -First 3 | ForEach-Object { "$($_.Type)=$($_.Data)" })
    return ($shown -join ', ')
}
