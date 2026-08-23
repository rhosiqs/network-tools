#requires -Version 5.1
<#
    Host.Context.ps1
    ------------------------------------------------------------------
    Collects the identity of *this machine on this network at this moment*
    so that a logged block can be attributed to a place, not just a time.

    The MAC addresses are the point of this file. An IP address is leased
    and rotates; the NIC MAC identifies the client that was blocked and
    the gateway MAC (plus the Wi-Fi BSSID) identifies the specific piece
    of hardware that was in the path when the block happened. That is what
    lets a network admin find the device holding the rule.

    Everything degrades gracefully: on a locked-down machine any single
    lookup may fail, and a missing field must never abort a monitoring run.
#>

Set-StrictMode -Version Latest

function ConvertTo-NormalizedMac {
    <#
        NOT named Format-MacAddress: Windows ships NetAdapter.Format.Helper,
        which exports a function of that exact name and is auto-loaded the
        first time Get-NetAdapter runs. The import silently replaces a
        same-named function, so a helper called Format-MacAddress works on
        the first call of a session and is hijacked on every call after --
        a bug that only appears once real adapter queries start happening.
    #>
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $hex = ($Raw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return $Raw.ToUpperInvariant() }
    # Regex.Matches rather than -split on a zero-width pattern: PowerShell's
    # -split emits the empty strings between zero-width matches as fields.
    return (([regex]::Matches($hex, '.{2}') | ForEach-Object { $_.Value }) -join '-')
}

function Get-WirelessContext {
    <#
        netsh is the only built-in that exposes the BSSID (the MAC of the
        access point actually serving us). Output is localised, so match on
        the structure -- "key : value" -- rather than on English labels
        where possible, with the common label spellings as the key filter.
    #>
    $ctx = [ordered]@{ IsWireless = $false; Ssid = $null; Bssid = $null; SignalPercent = $null; RadioType = $null; Channel = $null }
    try {
        $raw = & netsh.exe wlan show interfaces 2>$null
        if (-not $raw) { return [pscustomobject]$ctx }

        foreach ($line in $raw) {
            if ($line -notmatch '^\s*(.+?)\s*:\s*(.+?)\s*$') { continue }
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()

            switch -Regex ($key) {
                '^(SSID|網路名稱)$'            { if (-not $ctx.Ssid) { $ctx.Ssid = $val; $ctx.IsWireless = $true } }
                '^(BSSID|基地台)'              { $ctx.Bssid = ConvertTo-NormalizedMac $val; $ctx.IsWireless = $true }
                '^(Signal|訊號)'               { $ctx.SignalPercent = ($val -replace '[^0-9]', '') }
                '^(Radio type|無線電類型)'     { $ctx.RadioType = $val }
                '^(Channel|頻道)$'             { $ctx.Channel = $val }
            }
        }
    }
    catch { }
    return [pscustomobject]$ctx
}

function Get-EgressInterface {
    <#
        Finds the interface the OS would actually use to reach $TargetIp.
        On a multi-homed host (VPN up, docker bridge, second NIC) the
        "default" adapter is often not the one carrying the DNS traffic,
        and logging the wrong MAC would send an investigation down the
        wrong cable.
    #>
    param([string]$TargetIp)

    $ifIndex = $null
    $localIp = $null

    if ($TargetIp) {
        try {
            $route = Find-NetRoute -RemoteIPAddress $TargetIp -ErrorAction Stop | Select-Object -First 1
            if ($route) {
                $ifIndex = $route.InterfaceIndex
                $localIp = $route.IPAddress
            }
        }
        catch { }
    }

    if ($null -eq $ifIndex) {
        try {
            $default = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                       Sort-Object RouteMetric, ifMetric |
                       Select-Object -First 1
            if ($default) { $ifIndex = $default.InterfaceIndex }
        }
        catch { }
    }

    return [pscustomobject]@{ InterfaceIndex = $ifIndex; LocalIp = $localIp }
}

function Get-HostNetworkContext {
<#
    .SYNOPSIS
        Builds the "where and on what" record attached to every log entry.
    .PARAMETER TargetIp
        The DNS server being probed; the egress interface is resolved
        against this address so the MAC recorded is the one in the path.
#>
    param([string]$TargetIp)

    $ctx = [ordered]@{
        HostName          = $env:COMPUTERNAME
        UserName          = $env:USERNAME
        AdapterName       = $null
        AdapterDescription= $null
        AdapterMac        = $null
        MediaType         = $null
        LinkSpeed         = $null
        InterfaceIndex    = $null
        LocalIp           = $null
        PrefixLength      = $null
        GatewayIp         = $null
        GatewayMac        = $null
        GatewayMacState   = $null
        ConfiguredDns     = $null
        DhcpEnabled       = $null
        IsWireless        = $false
        Ssid              = $null
        Bssid             = $null
        SignalPercent     = $null
    }

    $egress = Get-EgressInterface -TargetIp $TargetIp
    $ctx.InterfaceIndex = $egress.InterfaceIndex
    $ctx.LocalIp        = $egress.LocalIp

    if ($null -ne $ctx.InterfaceIndex) {
        try {
            $adapter = Get-NetAdapter -InterfaceIndex $ctx.InterfaceIndex -ErrorAction Stop
            $ctx.AdapterName        = $adapter.Name
            $ctx.AdapterDescription = $adapter.InterfaceDescription
            $ctx.AdapterMac         = ConvertTo-NormalizedMac $adapter.MacAddress
            $ctx.MediaType          = $adapter.MediaType
            $ctx.LinkSpeed          = $adapter.LinkSpeed
        }
        catch { }

        try {
            $conf = Get-NetIPConfiguration -InterfaceIndex $ctx.InterfaceIndex -ErrorAction Stop
            if ($conf.IPv4DefaultGateway) {
                $ctx.GatewayIp = ($conf.IPv4DefaultGateway | Select-Object -First 1).NextHop
            }
            if ($conf.DNSServer) {
                $servers = @($conf.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
                if ($servers.Count -gt 0) { $ctx.ConfiguredDns = ($servers -join ';') }
            }
        }
        catch { }

        if (-not $ctx.LocalIp) {
            try {
                $ip = Get-NetIPAddress -InterfaceIndex $ctx.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
                      Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
                if ($ip) { $ctx.LocalIp = $ip.IPAddress; $ctx.PrefixLength = $ip.PrefixLength; $ctx.DhcpEnabled = ($ip.PrefixOrigin -eq 'Dhcp') }
            }
            catch { }
        }
        else {
            try {
                $ip = Get-NetIPAddress -InterfaceIndex $ctx.InterfaceIndex -IPAddress $ctx.LocalIp -ErrorAction Stop | Select-Object -First 1
                if ($ip) { $ctx.PrefixLength = $ip.PrefixLength; $ctx.DhcpEnabled = ($ip.PrefixOrigin -eq 'Dhcp') }
            }
            catch { }
        }
    }

    # Gateway MAC: the fingerprint of the first-hop device.
    if ($ctx.GatewayIp) {
        try {
            $neighbor = Get-NetNeighbor -IPAddress $ctx.GatewayIp -ErrorAction Stop |
                        Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
                        Select-Object -First 1
            if ($neighbor) {
                $ctx.GatewayMac      = ConvertTo-NormalizedMac $neighbor.LinkLayerAddress
                $ctx.GatewayMacState = [string]$neighbor.State
            }
        }
        catch { }
    }

    $wifi = Get-WirelessContext
    if ($wifi.IsWireless -and $ctx.MediaType -match '802\.11|Native') {
        $ctx.IsWireless    = $true
        $ctx.Ssid          = $wifi.Ssid
        $ctx.Bssid         = $wifi.Bssid
        $ctx.SignalPercent = $wifi.SignalPercent
    }
    elseif ($wifi.IsWireless -and $null -eq $ctx.MediaType) {
        $ctx.IsWireless    = $true
        $ctx.Ssid          = $wifi.Ssid
        $ctx.Bssid         = $wifi.Bssid
        $ctx.SignalPercent = $wifi.SignalPercent
    }

    return [pscustomobject]$ctx
}

function Get-LocalDnsFirewallRules {
<#
    .SYNOPSIS
        Looks for a *local* Windows Firewall rule that blocks port 53.
    .DESCRIPTION
        Run once per session rather than per probe: enumerating the full
        rule set with its port filters takes seconds. If a local rule is
        found, the block is on this machine and no amount of staring at
        the campus firewall will explain it.
#>
    $found = @()
    try {
        $blockRules = Get-NetFirewallRule -ErrorAction Stop |
                      Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }

        foreach ($rule in $blockRules) {
            try {
                $filter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
            } catch { continue }

            foreach ($f in $filter) {
                $ports = @($f.RemotePort) + @($f.LocalPort)
                $hit = $ports | Where-Object {
                    $_ -eq '53' -or ($_ -is [string] -and $_ -match '(^|,)\s*53\s*(,|$)') -or ($_ -is [string] -and $_ -match '^\d+-\d+$' -and (
                        [int]($_ -split '-')[0] -le 53 -and [int]($_ -split '-')[1] -ge 53))
                }
                if ($hit) {
                    $found += [pscustomobject]@{
                        DisplayName = $rule.DisplayName
                        Direction   = [string]$rule.Direction
                        Profile     = [string]$rule.Profile
                        Protocol    = [string]$f.Protocol
                        LocalPort   = ($f.LocalPort  -join ',')
                        RemotePort  = ($f.RemotePort -join ',')
                    }
                }
            }
        }
    }
    catch {
        return @()
    }
    return $found
}

function Get-FirstHopPath {
<#
    .SYNOPSIS
        Records the first few hops toward the DNS server.
    .DESCRIPTION
        Used only in the one-shot diagnostic, never in the monitor loop:
        it is slow and noisy. The value is that the hop where TTL expiry
        stops responding often sits next to the device dropping port 53.
#>
    param([Parameter(Mandatory)][string]$TargetIp, [int]$MaxHops = 8)

    try {
        $trace = Test-NetConnection -ComputerName $TargetIp -TraceRoute -Hops $MaxHops -WarningAction SilentlyContinue -ErrorAction Stop
        if ($trace -and $trace.TraceRoute) { return @($trace.TraceRoute) }
    }
    catch { }
    return @()
}
