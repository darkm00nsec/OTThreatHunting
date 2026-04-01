#requires -Version 5.1

<#
.SYNOPSIS
    Cross-platform threat hunting script for Windows and Linux with CSV output and OT protocol detection.

.DESCRIPTION
    Supports:
    - Local execution
    - Remote execution via WinRM
    - Remote execution via SSH (environment dependent)
    - Windows and Linux artifact collection
    - OT/ICS protocol port match detection
    - CSV output for all functions

Author: Hunter Harrison

#Credit to MrDuc as referenced in this article https://medium.com/@itpro677/hunting-threats-in-ot-environments-using-only-built-in-system-commands-no-tools-required-6adc80ef0ee2

.NOTES
    Intended for authorized defensive security and threat hunting only.
#>

$HuntingScriptBlock = {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedChoice,

        [Parameter(Mandatory)]
        [string]$ComputerNameForFile
    )

    function Get-PlatformInfo {
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            return @{
                IsWindows = $true
                IsLinux   = $false
            }
        }

        return @{
            IsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [System.Runtime.InteropServices.OSPlatform]::Windows
            )
            IsLinux   = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [System.Runtime.InteropServices.OSPlatform]::Linux
            )
        }
    }

    function Ensure-Directory {
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    }

    function Get-OutputDirectory {
        param(
            [Parameter(Mandatory)]
            [string]$BaseDir,
            [Parameter(Mandatory)]
            [string]$ComputerName,
            [Parameter(Mandatory)]
            [string]$DateString
        )

        $folderName = "{0}_{1}" -f $ComputerName, $DateString
        $targetDir = Join-Path -Path $BaseDir -ChildPath $folderName
        Ensure-Directory -Path $targetDir
        return $targetDir
    }

    function Write-CsvOutput {
        param(
            [Parameter(Mandatory)]
            [string]$FilePath,

            [Parameter(Mandatory)]
            $Data
        )

        if ($null -eq $Data) {
            [pscustomobject]@{ Message = "No results" } |
                Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
            return
        }

        $array = @($Data)

        if ($array.Count -eq 0) {
            [pscustomobject]@{ Message = "No results" } |
                Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
        }
        else {
            $array | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
        }
    }

    function Get-OTProtocolMap {
        @(
            [pscustomobject]@{ Name = 'Modbus/TCP';            Protocol = 'TCP'; Port = 502   }
            [pscustomobject]@{ Name = 'Siemens S7comm';        Protocol = 'TCP'; Port = 102   }
            [pscustomobject]@{ Name = 'EtherNet/IP';           Protocol = 'TCP'; Port = 44818 }
            [pscustomobject]@{ Name = 'EtherNet/IP I/O';       Protocol = 'UDP'; Port = 2222  }
            [pscustomobject]@{ Name = 'DNP3';                  Protocol = 'TCP'; Port = 20000 }
            [pscustomobject]@{ Name = 'OPC UA';                Protocol = 'TCP'; Port = 4840  }
            [pscustomobject]@{ Name = 'BACnet/IP';             Protocol = 'UDP'; Port = 47808 }
            [pscustomobject]@{ Name = 'PROFINET Context Mgmt'; Protocol = 'UDP'; Port = 34964 }
            [pscustomobject]@{ Name = 'PROFINET RT Discovery'; Protocol = 'UDP'; Port = 34962 }
            [pscustomobject]@{ Name = 'PROFINET RT Control';   Protocol = 'UDP'; Port = 34963 }
            [pscustomobject]@{ Name = 'IEC 60870-5-104';       Protocol = 'TCP'; Port = 2404  }
            [pscustomobject]@{ Name = 'Tridium Fox';           Protocol = 'TCP'; Port = 1911  }
            [pscustomobject]@{ Name = 'Niagara Fox SSL';       Protocol = 'TCP'; Port = 4911  }
            [pscustomobject]@{ Name = 'OMRON FINS';            Protocol = 'UDP'; Port = 9600  }
            [pscustomobject]@{ Name = 'MELSEC';                Protocol = 'TCP'; Port = 5007  }
            [pscustomobject]@{ Name = 'MELSEC';                Protocol = 'UDP'; Port = 5006  }
            [pscustomobject]@{ Name = 'IEC 61850 MMS';         Protocol = 'TCP'; Port = 102   }
            [pscustomobject]@{ Name = 'CODESYS Gateway';       Protocol = 'TCP'; Port = 1217  }
        )
    }

    function Get-IPScope {
        param([string]$Address)

        if ([string]::IsNullOrWhiteSpace($Address)) { return "Unknown" }
        if ($Address -match '^\*|^\[::\]|^0\.0\.0\.0|^::$') { return "Wildcard" }
        if ($Address -match '^127\.|^::1|^localhost') { return "Loopback" }
        if ($Address -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return "Private" }
        if ($Address -match '^169\.254\.') { return "LinkLocal" }
        return "PublicOrOther"
    }

    function Split-HostPort {
        param([string]$Endpoint)

        if ([string]::IsNullOrWhiteSpace($Endpoint)) {
            return [pscustomobject]@{ Host = ""; Port = "" }
        }

        if ($Endpoint -eq "*:*" -or $Endpoint -eq "*") {
            return [pscustomobject]@{ Host = "*"; Port = "*" }
        }

        if ($Endpoint -match '^\[(.*)\]:(\d+)$') {
            return [pscustomobject]@{ Host = $matches[1]; Port = $matches[2] }
        }

        if ($Endpoint -match '^(.*):(\d+)$') {
            return [pscustomobject]@{ Host = $matches[1]; Port = $matches[2] }
        }

        return [pscustomobject]@{ Host = $Endpoint; Port = "" }
    }

    $platform = Get-PlatformInfo
    $isWindows = $platform.IsWindows
    $isLinux   = $platform.IsLinux

    if ($isWindows) {
        $baseDir = Join-Path -Path $env:USERPROFILE -ChildPath "ThreatHunting"
    }
    elseif ($isLinux) {
        $baseDir = Join-Path -Path $HOME -ChildPath "threat_hunting_logs"
    }
    else {
        throw "Unsupported operating system."
    }

    Ensure-Directory -Path $baseDir

    $dateStr   = Get-Date -Format "yyyy-MM-dd"
    $outputDir = Get-OutputDirectory -BaseDir $baseDir -ComputerName $ComputerNameForFile -DateString $dateStr

    # -----------------------------
    # Windows functions
    # -----------------------------
    function Run-WindowsNetworkHunting {
        $lines = @(netstat -ano 2>$null)

        $parsed = foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^(TCP|UDP)\s+') {
                $parts = $trimmed -split '\s+'
                if ($parts[0] -eq 'TCP' -and $parts.Count -ge 5) {
                    $local = Split-HostPort $parts[1]
                    $remote = Split-HostPort $parts[2]
                    [pscustomobject]@{
                        Timestamp     = Get-Date
                        Computer      = $env:COMPUTERNAME
                        Protocol      = $parts[0]
                        LocalAddress  = $local.Host
                        LocalPort     = $local.Port
                        RemoteAddress = $remote.Host
                        RemotePort    = $remote.Port
                        State         = $parts[3]
                        PID           = $parts[4]
                    }
                }
                elseif ($parts[0] -eq 'UDP' -and $parts.Count -ge 4) {
                    $local = Split-HostPort $parts[1]
                    $remote = Split-HostPort $parts[2]
                    [pscustomobject]@{
                        Timestamp     = Get-Date
                        Computer      = $env:COMPUTERNAME
                        Protocol      = $parts[0]
                        LocalAddress  = $local.Host
                        LocalPort     = $local.Port
                        RemoteAddress = $remote.Host
                        RemotePort    = $remote.Port
                        State         = ""
                        PID           = $parts[3]
                    }
                }
            }
        }

        $established = @($parsed | Where-Object { $_.State -eq 'ESTABLISHED' })
        $listening   = @($parsed | Where-Object { $_.State -eq 'LISTENING' -or ($_.Protocol -eq 'UDP' -and $_.LocalPort) })

        Write-CsvOutput -FilePath (Join-Path $outputDir "established_connections.csv") -Data $established
        Write-CsvOutput -FilePath (Join-Path $outputDir "listening_ports.csv") -Data $listening
        Write-CsvOutput -FilePath (Join-Path $outputDir "all_network_connections.csv") -Data $parsed
    }

    function Run-WindowsProcessAndServiceHunting {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Timestamp    = Get-Date
                Computer     = $env:COMPUTERNAME
                Name         = $_.Name
                ProcessId    = $_.ProcessId
                ParentPID    = $_.ParentProcessId
                Executable   = $_.ExecutablePath
                CommandLine  = $_.CommandLine
            }
        }

        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Timestamp    = Get-Date
                Computer     = $env:COMPUTERNAME
                Name         = $_.Name
                DisplayName  = $_.DisplayName
                State        = $_.State
                StartMode    = $_.StartMode
                PathName     = $_.PathName
                ProcessId    = $_.ProcessId
                StartName    = $_.StartName
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "process_list.csv") -Data $processes
        Write-CsvOutput -FilePath (Join-Path $outputDir "services.csv") -Data $services
    }

    function Run-WindowsScheduledTaskHunting {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Timestamp        = Get-Date
                Computer         = $env:COMPUTERNAME
                TaskName         = $_.TaskName
                TaskPath         = $_.TaskPath
                State            = $_.State
                Author           = $_.Author
                Description      = $_.Description
                LastRunTime      = $info.LastRunTime
                NextRunTime      = $info.NextRunTime
                LastTaskResult   = $info.LastTaskResult
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "scheduled_tasks.csv") -Data $tasks
    }

    function Run-WindowsUserAccountHunting {
        $users = Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Timestamp            = Get-Date
                Computer             = $env:COMPUTERNAME
                Name                 = $_.Name
                Enabled              = $_.Enabled
                FullName             = $_.FullName
                Description          = $_.Description
                LastLogon            = $_.LastLogon
                PasswordRequired     = $_.PasswordRequired
                PasswordNeverExpires = $_.PasswordNeverExpires
            }
        }

        $admins = @()
        try {
            $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    Timestamp     = Get-Date
                    Computer      = $env:COMPUTERNAME
                    Group         = "Administrators"
                    Name          = $_.Name
                    ObjectClass   = $_.ObjectClass
                    PrincipalSource = $_.PrincipalSource
                }
            }
        } catch {}

        Write-CsvOutput -FilePath (Join-Path $outputDir "local_users.csv") -Data $users
        Write-CsvOutput -FilePath (Join-Path $outputDir "local_admins.csv") -Data $admins
    }

    function Run-WindowsEventLogHunting {
        $startTime = (Get-Date).AddDays(-30)

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | ForEach-Object {
            [xml]$xml = $_.ToXml()
            $eventData = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                $eventData[$d.Name] = $d.'#text'
            }

            [pscustomobject]@{
                Timestamp         = $_.TimeCreated
                Computer          = $_.MachineName
                EventId           = $_.Id
                RecordId          = $_.RecordId
                LevelDisplayName  = $_.LevelDisplayName
                TargetUserName    = $eventData['TargetUserName']
                TargetDomainName  = $eventData['TargetDomainName']
                IpAddress         = $eventData['IpAddress']
                IpPort            = $eventData['IpPort']
                LogonType         = $eventData['LogonType']
                Status            = $eventData['Status']
                SubStatus         = $eventData['SubStatus']
                WorkstationName   = $eventData['WorkstationName']
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "event_failed_logons.csv") -Data $events
    }

    function Run-WindowsNetworkConfigHunting {
        $adapters = Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($ipv4 in $_.IPv4Address) {
                [pscustomobject]@{
                    Timestamp         = Get-Date
                    Computer          = $env:COMPUTERNAME
                    InterfaceAlias    = $_.InterfaceAlias
                    InterfaceDesc     = $_.InterfaceDescription
                    InterfaceIndex    = $_.InterfaceIndex
                    IPv4Address       = $ipv4.IPAddress
                    PrefixLength      = $ipv4.PrefixLength
                    IPv4DefaultGateway= ($_.IPv4DefaultGateway.NextHop -join ';')
                    DNSServer         = ($_.DNSServer.ServerAddresses -join ';')
                }
            }
        }

        $arp = Get-NetNeighbor -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Timestamp      = Get-Date
                Computer       = $env:COMPUTERNAME
                InterfaceIndex = $_.InterfaceIndex
                IPAddress      = $_.IPAddress
                LinkLayerAddr  = $_.LinkLayerAddress
                State          = $_.State
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "network_adapter_config.csv") -Data $adapters
        Write-CsvOutput -FilePath (Join-Path $outputDir "arp_table.csv") -Data $arp
    }

    function Run-WindowsOTProtocolHunting {
        $otMap = Get-OTProtocolMap
        $lines = @(netstat -ano 2>$null)

        $findings = foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^(TCP|UDP)\s+') {
                $parts = $trimmed -split '\s+'

                if ($parts[0] -eq 'TCP' -and $parts.Count -ge 5) {
                    $local = Split-HostPort $parts[1]
                    $remote = Split-HostPort $parts[2]
                    $state = $parts[3]
                    $pid = $parts[4]
                    $portHits = @($otMap | Where-Object { $_.Protocol -eq 'TCP' -and ($_.Port -eq [int]$local.Port -or $_.Port -eq [int]$remote.Port) })

                    foreach ($hit in $portHits) {
                        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                        [pscustomobject]@{
                            Timestamp        = Get-Date
                            Computer         = $env:COMPUTERNAME
                            Protocol         = 'TCP'
                            OTProtocol       = $hit.Name
                            Port             = $hit.Port
                            LocalAddress     = $local.Host
                            LocalPort        = $local.Port
                            RemoteAddress    = $remote.Host
                            RemotePort       = $remote.Port
                            RemoteScope      = Get-IPScope $remote.Host
                            State            = $state
                            PID              = $pid
                            ProcessName      = $proc.ProcessName
                            Suspicious       = if ((Get-IPScope $remote.Host) -eq 'PublicOrOther') { 'YES' } else { 'NO' }
                        }
                    }
                }
                elseif ($parts[0] -eq 'UDP' -and $parts.Count -ge 4) {
                    $local = Split-HostPort $parts[1]
                    $remote = Split-HostPort $parts[2]
                    $pid = $parts[3]
                    $portHits = @($otMap | Where-Object { $_.Protocol -eq 'UDP' -and ($_.Port -eq [int]$local.Port -or $_.Port -eq [int]$remote.Port) })

                    foreach ($hit in $portHits) {
                        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                        [pscustomobject]@{
                            Timestamp        = Get-Date
                            Computer         = $env:COMPUTERNAME
                            Protocol         = 'UDP'
                            OTProtocol       = $hit.Name
                            Port             = $hit.Port
                            LocalAddress     = $local.Host
                            LocalPort        = $local.Port
                            RemoteAddress    = $remote.Host
                            RemotePort       = $remote.Port
                            RemoteScope      = Get-IPScope $remote.Host
                            State            = ''
                            PID              = $pid
                            ProcessName      = $proc.ProcessName
                            Suspicious       = if ((Get-IPScope $remote.Host) -eq 'PublicOrOther') { 'YES' } else { 'NO' }
                        }
                    }
                }
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "ot_protocol_reference_ports.csv") -Data $otMap
        Write-CsvOutput -FilePath (Join-Path $outputDir "ot_protocol_matches.csv") -Data $findings
    }

    # -----------------------------
    # Linux functions
    # -----------------------------
    function Run-LinuxNetworkHunting {
        $lines = @(ss -tuna 2>$null)

        $parsed = foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^(tcp|udp)') {
                $parts = $trimmed -split '\s+'
                if ($parts.Count -ge 5) {
                    $local = Split-HostPort $parts[4]
                    $peer  = if ($parts.Count -ge 6) { Split-HostPort $parts[5] } else { [pscustomobject]@{ Host=''; Port='' } }

                    [pscustomobject]@{
                        Timestamp     = Get-Date
                        Computer      = $env:COMPUTERNAME
                        Protocol      = $parts[0]
                        State         = $parts[1]
                        LocalAddress  = $local.Host
                        LocalPort     = $local.Port
                        RemoteAddress = $peer.Host
                        RemotePort    = $peer.Port
                    }
                }
            }
        }

        $established = @($parsed | Where-Object { $_.State -match 'ESTAB' })
        $listening   = @($parsed | Where-Object { $_.State -match 'LISTEN|UNCONN' })

        Write-CsvOutput -FilePath (Join-Path $outputDir "established_connections.csv") -Data $established
        Write-CsvOutput -FilePath (Join-Path $outputDir "listening_ports.csv") -Data $listening
        Write-CsvOutput -FilePath (Join-Path $outputDir "all_network_connections.csv") -Data $parsed
    }

    function Run-LinuxProcessAndServiceHunting {
        $processes = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Timestamp   = Get-Date
                Computer    = $env:COMPUTERNAME
                Name        = $_.ProcessName
                Id          = $_.Id
                CPU         = $_.CPU
                WS          = $_.WorkingSet64
                StartTime   = try { $_.StartTime } catch { $null }
                Path        = try { $_.Path } catch { $null }
            }
        }

        $services = @(systemctl list-units --type=service --state=running --no-pager --no-legend 2>$null | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                $parts = $line -split '\s+', 5
                [pscustomobject]@{
                    Timestamp   = Get-Date
                    Computer    = $env:COMPUTERNAME
                    Unit        = if ($parts.Count -ge 1) { $parts[0] } else { '' }
                    Load        = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                    Active      = if ($parts.Count -ge 3) { $parts[2] } else { '' }
                    Sub         = if ($parts.Count -ge 4) { $parts[3] } else { '' }
                    Description = if ($parts.Count -ge 5) { $parts[4] } else { '' }
                }
            }
        })

        Write-CsvOutput -FilePath (Join-Path $outputDir "process_list.csv") -Data $processes
        Write-CsvOutput -FilePath (Join-Path $outputDir "services.csv") -Data $services
    }

    function Run-LinuxCronHunting {
        $cron = @()
        try {
            $rootCron = bash -c 'crontab -l -u root 2>/dev/null'
            foreach ($entry in $rootCron) {
                if (-not [string]::IsNullOrWhiteSpace($entry) -and $entry.Trim() -notmatch '^\s*#') {
                    $cron += [pscustomobject]@{
                        Timestamp = Get-Date
                        Computer  = $env:COMPUTERNAME
                        User      = 'root'
                        Entry     = $entry.Trim()
                    }
                }
            }
        } catch {}

        Write-CsvOutput -FilePath (Join-Path $outputDir "cron_jobs.csv") -Data $cron
    }

    function Run-LinuxUserAccountHunting {
        $users = @()
        if (Test-Path /etc/passwd) {
            $users = Get-Content /etc/passwd | ForEach-Object {
                $fields = $_ -split ':'
                if ($fields.Count -ge 7) {
                    [pscustomobject]@{
                        Timestamp = Get-Date
                        Computer  = $env:COMPUTERNAME
                        UserName  = $fields[0]
                        UID       = $fields[2]
                        GID       = $fields[3]
                        Comment   = $fields[4]
                        HomeDir   = $fields[5]
                        Shell     = $fields[6]
                    }
                }
            }
        }

        $sessions = @(who 2>$null | ForEach-Object {
            $line = $_.Trim()
            if ($line) {
                $parts = $line -split '\s+'
                [pscustomobject]@{
                    Timestamp = Get-Date
                    Computer  = $env:COMPUTERNAME
                    UserName  = if ($parts.Count -ge 1) { $parts[0] } else { '' }
                    TTY       = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                    Date      = if ($parts.Count -ge 3) { $parts[2] } else { '' }
                    Time      = if ($parts.Count -ge 4) { $parts[3] } else { '' }
                    Source    = if ($parts.Count -ge 5) { $parts[4] } else { '' }
                }
            }
        })

        Write-CsvOutput -FilePath (Join-Path $outputDir "all_users.csv") -Data $users
        Write-CsvOutput -FilePath (Join-Path $outputDir "active_sessions.csv") -Data $sessions
    }

    function Run-LinuxLogHunting {
        $logs = @(journalctl _SYSTEMD_UNIT=sshd.service --since "30 days ago" 2>$null | Select-String "Failed password" | ForEach-Object {
            [pscustomobject]@{
                Timestamp = Get-Date
                Computer  = $env:COMPUTERNAME
                LogLine   = $_.Line.Trim()
            }
        })

        Write-CsvOutput -FilePath (Join-Path $outputDir "journal_failed_ssh_logons.csv") -Data $logs
    }

    function Run-LinuxNetworkConfigHunting {
        $ipConfig = @(ip -o addr 2>$null | ForEach-Object {
            $line = $_.Trim()
            $parts = $line -split '\s+'
            if ($parts.Count -ge 4) {
                [pscustomobject]@{
                    Timestamp = Get-Date
                    Computer  = $env:COMPUTERNAME
                    Interface = $parts[1]
                    Family    = $parts[2]
                    Address   = $parts[3]
                }
            }
        })

        $arp = @(ip -s neigh 2>$null | ForEach-Object {
            [pscustomobject]@{
                Timestamp = Get-Date
                Computer  = $env:COMPUTERNAME
                RawLine   = $_.Trim()
            }
        })

        Write-CsvOutput -FilePath (Join-Path $outputDir "network_adapter_config.csv") -Data $ipConfig
        Write-CsvOutput -FilePath (Join-Path $outputDir "arp_table.csv") -Data $arp
    }

    function Run-LinuxOTProtocolHunting {
        $otMap = Get-OTProtocolMap
        $lines = @(ss -tuna 2>$null)

        $findings = foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^(tcp|udp)') {
                $parts = $trimmed -split '\s+'
                if ($parts.Count -ge 6) {
                    $protocol = $parts[0].ToUpper()
                    $state    = $parts[1]
                    $local    = Split-HostPort $parts[4]
                    $peer     = Split-HostPort $parts[5]
                    $localPortInt = 0
                    $peerPortInt = 0
                    [void][int]::TryParse($local.Port, [ref]$localPortInt)
                    [void][int]::TryParse($peer.Port, [ref]$peerPortInt)

                    $portHits = @($otMap | Where-Object {
                        $_.Protocol -eq $protocol -and ($_.Port -eq $localPortInt -or $_.Port -eq $peerPortInt)
                    })

                    foreach ($hit in $portHits) {
                        [pscustomobject]@{
                            Timestamp        = Get-Date
                            Computer         = $env:COMPUTERNAME
                            Protocol         = $protocol
                            OTProtocol       = $hit.Name
                            Port             = $hit.Port
                            LocalAddress     = $local.Host
                            LocalPort        = $local.Port
                            RemoteAddress    = $peer.Host
                            RemotePort       = $peer.Port
                            RemoteScope      = Get-IPScope $peer.Host
                            State            = $state
                            Suspicious       = if ((Get-IPScope $peer.Host) -eq 'PublicOrOther') { 'YES' } else { 'NO' }
                            RawLine          = $trimmed
                        }
                    }
                }
            }
        }

        Write-CsvOutput -FilePath (Join-Path $outputDir "ot_protocol_reference_ports.csv") -Data $otMap
        Write-CsvOutput -FilePath (Join-Path $outputDir "ot_protocol_matches.csv") -Data $findings
    }

    if ($isWindows) {
        switch ($SelectedChoice) {
            '1' { Run-WindowsNetworkHunting }
            '2' { Run-WindowsProcessAndServiceHunting }
            '3' { Run-WindowsScheduledTaskHunting }
            '4' { Run-WindowsUserAccountHunting }
            '5' { Run-WindowsEventLogHunting }
            '6' { Run-WindowsNetworkConfigHunting }
            '7' { Run-WindowsOTProtocolHunting }
            '8' {
                Run-WindowsNetworkHunting
                Run-WindowsProcessAndServiceHunting
                Run-WindowsScheduledTaskHunting
                Run-WindowsUserAccountHunting
                Run-WindowsEventLogHunting
                Run-WindowsNetworkConfigHunting
                Run-WindowsOTProtocolHunting
            }
            default { throw "Invalid selection: $SelectedChoice" }
        }
    }
    elseif ($isLinux) {
        switch ($SelectedChoice) {
            '1' { Run-LinuxNetworkHunting }
            '2' { Run-LinuxProcessAndServiceHunting }
            '3' { Run-LinuxCronHunting }
            '4' { Run-LinuxUserAccountHunting }
            '5' { Run-LinuxLogHunting }
            '6' { Run-LinuxNetworkConfigHunting }
            '7' { Run-LinuxOTProtocolHunting }
            '8' {
                Run-LinuxNetworkHunting
                Run-LinuxProcessAndServiceHunting
                Run-LinuxCronHunting
                Run-LinuxUserAccountHunting
                Run-LinuxLogHunting
                Run-LinuxNetworkConfigHunting
                Run-LinuxOTProtocolHunting
            }
            default { throw "Invalid selection: $SelectedChoice" }
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        OutputPath   = $outputDir
        Status       = "Execution finished successfully."
    }
}

Write-Host "`nSelect Execution Mode:" -ForegroundColor Green
$runMode = Read-Host "(L)ocal or (R)emote?"
if ($runMode -notmatch '^[Rr]$') {
    $runMode = 'L'
}
else {
    $runMode = 'R'
}

$computerNames = @($env:COMPUTERNAME)
$credential = $null
$useSSH = $false

if ($runMode -eq 'R') {
    $computerInput = Read-Host "Enter remote computer names, separated by commas (e.g., Server1,192.168.1.50)"
    if ([string]::IsNullOrWhiteSpace($computerInput)) {
        Write-Host "No computer names entered. Exiting." -ForegroundColor Red
        exit
    }

    $computerNames = $computerInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $credential = Get-Credential

    $protocol = Read-Host "Use (W)inRM or (S)SH for connection?"
    if ($protocol -match '^[Ss]$') {
        $useSSH = $true
    }
}

do {
    Write-Host "`nSelect a threat hunting category to run:" -ForegroundColor Yellow
    Write-Host "1. Network Connections"
    Write-Host "2. Processes and Services"
    Write-Host "3. Scheduled Tasks / Cron Jobs"
    Write-Host "4. User Accounts"
    Write-Host "5. Logs (Event Logs / Journal)"
    Write-Host "6. Network Configuration"
    Write-Host "7. OT Protocol Port Matches"
    Write-Host "8. RUN ALL CHECKS"
    Write-Host "Q. Quit"

    $choice = Read-Host "Enter your choice"

    if ($choice -match '^[Qq]$') {
        break
    }

    if ('1','2','3','4','5','6','7','8' -notcontains $choice) {
        Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        continue
    }

    try {
        if ($runMode -eq 'R') {
            Write-Host "`nExecuting remote command(s)..." -ForegroundColor Cyan

            foreach ($computer in $computerNames) {
                Write-Host "--- Connecting to $computer ---" -ForegroundColor DarkCyan

                if ($useSSH) {
                    Write-Host "Note: PowerShell SSH remoting may require PowerShell 7+ and SSH remoting configuration." -ForegroundColor Yellow

                    $result = Invoke-Command `
                        -HostName $computer `
                        -UserName $credential.UserName `
                        -ScriptBlock $HuntingScriptBlock `
                        -ArgumentList $choice, $computer
                }
                else {
                    $result = Invoke-Command `
                        -ComputerName $computer `
                        -Credential $credential `
                        -ScriptBlock $HuntingScriptBlock `
                        -ArgumentList $choice, $computer
                }

                $result | Format-List
            }
        }
        else {
            Write-Host "`nExecuting local command..." -ForegroundColor Cyan
            $result = & $HuntingScriptBlock -SelectedChoice $choice -ComputerNameForFile $env:COMPUTERNAME
            $result | Format-List
        }
    }
    catch {
        Write-Host "An error occurred during execution:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }

} while ($true)

Write-Host "Exiting script."
