#requires -Version 5.1

#Credit to MrDuc as referenced in this article https://medium.com/@itpro677/hunting-threats-in-ot-environments-using-only-built-in-system-commands-no-tools-required-6adc80ef0ee2

# -----------------------------
# Threat Hunting Script
# -----------------------------

$HuntingScriptBlock = {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedChoice,

        [Parameter(Mandatory)]
        [string]$ComputerNameForFile
    )

    # -----------------------------
    # Helper functions
    # -----------------------------
    function Get-PlatformInfo {
        # Windows PowerShell 5.1 does not always have $IsWindows / $IsLinux
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

    function Get-SafeOutputBase {
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

    function Out-CommandToFile {
        param(
            [Parameter(Mandatory)]
            [string]$FilePath,

            [Parameter(Mandatory)]
            [scriptblock]$Command
        )

        try {
            & $Command | Out-File -FilePath $FilePath -Encoding utf8 -Width 4096 -Force
        }
        catch {
            "ERROR running command: $($_.Exception.Message)" | Out-File -FilePath $FilePath -Encoding utf8 -Force
        }
    }

    # -----------------------------
    # Platform + output setup
    # -----------------------------
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
    $outputDir = Get-SafeOutputBase -BaseDir $baseDir -ComputerName $ComputerNameForFile -DateString $dateStr

    # -----------------------------
    # Windows functions
    # -----------------------------
    function Run-WindowsNetworkHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "established_connections.txt") -Command {
            netstat -ano | findstr "ESTABLISHED"
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "listening_ports.txt") -Command {
            netstat -ano | findstr "LISTENING"
        }
    }

    function Run-WindowsProcessAndServiceHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "process_list_verbose.txt") -Command {
            tasklist /v
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "wmic_process_details.txt") -Command {
            wmic process get Name,ProcessId,CommandLine /format:list
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "wmic_running_services.txt") -Command {
            wmic service where "State='Running'" get Name,PathName
        }
    }

    function Run-WindowsScheduledTaskHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "scheduled_tasks_all.txt") -Command {
            schtasks /query /fo LIST /v
        }
    }

    function Run-WindowsUserAccountHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "local_users.txt") -Command {
            net user
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "local_admins.txt") -Command {
            net localgroup administrators
        }
    }

    function Run-WindowsEventLogHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "event_failed_logons.txt") -Command {
            wevtutil qe Security /q:"*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 2592000000]]]" /f:text
        }
    }

    function Run-WindowsNetworkConfigHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "network_adapter_config.txt") -Command {
            ipconfig /all
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "arp_table.txt") -Command {
            arp -a
        }
    }

    # -----------------------------
    # Linux functions
    # -----------------------------
    function Run-LinuxNetworkHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "established_connections.txt") -Command {
            ss -tuna | grep 'ESTAB'
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "listening_ports.txt") -Command {
            ss -tuna | grep 'LISTEN'
        }
    }

    function Run-LinuxProcessAndServiceHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "process_list_verbose.txt") -Command {
            ps aux --forest
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "running_services.txt") -Command {
            systemctl list-units --type=service --state=running
        }
    }

    function Run-LinuxCronHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "cron_jobs_root.txt") -Command {
            crontab -l -u root 2>$null
        }
    }

    function Run-LinuxUserAccountHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "all_users.txt") -Command {
            Get-Content /etc/passwd
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "active_sessions.txt") -Command {
            who
        }
    }

    function Run-LinuxLogHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "journal_failed_ssh_logons.txt") -Command {
            journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed password"
        }
    }

    function Run-LinuxNetworkConfigHunting {
        Out-CommandToFile -FilePath (Join-Path $outputDir "network_adapter_config.txt") -Command {
            ip addr
        }

        Out-CommandToFile -FilePath (Join-Path $outputDir "arp_table.txt") -Command {
            ip -s neigh
        }
    }

    # -----------------------------
    # Execution logic
    # -----------------------------
    if ($isWindows) {
        switch ($SelectedChoice) {
            '1' { Run-WindowsNetworkHunting }
            '2' { Run-WindowsProcessAndServiceHunting }
            '3' { Run-WindowsScheduledTaskHunting }
            '4' { Run-WindowsUserAccountHunting }
            '5' { Run-WindowsEventLogHunting }
            '6' { Run-WindowsNetworkConfigHunting }
            '7' {
                Run-WindowsNetworkHunting
                Run-WindowsProcessAndServiceHunting
                Run-WindowsScheduledTaskHunting
                Run-WindowsUserAccountHunting
                Run-WindowsEventLogHunting
                Run-WindowsNetworkConfigHunting
            }
            default {
                throw "Invalid selection: $SelectedChoice"
            }
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
            '7' {
                Run-LinuxNetworkHunting
                Run-LinuxProcessAndServiceHunting
                Run-LinuxCronHunting
                Run-LinuxUserAccountHunting
                Run-LinuxLogHunting
                Run-LinuxNetworkConfigHunting
            }
            default {
                throw "Invalid selection: $SelectedChoice"
            }
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        OutputPath   = $outputDir
        Status       = "Execution finished successfully."
    }
}

# -----------------------------
# Main interactive menu
# -----------------------------
Write-Host "`nSelect Execution Mode:" -ForegroundColor Green
$runMode = Read-Host "(L)ocal or (R)emote?"
if ($runMode -notmatch '^[Rr]$') {
    $runMode = 'L'
} else {
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
    Write-Host "7. RUN ALL CHECKS"
    Write-Host "Q. Quit"

    $choice = Read-Host "Enter your choice"

    if ($choice -match '^[Qq]$') {
        break
    }

    if ('1','2','3','4','5','6','7' -notcontains $choice) {
        Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        continue
    }

    try {
        if ($runMode -eq 'R') {
            Write-Host "`nExecuting remote command(s)..." -ForegroundColor Cyan

            foreach ($computer in $computerNames) {
                Write-Host "--- Connecting to $computer ---" -ForegroundColor DarkCyan

                if ($useSSH) {
                    $result = Invoke-Command `
                        -HostName $computer `
                        -UserName $credential.UserName `
                        -KeyFilePath $null `
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