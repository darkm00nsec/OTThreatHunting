# Threat Hunting Script

A cross-platform PowerShell threat hunting script for **local** or **remote** collection of basic host artifacts on **Windows** and **Linux** systems.

This script can collect:

- Network connections
- Listening ports
- Processes and services
- Scheduled tasks or cron jobs
- User account information
- Authentication or event log data
- Network configuration details

The script is designed to save output into organized folders by **host name** and **date**, making it easier to review results from multiple systems.

## Features

- Supports **local** execution
- Supports **remote** execution
- Works against **Windows** and **Linux** targets
- Creates output folders automatically
- Saves each hunt category into separate text files
- Can run one category at a time or **run all checks**

## Collected Artifacts

### Windows
1. **Network Connections**
   - Established connections
   - Listening ports

2. **Processes and Services**
   - Verbose task list
   - WMIC process details
   - Running services

3. **Scheduled Tasks**
   - Full scheduled task listing

4. **User Accounts**
   - Local users
   - Local administrators group

5. **Event Logs**
   - Failed logon events (Event ID 4625)

6. **Network Configuration**
   - `ipconfig /all`
   - `arp -a`

### Linux
1. **Network Connections**
   - Established connections
   - Listening ports

2. **Processes and Services**
   - Process tree
   - Running services

3. **Cron Jobs**
   - Root crontab entries

4. **User Accounts**
   - `/etc/passwd`
   - Active sessions

5. **Logs**
   - Failed SSH logon attempts from `journalctl`

6. **Network Configuration**
   - `ip addr`
   - Neighbor/ARP table

## Output Structure

### Windows
```text
C:\Users\<YourUser>\ThreatHunting\<ComputerName>_YYYY-MM-DD\
```

### Linux
```text
$HOME/threat_hunting_logs/<ComputerName>_YYYY-MM-DD/
```

Example:

```text
C:\Users\hunter\ThreatHunting\WS01_2026-04-01\
├── established_connections.txt
├── listening_ports.txt
├── process_list_verbose.txt
├── wmic_process_details.txt
├── wmic_running_services.txt
├── scheduled_tasks_all.txt
├── local_users.txt
├── local_admins.txt
├── event_failed_logons.txt
├── network_adapter_config.txt
└── arp_table.txt
```

## Requirements

### Windows
- PowerShell 5.1 or later
- Appropriate permissions to run local commands
- For remote execution with WinRM:
  - PowerShell remoting enabled
  - Network access to target
  - Valid credentials

### Linux
- PowerShell 7+ for best compatibility
- Utilities available on target system such as:
  - `ss`
  - `grep`
  - `ps`
  - `systemctl`
  - `crontab`
  - `journalctl`
  - `ip`

### Remote Execution Notes
- **WinRM** is used for standard PowerShell remoting to Windows systems
- **SSH** can be used where PowerShell over SSH is configured
- Remote collection requires valid access and appropriate privileges on the target host

## Usage

## Run the Script

Start the script in PowerShell:

```powershell
.\ThreatHunting.ps1
```

You will be prompted to choose:

- **Local** or **Remote** execution
- The hunt category to run

## Menu Options

```text
1. Network Connections
2. Processes and Services
3. Scheduled Tasks / Cron Jobs
4. User Accounts
5. Logs (Event Logs / Journal)
6. Network Configuration
7. RUN ALL CHECKS
Q. Quit
```

## Example: Local Execution

1. Run the script:
   ```powershell
   .\ThreatHunting.ps1
   ```

2. Choose:
   ```text
   (L)ocal
   ```

3. Choose:
   ```text
   7
   ```

This will run all checks on the local machine and save the results into the output folder.

## Example: Remote Execution with WinRM

1. Run the script:
   ```powershell
   .\ThreatHunting.ps1
   ```

2. Choose:
   ```text
   (R)emote
   ```

3. Enter one or more hostnames or IPs:
   ```text
   Server1,192.168.1.50
   ```

4. Enter credentials when prompted

5. Choose protocol:
   ```text
   W
   ```

6. Choose a hunt category or `7` for all checks

## Example: Remote Execution with SSH

If PowerShell remoting over SSH is configured:

1. Run the script
2. Choose remote mode
3. Enter target hostnames
4. Supply credentials
5. Choose:
   ```text
   S
   ```

## What the Script Does

At runtime, the script:

1. Detects whether the target system is Windows or Linux
2. Creates the base log folder if it does not already exist
3. Creates a subfolder using:
   - Computer name
   - Current date
4. Runs the selected hunt commands
5. Writes each command's output to a separate text file

## Error Handling

The script includes basic error handling:

- Creates folders with `-Force`
- Writes command failures into output files where possible
- Displays execution errors in the console

If a command fails, review:

- Your privileges
- Remote connectivity
- Whether the required utility exists on the target system
- Whether the target supports the selected remoting method

## Security Considerations

- Run only on systems you are authorized to assess
- Remote execution requires credentials and access rights
- Output may contain sensitive host and user data
- Review and protect collected artifacts appropriately
- Consider encrypting or securely storing hunt results

## Recommended Improvements

Some optional enhancements you may want to add later:

- Parameterized non-interactive mode
- CSV or JSON output
- Transcript logging
- Compression of collected artifacts
- Hashing of result files
- Additional Windows event collection
- Additional Linux log collection
- IOC matching or enrichment
- Centralized collection to a share or S3-compatible bucket

## Known Considerations

- `wmic` is deprecated on some modern Windows systems, though it may still work
- Linux log collection assumes `sshd.service` and `journalctl` are present
- SSH remoting may need adjustment depending on your PowerShell and SSH configuration
- Some commands require elevated privileges to return full results

## Suggested Repository Layout

```text
.
├── ThreatHunting.ps1
├── README.md
└── LICENSE
```

## Disclaimer

This script is intended for defensive security, system administration, and authorized threat hunting purposes only. Use it only in environments where you have explicit permission.
