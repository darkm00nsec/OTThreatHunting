# Threat Hunting Script

A cross-platform PowerShell threat hunting script for **Windows** and **Linux** that supports:

- **Local execution**
- **Remote execution**
  - **WinRM** for Windows targets
  - **SSH** where PowerShell remoting over SSH is configured
- **CSV output for all functions**
- **OT / ICS protocol port detection**
- **Organized output folders by computer name and date**

This script is intended for **authorized defensive security, threat hunting, and system administration** use.

---

## Features

- Runs on **Windows** and **Linux**
- Supports **local** and **remote** collection
- Automatically creates output folders
- Exports all results as **CSV**
- Can run a **single hunt category** or **all checks**
- Includes **OT protocol detection** for common ICS/OT ports
- Adds a simple **Suspicious** flag for OT findings involving non-private remote addresses

---

## Hunt Categories

### 1. Network Connections
Collects network socket data and exports:

- `established_connections.csv`
- `listening_ports.csv`
- `all_network_connections.csv`

### 2. Processes and Services
Collects:

- Running processes
- Running services

Exports:

- `process_list.csv`
- `services.csv`

### 3. Scheduled Tasks / Cron Jobs
Collects:

- **Windows:** Scheduled tasks
- **Linux:** Root cron entries

Exports:

- **Windows:** `scheduled_tasks.csv`
- **Linux:** `cron_jobs.csv`

### 4. User Accounts
Collects:

- **Windows:** Local users and local administrators
- **Linux:** `/etc/passwd` users and active sessions

Exports:

- **Windows:** `local_users.csv`, `local_admins.csv`
- **Linux:** `all_users.csv`, `active_sessions.csv`

### 5. Logs (Event Logs / Journal)
Collects:

- **Windows:** Failed logons from Security log (`Event ID 4625`) from the last 30 days
- **Linux:** Failed SSH logon lines from `journalctl`

Exports:

- **Windows:** `event_failed_logons.csv`
- **Linux:** `journal_failed_ssh_logons.csv`

### 6. Network Configuration
Collects:

- **Windows:** IP configuration and ARP/neighbor data
- **Linux:** Interface addressing and neighbor data

Exports:

- `network_adapter_config.csv`
- `arp_table.csv`

### 7. OT Protocol Port Matches
Checks active/listening connections against a built-in OT protocol port reference list and exports:

- `ot_protocol_reference_ports.csv`
- `ot_protocol_matches.csv`

### 8. RUN ALL CHECKS
Runs every function above for the target host.

---

## Supported OT / ICS Protocols

The script currently checks for these protocol ports:

- Modbus/TCP
- Siemens S7comm
- EtherNet/IP
- EtherNet/IP I/O
- DNP3
- OPC UA
- BACnet/IP
- PROFINET Context Management
- PROFINET RT Discovery
- PROFINET RT Control
- IEC 60870-5-104
- Tridium Fox
- Niagara Fox SSL
- OMRON FINS
- MELSEC
- IEC 61850 MMS
- CODESYS Gateway

> **Note:** This script performs **port-based OT detection**. It does **not** do deep packet inspection and will not detect non-port-based industrial traffic or confirm protocol content by payload.

---

## Output Structure

### Windows
```text
C:\Users\<YourUser>\ThreatHunting\<ComputerName>_YYYY-MM-DD\
```

### Linux
```text
$HOME/threat_hunting_logs/<ComputerName>_YYYY-MM-DD/
```

### Example
```text
C:\Users\<userprofile>\ThreatHunting\WS01_2026-04-01\
├── all_network_connections.csv
├── established_connections.csv
├── listening_ports.csv
├── process_list.csv
├── services.csv
├── scheduled_tasks.csv
├── local_users.csv
├── local_admins.csv
├── event_failed_logons.csv
├── network_adapter_config.csv
├── arp_table.csv
├── ot_protocol_reference_ports.csv
└── ot_protocol_matches.csv
```

Linux output will use the same date/host folder structure with Linux-specific CSV files such as `cron_jobs.csv`, `all_users.csv`, and `journal_failed_ssh_logons.csv`.

---

## Requirements

## Windows
- PowerShell **5.1 or later**
- Appropriate privileges to collect host data
- For remote execution with WinRM:
  - PowerShell remoting enabled
  - Network access to the target
  - Valid credentials
- Some commands may require administrator rights

## Linux
- PowerShell **7+ recommended**
- Utilities available on the target host, such as:
  - `ss`
  - `ip`
  - `systemctl`
  - `journalctl`
  - `who`
  - `bash`
  - `crontab`

## Remote Execution
- **WinRM** is used for standard PowerShell remoting to Windows systems
- **SSH** can be used where PowerShell remoting over SSH is configured
- Remote collection requires valid credentials and appropriate access rights

---

## Usage

Run the script in PowerShell:

```powershell
.\ThreatHunting.ps1
```

You will be prompted to choose:

- **Local** or **Remote**
- A hunt category

---

## Interactive Menu

```text
1. Network Connections
2. Processes and Services
3. Scheduled Tasks / Cron Jobs
4. User Accounts
5. Logs (Event Logs / Journal)
6. Network Configuration
7. OT Protocol Port Matches
8. RUN ALL CHECKS
Q. Quit
```

---

## Example: Local Execution

1. Run the script:
   ```powershell
   .\ThreatHunting.ps1
   ```

2. Choose:
   ```text
   L
   ```

3. Choose:
   ```text
   8
   ```

This runs all checks on the local machine and saves the CSV files to the output folder.

---

## Example: Remote Execution with WinRM

1. Run the script:
   ```powershell
   .\ThreatHunting.ps1
   ```

2. Choose:
   ```text
   R
   ```

3. Enter target hosts:
   ```text
   Server1,192.168.1.50
   ```

4. Enter credentials when prompted

5. Choose protocol:
   ```text
   W
   ```

6. Choose a menu option such as:
   ```text
   8
   ```

---

## Example: Remote Execution with SSH

If PowerShell remoting over SSH is configured:

1. Run the script
2. Choose `R`
3. Enter target hosts
4. Enter credentials
5. Choose:
   ```text
   S
   ```

---

## CSV Output Notes

All functions now write **CSV** files to make the output easier to:

- ingest into SIEM platforms
- load into spreadsheets
- parse with PowerShell, Python, or Splunk/Elastic tooling
- pivot and filter during DFIR or CTI workflows

### Example OT CSV fields
`ot_protocol_matches.csv` may include fields such as:

- `Timestamp`
- `Computer`
- `Protocol`
- `OTProtocol`
- `Port`
- `LocalAddress`
- `LocalPort`
- `RemoteAddress`
- `RemotePort`
- `RemoteScope`
- `State`
- `PID`
- `ProcessName`
- `Suspicious`

### Suspicious flag
For OT findings, the script adds a basic `Suspicious` field:

- `YES` when the remote address appears to be **public or non-private**
- `NO` when the remote address appears to be **private, loopback, or expected internal scope**

This is only a simple heuristic and should not be treated as a final determination of malicious activity.

---

## What the Script Does

At runtime, the script:

1. Detects the target operating system
2. Creates the base output directory if needed
3. Creates a subfolder based on:
   - host name
   - current date
4. Runs the selected hunt category
5. Exports the results to one or more CSV files
6. Returns the output path for the run

---

## Error Handling

The script includes basic error handling:

- Auto-creates folders with `-Force`
- Writes a placeholder CSV row when no results are found
- Displays console errors during execution
- Uses `SilentlyContinue` for some commands to avoid full script failure

If a function fails, check:

- permissions
- remote connectivity
- PowerShell version
- module availability
- whether required Linux utilities are installed

---

## Security Considerations

- Use only on systems you are authorized to assess
- Collected output may contain sensitive host, user, service, and network data
- Protect the generated CSV files appropriately
- Use encrypted storage or transfer where appropriate
- Review OT findings carefully before taking action in production environments

---

## Known Considerations

- `Get-LocalUser`, `Get-LocalGroupMember`, `Get-ScheduledTask`, and some network-related commands may require administrative privileges on Windows
- Linux service and log collection depend on `systemd` / `journalctl`
- SSH remoting depends on the environment being configured correctly
- OT detection is **port-based** only
- Some Linux outputs are parsed from shell command output and may vary slightly by distribution

---

## Suggested Repository Layout

```text
.
├── ThreatHunting.ps1
├── README.md
└── LICENSE
```

---

## License

- MIT

---

## Disclaimer

This script is intended for defensive security, threat hunting, incident response support, and authorized administrative use only. Do not use it on systems or networks without explicit permission.

---

## Credit 

MrDuc in this article https://medium.com/@itpro677/hunting-threats-in-ot-environments-using-only-built-in-system-commands-no-tools-required-6adc80ef0ee2
