

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nicholasmagner/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some n3bulas may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of n3bulas discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it, and discovered what looks like to be the user “n3bula” downloading a Tor installer. User then did something that created many Tor files to the desktop and the creation of the file “tor-shopping-list.txt” on the desktop.  These events started at Dec 1, 2024 8:33:43 PM.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "lab-test-n3bula"
| where InitiatingProcessAccountName == "n3bula"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-12-02T01:34:00.7166522Z)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, Account = InitiatingProcessAccountName

```
<img width="1038" height="350" alt="image" src="https://github.com/user-attachments/assets/b0852f0f-99a4-42b5-878c-2fb551163682" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string ”tor-browser-windows-x86_64-portable-15.0.2.exe”. Based on the logs returned, at Dec 1, 2025 8:33:43 PM, an n3bula on the “lab-test-n3bula” device ran the file tor-browser-windows-x86_64-portable-15.0.2.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "lab-test-n3bula"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1051" height="198" alt="image" src="https://github.com/user-attachments/assets/ba1584e5-2daa-4c7e-b7ac-436d65a67c01" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “n3bula” actually opened the tor browser.  There was evidence that they did open it at Dec 1, 2025 8:34:22 PM.  There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "lab-test-n3bula"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1021" height="406" alt="image" src="https://github.com/user-attachments/assets/287b7d96-3a96-4947-9fa5-0238a1b7b91d" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

On December 1, 2025 at 8:34 PM, the user account ‘n3bula’ on the device ‘lab-test-n3bula’ successfully made a network connection. The program that initiated the connection was tor.exe, located in the user’s Tor Browser folder. It connected to the remote IP address 64.65.1.169 over port 443. The connection was initiated by the process tor.exe, located in the folder c:\users\n3bula\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "lab-test-n3bula"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1015" height="419" alt="image" src="https://github.com/user-attachments/assets/6eae2798-8294-4a20-8cfe-6452aff2bf84" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Dec 1, 2025 8:33:43 PM`
- **Event:** The user "n3bula" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.2.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\n3bula\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Dec 1, 2025 8:34:00 PM`
- **Event:** The user "n3bula" executed the file `tor-browser-windows-x86_64-portable-15.0.2.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.2.exe /S`
- **File Path:** `C:\Users\n3bula\Downloads\tor-browser-windows-x86_64-portable-15.0.2.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Dec 1, 2025 8:34:22 PM`
- **Event:** User "n3bula" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\n3bula\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Dec 1, 2025 8:34:36 PM`
- **Event:** A network connection to IP `94.130.89.176` on port `9030` by user "n3bula" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\n3bula\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Dec 1, 2025 8:34:34 PM` - Connected to `64.65.1.169` on port `443`.
  - `Dec 1, 2025 8:34:25 PM` - Local connection to `127.0.0.1` on port `9151`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "n3bula" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Dec 1, 2025 8:41:50 PM`
- **Event:** The user "n3bula" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\n3bula\Desktop\tor-shopping-list.txt`

---

## Summary

Between 8:33 PM and 8:42 PM on December 1, 2025, the user account “n3bula” intentionally installed, launched, and used TOR Browser on the workstation “lab-test-n3bula.” Evidence shows that the TOR installer was executed from the user’s Downloads directory, TOR binaries were deployed onto the desktop, and multiple processes related to tor.exe and firefox.exe were launched. Network logs confirm successful outbound connections to TOR entry nodes and continued encrypted TOR traffic over known TOR ports. Additional file creation activity occurred during the same window, indicating continued user interaction. Overall, the activity demonstrates deliberate and unauthorized use of TOR to bypass corporate monitoring controls. Management should be notified and the workstation isolated for further investigation.

---

## Response Taken

TOR usage was confirmed on the endpoint `lab-test-n3bula` by the user `n3bula`. The device was isolated, and the user's direct manager was notified.

---
