# Phishing Case Study: “Open Case” Email

This repository documents a controlled detonation of a phishing email that delivered a disguised remote-access tool (ScreenConnect) through a malicious EXE masquerading as a PDF viewer.

## Overview
- **Phish lure:** Email claiming the recipient had a pending court case.
- **Malicious link:** Redirect through Google → `orphanageatd[.]org/court/PdfEdgeViewer.exe`
- **Payload:** Legitimate `ScreenConnect.ClientSetup.exe` renamed to `PdfEdgeViewer.exe`
- **Outcome:** Installation of a ScreenConnect remote access client, beaconing to relay infrastructure.

---

## Timeline

### Step 1 – Link & Redirect
- Email contained a “here” link → redirected via Google → **orphanageatd[.]org**
- Host downloaded `PdfEdgeViewer.exe` over HTTPS

![Redirect Notice](/Redirect_Notice.png)

### Step 2 – Defender/SmartScreen Block
- Microsoft SmartScreen flagged the EXE
- Outlook revealed **original name: ScreenConnect.ClientSetup.exe**

![SmartScreen](/SmartScreen_Block.png)

### Step 3 – Execution
- Executing `PdfEdgeViewer.exe` dropped and installed `ScreenConnect.ClientSetup.msi`
- ProcMon logs show registry edits to **HKCU\Internet Settings** (proxy/intranet tweaks for stable C2)

### Step 4 – C2 Connections
- DNS query to: `instance-t68c6n-relay.screenconnect[.]com`
- Established TLS connection to **15.204.43.235**

![TCPView](/tcpview.png)

---

## Findings

### DNS / Network
- **Phish delivery:** orphanageatd[.]org → 184.154.115.26
- **C2:** instance-t68c6n-relay.screenconnect[.]com → 15.204.43.235
- SmartScreen/Defender telemetry fired as expected

### ProcMon
- Dropped: `ScreenConnect.ClientSetup.msi` (~13 MB)
- Modified registry under HKCU to disable proxy auto-detection & treat intranet as trusted
- Installed as persistent service: **ScreenConnect Client**

### TCPView
- Outbound session: `ScreenConnect.ClientService.exe` → 15.204.43.235:443

---

## Indicators of Compromise (IOCs)

| Type      | Value |
|-----------|-------|
| URL       | `https[:]//orphanageatd[.]org/court/PdfEdgeViewer.exe` |
| File      | `PdfEdgeViewer.exe` (renamed `ScreenConnect.ClientSetup.exe`) |
| Dropped   | `ScreenConnect.ClientSetup.msi` |
| Domain    | `instance-t68c6n-relay.screenconnect[.]com` |
| IP        | `15.204.43.235` |
| Registry  | HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap |
| Registry  | HKCU\...\Internet Settings\Connections\DefaultConnectionSettings |

---

## Artifacts

All supporting files are provided for validation and reproduction:

- [Wireshark DNS results](dns_results.csv)
- [Wireshark HTTP results](http_results.csv)
- [Wireshark TLS results](tls_results.csv)
- [TCPView logs](tcpview.csv)
- [ProcMon logs](Logfile.csv)
- [Packet capture](payload_test-2.pcapng)

---

## Conclusion
This phishing case demonstrates how attackers can repurpose legitimate remote-access tools (RATs) for persistence. By disguising a **ScreenConnect client installer** as a “PDF viewer,” attackers bypass user suspicion and gain full remote access once the EXE is run.

> Defensive note: SmartScreen correctly flagged this binary, but a user click-through would still lead to compromise.
