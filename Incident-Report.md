Security Incident Report --- FTP Data Exfiltration
1. Incident Information
  Field                Details
  Incident ID          INC-001
Analyst              Dalton McAuliffe
Report date          November 25, 2026
Incident category    Simulated data exfiltration
Potential severity   High
Status               Investigation complete; remediation recommended
Environment          NGT Academy controlled training lab
Evidence source      suspicious_activity.pcapng
2. Executive Summary
Network traffic analysis identified a simulated disclosure of an employee database through an insecure FTP service. The client at 10.0.2.19 successfully authenticated to the server at 10.0.2.20 using the username anonymous and an empty password.

The client retrieved employee_database.csv over an unencrypted TCP data connection. Wireshark reconstruction and Linux-based verification established a recovered file size of 130,442 bytes containing 1,000 synthetic employee records across 12 fields.

Potential severity is rated High because equivalent production data could expose sensitive personal and financial information. No actual production breach is established by this exercise.
3. Network Indicators
  Indicator                         Observed value
  Suspected attacker / FTP client   10.0.2.19
Affected FTP server               10.0.2.20
Server software                   FileZilla Server 1.5.1
Control connection                10.0.2.19:50080 → 10.0.2.20:21
Data connection                   10.0.2.20:49772 → 10.0.2.19:50082
TCP data stream                   202
Authentication                    Anonymous; empty password
Retrieved file                    employee_database.csv

These are lab-specific investigation indicators, not globally malicious IP addresses.
4. Incident Timeline
Times are relative to the packet capture, not wall-clock timestamps.
  Capture time / order                Observed activity
  Before 32.326 s                     Anonymous login accepted; initial directory listing

  32.326 s                            Client negotiates TCP data port 50082

  32.330 s                            Client requests employee_database.csv

  32.344 s                            Server initiates data connection and reports transfer starting

  32.344--32.354 s                    Data transfer, acknowledgments and connection closure observed

  32.344 s                            FTP server reports 226 Operation successful

  34.689 s                            Subsequent directory listing requested
37.772 s                            FTP session terminated
Times are rounded from the supplied packet screenshots; overlapping control and data events are expected.
5. Technical Findings and Evidence
  Finding                                     Supporting evidence
  Anonymous authentication accepted           [01 --- FTP control stream](01-FTP-Control-Stream.png)

  Empty password argument                     [06 --- Password analysis](06-FTP-Password-Analysis.png)

  Employee database requested                 [02 --- File retrieval](02-File-Retrieval.png)

  Data transferred to TCP port 50082          [03 --- TCP data stream](03-TCP-Data-Stream.png)

  Sensitive data categories identified        [04 --- Sanitized CSV headers](04-Recovered-Data-Redacted.png)
Record count, file size and hash verified   [05 --- Forensic verification](05-Forensic-Evidence-Verification.png)
The FTP PORT command specified 10,0,2,19,195,162, yielding destination port (195 × 256) + 162 = 50082. This distinguishes the data connection from the client control port 50080.

The FTP RETR request and 226 response, TCP stream analysis and reconstructed CSV support successful file retrieval.
6. Scope and Impact
- Recovered records: 1,000 (1,001 CSV lines including header).
- Recovered file size: 130,442 bytes (127.4 KiB).
- Data categories: names, email addresses, dates of birth, Social Security numbers, credit card numbers, addresses, telephone numbers and other personal fields.
- Security property affected: confidentiality. No evidence presented establishes integrity or availability impact.
If genuine production information were involved, potential consequences would include identity theft, financial fraud, privacy violations and regulatory exposure.
7. Evidence Integrity
SHA-256 of the recovered CSV:
cbe10a41e5215218f82730546f5dfbe02a87d3daab2c1a671ab7e00e38a70319
The recovered file size matches the TCP sequence-based payload calculation. The SHA-256 digest establishes a baseline for subsequent integrity checks; it does not independently establish authenticity or chain of custody.
8. Security Weaknesses and MITRE ATT&CK
Observed weaknesses include anonymous access, acceptance of an empty password, plaintext FTP and access to sensitive files. The underlying server configuration and authorization policy were not independently examined.

Potential technique: T1048.003 --- Exfiltration Over Unencrypted Non-C2 Protocol. This mapping is conditional on the simulated exfiltration scenario; the capture alone does not establish malicious intent or whether the protocol was used for command and control.
9. Recommended Incident Response
  Priority                Phase                   Recommended action
  P1                      Containment             Restrict FTP access, disable unnecessary anonymous authentication and preserve packet captures and server logs.

  P1                      Scoping                 Review additional FTP sessions, accessed files, endpoint telemetry and authorization records.

  P2                      Eradication             Replace plaintext FTP with SFTP or properly configured FTPS; enforce individual authentication and least-privilege permissions.

  P2                      Recovery                Validate secure configurations and authorized file access before restoring service.
P3                      Prevention              Implement network segmentation, data loss prevention and centralized SIEM monitoring.
These actions are recommendations, not remediation performed during the lab.
10. Detection Recommendations
- Alert on successful anonymous FTP authentication to sensitive servers.
- Correlate FTP file retrieval commands with sensitive filenames and associated data connections.
- Monitor unusual server-to-client transfer volumes and unexpected destinations.
- Collect FTP server logs and network telemetry in a SIEM such as Splunk.
Detection rules should be tested and tuned against authorized business activity before production deployment.
11. Conclusion and Limitations
The available evidence supports successful retrieval of the simulated employee database through anonymous, unencrypted FTP. The technical investigation is complete within the lab scope. Production root cause, authorization, attacker identity, additional affected systems and remediation effectiveness remain unverified.

The dataset is synthetic according to the lab context. Individual record values, the original PCAP and the recovered CSV are excluded from public documentation.

For the full technical methodology, see the [project README](README.md).
