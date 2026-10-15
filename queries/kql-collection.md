# 📘 KQL Query Collection  

> **Query status:** Historical, illustrative KQL only; not executed against a live SIEM.
> Verify required data connector, table names, columns, and logic against your actual environment before use.

A lightweight set of reusable KQL queries commonly used during threat hunting across Windows, Network, and Cloud environments.

---

## 🔍 1. Identify New Processes (Last 24 Hours)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize count() by FileName
| sort by count_ desc
```

---

## 🔍 2. Suspicious PowerShell Usage
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "IEX", "Invoke-")
| project Timestamp, DeviceName, ProcessCommandLine
```

---

## 🔍 3. Top Failed Login Sources (Brute-Force Indicator)
```kql
SigninLogs
| where ResultType != 0
| summarize Failures=count() by IPAddress
| sort by Failures desc
```

---

## 🔍 4. Newly Installed Software (Past 7 Days)
```kql
DeviceTvmSoftwareInventoryChangeEvents
| where Timestamp > ago(7d)
| project Timestamp, SoftwareName=NewValue, ChangeType
```

---

## 🔍 5. Unusual Outbound Ports
```kql
DeviceNetworkEvents
| summarize count() by RemotePort
| where RemotePort > 1024 and count_ > 50
| sort by count_ desc
```

---

## 🔍 6. Large DNS Query Volumes (Beaconing Indicator)
```kql
DnsEvents
| summarize Count=count() by QueryName
| where Count > 100
| sort by Count desc
```

---

## 🔍 7. Suspicious OAuth App Consents (M365)
```kql
AuditLogs
| where OperationName == "Consent to application"
| project TimeGenerated, InitiatedBy, ConsentInfo=TargetResources
```

---

## 🔍 8. Rarely Seen Process Execution
```kql
DeviceProcessEvents
| summarize Seen=count() by FileName
| where Seen < 5
| project FileName, Seen
```

---

## 🔍 9. Network Connections to Known Hosting Providers
```kql
DeviceNetworkEvents
| where RemoteUrl matches regex @"(aws|azure|digitalocean|linode)\.(com|net)"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP
```

---

## 🧑‍💻 Usage Notes
- Use these queries to pivot quickly during investigations  
- Modify `ago()` ranges based on your environment  
- Combine queries for deeper correlation hunts  

---
