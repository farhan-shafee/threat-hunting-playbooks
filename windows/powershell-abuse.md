# 🪟 Windows Hunt: PowerShell Abuse  

> **Query status:** Historical, illustrative KQL only; not executed against a live SIEM.
> Verify required data connector, table names, columns, and logic against your actual environment before use.

## 🎯 Objective  
Identify suspicious PowerShell activity that may indicate execution of malicious scripts, recon, credential theft, or lateral movement.

---

## 🔎 Key Indicators  
- Excessive PowerShell execution  
- Base64-encoded commands  
- PowerShell spawned by unusual parent processes (WINWORD, EXCEL, Wscript)  
- ScriptBlock logging showing obfuscation  
- PowerShell remoting misuse  

---

## 🧪 Hunt Queries (KQL)

### **1. Base64 Encoded Commands**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "encodedcommand"
```

---

### **2. Obfuscated Commands**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("^", ">", "+", "Invoke-", "$(", "FromBase64String")
```

---

### **3. Suspicious Parent Process**
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName in ("WINWORD.EXE", "EXCEL.EXE", "wscript.exe", "cscript.exe")
```

---

## 👨‍💻 Analyst Workflow  
1. Review PowerShell command line for obfuscation  
2. Check if parent process is suspicious (macro → PowerShell)  
3. Decode Base64 content  
4. Inspect ScriptBlock logs for hidden behavior  
5. Check for lateral movement commands (WinRM, WMI, PSRemoting)  
6. Escalate if credential theft or payload execution detected  

---

## 🧩 MITRE ATT&CK Mapping  
| Technique | Description |
|----------|-------------|
| **T1059.001** | PowerShell |
| **T1059** | Command Execution |
| **T1027** | Obfuscated/Encoded Commands |
| **T1569.002** | Remote Service Execution |

---

## ☠️ Common Malicious Patterns  
- `IEX (New-Object Net.WebClient).DownloadString(...)`  
- `Invoke-Mimikatz`  
- `FromBase64String(`  
- `Invoke-Expression`  
- `-WindowStyle Hidden`  
