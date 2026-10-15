# 🪟 Windows Hunt: Suspicious Parent Process

> **Query status:** Historical, illustrative KQL only; not executed against a live SIEM.
> Verify required data connector, table names, columns, and logic against your actual environment before use.

## 🎯 Objective  
Identify malicious execution chains where legitimate apps launch system tools.

---

## 🔎 Key Indicators  
- Office apps spawning PowerShell  
- Wscript/Cscript launching cmd.exe  
- Browsers spawning PowerShell  
- Unexpected process inheritance  

---

## 🧪 Hunt Query (KQL)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in ("WINWORD.EXE", "EXCEL.EXE", "outlook.exe", "wscript.exe", "cscript.exe")
| where FileName in ("powershell.exe", "cmd.exe", "regsvr32.exe", "mshta.exe")
```

---

## 👨‍💻 Analyst Workflow  
1. Identify the document or script triggering execution  
2. Review associated command line  
3. Determine if macro or script abuse occurred  
4. Validate user intent  
5. Escalate if phishing → payload chain confirmed  

---

## 🧩 MITRE ATT&CK  
- **T1204 – User Execution**  
- **T1059 – Command Execution**  
- **T1566 – Phishing**  
