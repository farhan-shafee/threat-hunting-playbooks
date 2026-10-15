# 🌐 Network Hunt: DNS Tunneling Detection

> **Query status:** Historical, illustrative KQL only; not executed against a live SIEM.
> Verify required data connector, table names, columns, and logic against your actual environment before use.

---

## 🎯 Objective
Detect potential DNS tunneling activity used for covert C2 communication or data exfiltration.

---

## 🔍 Key Indicators
- Long DNS query lengths  
- High-frequency DNS queries from a single host  
- Encoded or Base64-like subdomain patterns  
- Queries to suspicious or newly registered domains  
- DNS resolution that looks algorithmically generated  

---

## 🧪 Hunt Queries (KQL)

### **1. Long DNS Query Lengths**
```kql
DnsEvents
| where QueryLength > 60
| project Timestamp, DeviceName, QueryName, QueryType
```

---

### **2. High-Frequency DNS Queries**
```kql
DnsEvents
| summarize Count = count() by QueryName, DeviceName
| where Count > 50
| sort by Count desc
```

---

### **3. Encoded / Base64-like Subdomain Patterns**
```kql
DnsEvents
| where QueryName matches regex @"[A-Za-z0-9+/]{20,}"
| project Timestamp, DeviceName, QueryName
```

---

## 🕵️ Analyst Workflow
1. Check if queried domains are suspicious or newly registered  
2. Review subdomain patterns for Base64 or encoded data  
3. Identify internal hosts generating large DNS volumes  
4. Decode sample subdomains if possible  
5. Validate whether traffic matches DNS tunneling frameworks  
6. Escalate if covert C2 or exfiltration is suspected  

---

## 🧩 MITRE ATT&CK Mapping
- **T1071.004 – C2 Over DNS**  
- **T1048 – Exfiltration Over Alternative Protocol**  
- **T1568 – Dynamic Resolution**

---
