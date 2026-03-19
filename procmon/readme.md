# Procmon Boot Logging & SIEM Analysis for Security Research

**Process Monitor (Procmon)** from Sysinternals is a powerful tool for tracing **file, registry, and process activity**, including **SYSTEM-level operations during boot**. This workflow is commonly used in **privilege escalation research**, malware analysis, and endpoint monitoring.

---

## 1️⃣ Enable Boot Logging

1. Download and run **Procmon** as Administrator.
2. Go to **Options → Enable Boot Logging**.
3. Click **OK** and reboot the system.  
   Procmon will record all activity during boot, including early SYSTEM processes and service startups.

---

## 2️⃣ Collect & Open Boot Log

1. After boot, wait 5-10 minutes and then launch Procmon as Administrator.
2. Procmon will prompt to **save the boot log** (`.PML` file). Save it to a secure location.
3. The log will automatically load for analysis.

> **Tip:** Boot logs can be very large (hundreds of MBs to several GBs depending on how you capture it), which is normal, so consider using filters (Filter 1) provided in this repository to reduce some noise without excluding relevant events that we dont want to miss.

---

## 3️⃣ Save PML to CSV

For sharing or automated analysis:

1. Open the boot log `.PML` in Procmon.
2. **Make sure that atleast following columns exists**
   - Time of day
   - Image Path
   - Process Name
   - Command Line
   - Path
   - Operation
   - User Name
   - Result
   - Detail
   - Duration
   - PID
   - Parent PID
   
4. Go to **File → Save**.
5. In the **Save Configuration** window:
   - Select **“All Events”** or **“Filtered Events”** (filtered events using "Filter 1" is recommended to reduce size and noise)
   - Choose **CSV** as the file type.
   - Choose a filename and location.
6. Click **OK**.  
   You now have a CSV file that We will convert the CSV to NDJSON and ingest it to a SIEM. It could also be opened in Excel, Python, or other data analysis tools.

> **Pro tip:** Saving filtered events reduces file size and helps focus on relevant actions like `Path`, `User`, and `Result: NAME NOT FOUND`. To much exclusion filters will likely miss important events. Filter 1 is focusing on SYSTEM user and is excluding Registry Operations. 

---

## 4️⃣ Convert CSV to NDJSON and Split for SIEM

To prepare Procmon logs for ingestion into a SIEM:

1. Use the csvtondjsonv.ps1 script (powershell provided one) to **convert CSV → NDJSON**.
   - Each row becomes a JSON object.
   - NDJSON (Newline-Delimited JSON) is optimized for bulk ingestion.
2. If the NDJSON file is very large, greater than 1000MB/1GB:
   - Split it into smaller chunks using provided script splitndjson.ps1 (e.g., up to 1000 MB per file).
   - Ensure each chunk is valid NDJSON (one JSON object per line).
3. These splitted NDJSON files can now be ingested into SIEM tools like **Elastic** without performance issues. You can use provided script importtoelastic.ps1 to ingest the ndjson files using the Bulk API.

> **Tip:** Always validate the NDJSON after conversion and splitting to avoid ingestion errors.

---

## 5️⃣ Recommended Filters for Security Research

### Capture Filter
We want to capture as much as possible without excluding important events. We are more interested in SYSTEM user events.
Focusing on SYSTEM user will give you wide area of events to focus on. My good to go filter is focusing on SYSTEM user and excluding Registry related events (Filter 1 in Filters section). Be aware that we miss registry related events that could have vulnerabilities.

| Filter | Include/Exclude | Purpose |
|--------|----------------|---------|
| `Process Name` → `SYSTEM` | Include | Focus on privileged processes |
| `Result` → `NAME NOT FOUND` OR `PATH NOT FOUND` | Include | Detect potential binary/DLL planting or missing files |
| `Path` → `C:\Windows\Temp` | Include | Monitor temp directories and other user-writable directories often used by installers or malicious binaries |
| `Operation` → `CreateFile` | Include | Trace file reads/writes/deletes |
| `Operation` → `Process Create` | Include | Track execution of new processes |

### Post-boot / Analysis Filters
Apply after log capture to refine investigation:

| Filter | Purpose |
|--------|---------|
| `Process Name` → `cmd.exe` | Analyze scripts or shell commands run by SYSTEM |
| `Path contains .exe` | Identify executable launches |
| `Path contains .dll` | Detect DLL loads and potential hijacks |
| `Result = SUCCESS` | Focus on actual successful operations in User-writable paths, any file replacement allowed? |
| `Result = NAME NOT FOUND` | Identify failed attempts, potential symlink or file planting opportunities |
| `Result = PATH NOT FOUND` | Identify failed attempts, potential symlink or file planting opportunities |

> **Pro tip:** Combine `Result = NAME NOT FOUND` with `User = SYSTEM` and `Path = Temp` to find privileged processes **searching for missing files** — a common pattern exploited in privilege escalation.
>
> **SIEM Queries:** Procmon SIEM queries in the procmonsiemqueries.md file
> 

---

## 6️⃣ References / Resources

- **Finding PrivEsc with Procmon** PDF format https://bordplate.no/presentations/finding_privesc_with_procmon.pdf
- **Finding PrivEsc with Procmon** Video format [BSides Oslo 2019 - Vetle Hjelle - Finding Privilege Escalation with Procmon](https://www.youtube.com/watch?v=s-Vdt2-kZPc)
- **Finding Privilege Escalation Vulnerabilities in Windows using Process Monitor** https://web.archive.org/web/20220719145528/https://vuls.cert.org/confluence/display/Wiki/2021/06/21/Finding+Privilege+Escalation+Vulnerabilities+in+Windows+using+Process+Monitor
- **Procmon Documentation:** [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)  
- **Windows Object Manager & Reparse Points:** James Forshaw, Microsoft Security Research  
- **Red Team Blogs:** Practical examples of **privileged file operation tracing** using Procmon
- **FileDelete --> LPE PrivEsc with Procmon**  https://www.securitum.com/wipe_and_rise_how_deleting_files_on_windows_enables_lpe.html

✅ This README section provides **everything needed to run boot logging, apply security-research-oriented filters, and export events for analysis**, safely and efficiently.
