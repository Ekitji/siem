# Procmon Boot Logging & Analysis for Security Research

**Process Monitor (Procmon)** from Sysinternals is a powerful tool for tracing **file, registry, and process activity**, including **SYSTEM-level operations during boot**. This workflow is commonly used in **privilege escalation research**, malware analysis, and endpoint monitoring.

---

## 1️⃣ Enable Boot Logging

1. Download and run **Procmon** as Administrator.
2. Go to **Options → Enable Boot Logging**.
3. Click **OK** and reboot the system.  
   Procmon will record all activity during boot, including early SYSTEM processes and service startups.

---

## 2️⃣ Collect & Open Boot Log

1. After boot, launch Procmon as Administrator.
2. Procmon will prompt to **save the boot log** (`.PML` file). Save it to a secure location.
3. The log will automatically load for analysis.

> **Tip:** Boot logs can be very large (hundreds of MBs to several GBs), so consider using filters to reduce noise.

---

## 3️⃣ Save PML to CSV

For sharing or automated analysis:

1. Open the boot log `.PML` in Procmon.
2. Go to **File → Save**.
3. In the **Save Configuration** window:
   - Select **“All Events”** or **“Filtered Events”** (filtered is recommended to reduce size)
   - Choose **CSV** as the file type.
   - Choose a filename and location.
4. Click **OK**.  
   You now have a CSV file that can be opened in Excel, Python, or other data analysis tools.

> **Pro tip:** Saving filtered events reduces file size and helps focus on relevant actions like `Process Create`, `CreateFile`, and `NAME NOT FOUND`.

---

## 4️⃣ Recommended Filters for Security Research

### Pre-boot / Live Capture Filters
Apply before enabling boot logging to reduce log size:

| Filter | Include/Exclude | Purpose |
|--------|----------------|---------|
| `Process Name` → `SYSTEM` | Include | Focus on privileged processes |
| `Result` → `NAME NOT FOUND` | Include | Detect potential binary/DLL planting or missing files |
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
| `Result = SUCCESS` | Focus on actual successful operations |
| `Result = NAME NOT FOUND` | Identify failed attempts, potential symlink or file planting opportunities |

> **Pro tip:** Combine `Result = NAME NOT FOUND` with `Process Name = SYSTEM` and `Path = Temp` to find privileged processes **searching for missing files** — a common pattern exploited in privilege escalation.

---

## 5️⃣ Analysis Workflow

1. Open the boot log in Procmon.
2. Apply post-boot filters iteratively.
3. Investigate suspicious patterns:
   - **SYSTEM process attempting to open files in writable directories**  
   - **Failed CreateFile or Load Image events (`NAME NOT FOUND`)**  
   - **Unexpected Process Create or registry modifications**
4. Save filtered `.PML` or export to CSV for sharing, automation, or reporting.

---

## 6️⃣ References / Resources

- **Procmon Documentation:** [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)  
- **Windows Object Manager & Reparse Points:** James Forshaw, Microsoft Security Research  
- **Red Team Blogs:** Practical examples of **privileged file operation tracing** using Procmon

---

## 7️⃣ Convert CSV to NDJSON and Split for SIEM

To prepare Procmon logs for ingestion into a SIEM:

1. Use a script (PowerShell provided one, or your preferred tool) to **convert CSV → NDJSON**.
   - Each row becomes a JSON object.
   - NDJSON (Newline-Delimited JSON) is optimized for bulk ingestion.
2. If the NDJSON file is very large:
   - Split it into smaller chunks (e.g., up to 1000 MB per file).
   - Ensure each chunk is valid NDJSON (one JSON object per line).
3. These splitted NDJSON files can now be ingested into SIEM tools like **Splunk, Elastic** without performance issues.

> **Tip:** Always validate the NDJSON after conversion and splitting to avoid ingestion errors.

---


✅ This README section provides **everything needed to run boot logging, apply security-research-oriented filters, and export events for analysis**, safely and efficiently.
