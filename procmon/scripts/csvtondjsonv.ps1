$Source = $PSScriptRoot # Run this script in same directory as your csv files

Add-Type -AssemblyName "Microsoft.VisualBasic"

# Use yesterday's date for all timestamps
$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
Write-Host "Using date: $yesterday for all timestamps" -ForegroundColor Cyan

Add-Type -TypeDefinition @'
using System;
using System.Text;

public static class NdjsonBuilder {

    public static string EscapeValue(string s) {
        if (s == null) return "null";
        var sb = new StringBuilder(s.Length + 4);
        sb.Append('"');
        foreach (char c in s) {
            switch (c) {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                case '\t': sb.Append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.AppendFormat("\\u{0:x4}", (int)c);
                    } else {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    // Converts "07:23:49,0697185" + "2024-01-15" to "2024-01-15T07:23:49.069Z"
    public static string FormatTimestamp(string timeValue, string date) {
        if (string.IsNullOrEmpty(timeValue)) return "null";
        try {
            string normalized = timeValue.Replace(',', '.');
            TimeSpan ts = TimeSpan.Parse(normalized);
            int ms = ts.Milliseconds;
            return '"' + date + "T" + ts.ToString(@"hh\:mm\:ss") + "." + ms.ToString("000") + "Z\"";
        }
        catch {
            return EscapeValue(timeValue);
        }
    }

    public static string BuildRow(string[] escapedHeaders, string[] fields, int headerCount, int timeColIndex, string date) {
        var sb = new StringBuilder(256);
        sb.Append('{');
        for (int i = 0; i < headerCount; i++) {
            if (i > 0) sb.Append(',');
            sb.Append(escapedHeaders[i]);
            sb.Append(':');
            if (i < fields.Length && fields[i] != null) {
                if (i == timeColIndex) {
                    sb.Append(FormatTimestamp(fields[i], date));
                } else {
                    sb.Append(EscapeValue(fields[i]));
                }
            } else {
                sb.Append("null");
            }
        }
        sb.Append('}');
        return sb.ToString();
    }
}
'@ -Language CSharp

$list = Get-ChildItem -Path $Source -Filter "*.csv"

foreach ($file in $list) {
    $csvPath    = $file.FullName
    $baseName   = $file.BaseName
    $ndjsonPath = Join-Path $Source "$baseName.ndjson"

    Write-Host "`nProcessing: $($file.Name)" -ForegroundColor Cyan
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $parser = $null
    $writer = $null

    try {
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($csvPath, [System.Text.Encoding]::UTF8)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(",")
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $true

        if ($parser.EndOfData) {
            Write-Host "  [!] File is empty, skipping." -ForegroundColor Yellow
            continue
        }

        $headers     = $parser.ReadFields()
        $headerCount = $headers.Count

        # Find timestamp column and rename it to @timestamp
        # Works for Elastic (native date field) and Splunk (recognized as event time)
        $timeColIndex = -1
        for ($i = 0; $i -lt $headerCount; $i++) {
            if ($headers[$i] -match "Time") {
                $timeColIndex  = $i
                $originalName  = $headers[$i]
                $headers[$i]   = "@timestamp"
                Write-Host "  [+] Renamed '$originalName' -> '@timestamp' at index $i" -ForegroundColor DarkCyan
                break
            }
        }
        if ($timeColIndex -eq -1) {
            Write-Host "  [!] No timestamp column found - all fields written as-is" -ForegroundColor Yellow
        }

        # Pre-escape all header names once
        $escapedHeaders = [string[]]($headers | ForEach-Object { [NdjsonBuilder]::EscapeValue($_) })

        Write-Host "  [+] Columns ($headerCount): $($headers -join ', ')" -ForegroundColor DarkCyan
        Write-Host "  [+] Reading and converting CSV..." -ForegroundColor Yellow

        $rows       = [System.Collections.Generic.List[string]]::new(30000000)
        $rowCount   = 0
        $errorCount = 0

        while (-not $parser.EndOfData) {
            try {
                $fields = $parser.ReadFields()
                if (-not $fields) { continue }

                $rows.Add([NdjsonBuilder]::BuildRow($escapedHeaders, $fields, $headerCount, $timeColIndex, $yesterday))

                $rowCount++
                if ($rowCount % 500000 -eq 0) {
                    $elapsed = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
                    $rate    = [math]::Round($rowCount / $stopwatch.Elapsed.TotalSeconds, 0)
                    Write-Host "  Rows: $($rowCount.ToString('N0')) | $($rate.ToString('N0')) rows/sec | ${elapsed}s elapsed" -ForegroundColor Yellow
                }
            }
            catch {
                $errorCount++
                Write-Host "  [!] Skipped malformed row near line $($parser.LineNumber): $_" -ForegroundColor DarkYellow
            }
        }

        $elapsed = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        Write-Host "  [+] Read complete: $($rowCount.ToString('N0')) rows in ${elapsed}s - writing to disk..." -ForegroundColor Cyan

        $writer = [System.IO.StreamWriter]::new($ndjsonPath, $false, [System.Text.Encoding]::UTF8, 1048576)
        foreach ($line in $rows) {
            $writer.WriteLine($line)
        }
        $writer.Flush()

        $stopwatch.Stop()
        $totalTime = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        $rate      = [math]::Round($rowCount / $stopwatch.Elapsed.TotalSeconds, 0)

        Write-Host "  [+] Done. $($rowCount.ToString('N0')) rows written to: $ndjsonPath" -ForegroundColor Green
        Write-Host "  [+] Total time: ${totalTime}s at avg $($rate.ToString('N0')) rows/sec" -ForegroundColor Green

        if ($errorCount -gt 0) {
            Write-Host "  [!] $errorCount rows skipped due to errors" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [*] Fatal error processing $($file.Name): $_" -ForegroundColor Red
    }
    finally {
        if ($parser) { $parser.Close(); $parser.Dispose() }
        if ($writer)  { $writer.Close(); $writer.Dispose() }
        $rows = $null
        [GC]::Collect()
    }
}

Write-Host "`nAll done." -ForegroundColor Cyan
