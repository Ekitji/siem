# ── Configuration ─────────────────────────────────────────────────────────────

$InputFolder = "C:\Users\user\accessenumfiles"
$OutputFile  = "C:\Users\user\accessenumfiles\AccessEnumout.ndjson"

# ──────────────────────────────────────────────────────────────────────────────

$timestamp = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

# Ensure output directory exists
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($OutputFile)) | Out-Null

$writer = [System.IO.StreamWriter]::new($OutputFile, $false, [System.Text.Encoding]::UTF8)

$txtFiles = [System.IO.Directory]::GetFiles($InputFolder, "*.txt")

if ($txtFiles.Count -eq 0) {
    Write-Host "No .txt files found in $InputFolder" -ForegroundColor Red
    $writer.Dispose()
    exit 1
}

$totalRecs = 0
$sb        = [System.Text.StringBuilder]::new(512)

foreach ($filePath in $txtFiles) {
    $sourceFile = [System.IO.Path]::GetFileName($filePath)
    Write-Host "Processing: $sourceFile" -ForegroundColor Yellow

    $reader = [System.IO.StreamReader]::new($filePath, [System.Text.Encoding]::Unicode)

    # Skip header line
    $null = $reader.ReadLine()

    $detectedType = $null

    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Split on tab, strip surrounding quotes
        $fields = $line.Split("`t")
        if ($fields.Length -lt 4) { continue }

        $path  = $fields[0].Trim('"')
        $read  = $fields[1].Trim('"')
        $write = $fields[2].Trim('"')
        $deny  = $fields[3].Trim('"')

        # Detect source type once per file
        if ($null -eq $detectedType) {
            if ($path.StartsWith("HK")) { $detectedType = "registry" }
            elseif ($path.Length -gt 1 -and $path[1] -eq ':') { $detectedType = "filesystem" }
            else { $detectedType = "unknown" }
        }

        # Path depth
        $depth = ($path.Split('\').Length - 1)

        # Flags
        $accessDenied = ($read -eq "Access Denied" -or $write -eq "Access Denied" -or $deny -eq "Access Denied")
        $errorMsg     = if ($read -eq "The handle is invalid." -or $write -eq "The handle is invalid." -or $deny -eq "The handle is invalid.") { "The handle is invalid." } else { "" }

        # Split principals into JSON arrays inline
        function ToJsonArray($raw) {
            $skip = @("Access Denied", "The handle is invalid.", "")
            if ($raw -in $skip) { return "[]" }
            $parts = $raw.Split(',') | ForEach-Object {
                $t = $_.Trim()
                if ($t -ne "") { '"' + $t.Replace('\', '\\').Replace('"', '\"') + '"' }
            }
            return "[" + ($parts -join ",") + "]"
        }

        $readArr  = ToJsonArray $read
        $writeArr = ToJsonArray $write
        $denyArr  = ToJsonArray $deny

        # Escape backslashes and quotes in path for JSON
        $pathJson      = $path.Replace('\', '\\').Replace('"', '\"')
        $sourceFileJson = $sourceFile.Replace('"', '\"')
        $errorMsgJson  = $errorMsg.Replace('"', '\"')

        $null = $sb.Clear()
        $null = $sb.Append('{"@timestamp":"').Append($timestamp)
        $null = $sb.Append('","source_file":"').Append($sourceFileJson)
        $null = $sb.Append('","source_type":"').Append($detectedType)
        $null = $sb.Append('","path":"').Append($pathJson)
        $null = $sb.Append('","path_depth":').Append($depth)
        $null = $sb.Append(',"read_principals":').Append($readArr)
        $null = $sb.Append(',"write_principals":').Append($writeArr)
        $null = $sb.Append(',"deny_principals":').Append($denyArr)
        $null = $sb.Append(',"access_denied":').Append($accessDenied.ToString().ToLower())
        $null = $sb.Append(',"error":"').Append($errorMsgJson).Append('"}')

        $writer.WriteLine($sb.ToString())
        $totalRecs++
    }

    $reader.Dispose()
}

$writer.Flush()
$writer.Dispose()

Write-Host "Done. $totalRecs records written to $OutputFile" -ForegroundColor Green
