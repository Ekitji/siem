$sourceFile   = Get-ChildItem -Path $PSScriptRoot -Filter '*.ndjson' | Sort-Object Name | Select-Object -First 1
$outputDir    = Join-Path $PSScriptRoot 'splitted'
$maxSizeBytes = 970MB

if (-not $sourceFile) {
    Write-Host "No .ndjson file found in $PSScriptRoot" -ForegroundColor Red
    exit 1
}

$baseName = $sourceFile.BaseName

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$sw         = [System.Diagnostics.Stopwatch]::StartNew()
$fileNumber = 1
$lineCount  = 0
$totalLines = 0
$fileBytes  = 0
$reader     = $null
$writer     = $null

Write-Host "Starting size-based split: max $($maxSizeBytes / 1MB)MB per file" -ForegroundColor Cyan
Write-Host "Source: $($sourceFile.FullName)" -ForegroundColor Cyan
Write-Host "Output: $outputDir`n" -ForegroundColor Cyan

function New-SplitWriter {
    param($number, $dir, $baseName)
    $fileName = "{0}_part{1:000}.ndjson" -f $baseName, $number
    $filePath = Join-Path $dir $fileName
    Write-Host "  Opening: $fileName" -ForegroundColor Yellow
    return [System.IO.StreamWriter]::new($filePath, $false, [System.Text.Encoding]::UTF8, 1048576)
}

function Close-SplitWriter {
    param($w, $bytes, $lines, $total, $sw)
    $w.Flush()
    $w.Close()
    $w.Dispose()
    $sizeMB  = [math]::Round($bytes / 1MB, 1)
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $rate    = if ($sw.Elapsed.TotalSeconds -gt 0) {
                   [math]::Round($total / $sw.Elapsed.TotalSeconds, 0)
               } else { 0 }
    Write-Host "  Closed:  $($lines.ToString('N0')) rows | ${sizeMB}MB | total so far: $($total.ToString('N0')) rows | $($rate.ToString('N0')) rows/sec | ${elapsed}s" -ForegroundColor Green
}

try {
    $reader = [System.IO.StreamReader]::new($sourceFile.FullName, [System.Text.Encoding]::UTF8, $true, 1048576)
    $writer = New-SplitWriter $fileNumber $outputDir $baseName

    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { continue }

        $lineBytes = [System.Text.Encoding]::UTF8.GetByteCount($line) + 2

        if ($fileBytes -gt 0 -and ($fileBytes + $lineBytes) -gt $maxSizeBytes) {
            Close-SplitWriter $writer $fileBytes $lineCount $totalLines $sw
            $fileNumber++
            $lineCount = 0
            $fileBytes = 0
            $writer    = New-SplitWriter $fileNumber $outputDir $baseName
        }

        $writer.WriteLine($line)
        $fileBytes  += $lineBytes
        $lineCount++
        $totalLines++
    }

    if ($lineCount -gt 0) {
        Close-SplitWriter $writer $fileBytes $lineCount $totalLines $sw
        $writer = $null
    }
}
catch {
    Write-Host "[*] Fatal error: $_" -ForegroundColor Red
}
finally {
    if ($reader) { $reader.Close(); $reader.Dispose() }
    if ($writer) { $writer.Close(); $writer.Dispose() }
}

$sw.Stop()
$totalTime = [math]::Round($sw.Elapsed.TotalSeconds, 1)
$rate      = if ($sw.Elapsed.TotalSeconds -gt 0) {
                 [math]::Round($totalLines / $sw.Elapsed.TotalSeconds, 0)
             } else { 0 }

Write-Host "`nSplit complete."         -ForegroundColor Cyan
Write-Host "  Total rows  : $($totalLines.ToString('N0'))" -ForegroundColor Cyan
Write-Host "  Total files : $fileNumber"                   -ForegroundColor Cyan
Write-Host "  Total time  : ${totalTime}s at avg $($rate.ToString('N0')) rows/sec" -ForegroundColor Cyan
Write-Host "  Files in    : $outputDir"                    -ForegroundColor Cyan