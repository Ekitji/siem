$elasticUrl = "http://127.0.0.1:9200"
$indexName  = "Indexname" # Name of the index
$ndjsonDir  = $PSScriptRoot # Run this script from same directory as your ndjson files
$batchSize  = 5000  # Documents per bulk request - tune up/down based on speed

$files = Get-ChildItem -Path $ndjsonDir -Filter "*.ndjson"

if ($files.Count -eq 0) {
    Write-Host "No NDJSON files found in $ndjsonDir" -ForegroundColor Red
    exit
}

Write-Host "Found $($files.Count) NDJSON file(s) to import" -ForegroundColor Cyan
Write-Host "Target : $elasticUrl/$indexName" -ForegroundColor Cyan
Write-Host "Batch  : $($batchSize.ToString('N0')) documents per request`n" -ForegroundColor Cyan

$actionLine   = '{"index":{}}'
$totalIndexed = 0
$totalFailed  = 0
$swTotal      = [System.Diagnostics.Stopwatch]::StartNew()

function Send-Batch {
    param($batch, $url, $index)

    $body = $batch -join "`n"
    $body += "`n"

    try {
        $response = Invoke-WebRequest `
            -Uri "$url/$index/_bulk?filter_path=errors" `
            -Method POST `
            -Headers @{ "Content-Type" = "application/x-ndjson" } `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
            -TimeoutSec 120 `
            -UseBasicParsing

        $result = $response.Content | ConvertFrom-Json
        return $result.errors
    }
    catch {
        Write-Host "      [*] Batch error: $_" -ForegroundColor Red
        return $true
    }
}

foreach ($file in $files) {
    Write-Host "Importing: $($file.Name)" -ForegroundColor Yellow
    $swFile     = [System.Diagnostics.Stopwatch]::StartNew()
    $reader     = $null
    $batch      = [System.Collections.Generic.List[string]]::new($batchSize * 2)
    $docCount   = 0
    $batchNum   = 0
    $fileFailed = 0

    try {
        $reader = [System.IO.StreamReader]::new($file.FullName, [System.Text.Encoding]::UTF8, $true, 1048576)

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $batch.Add($actionLine)
            $batch.Add($line)
            $docCount++

            if ($docCount -ge $batchSize) {
                $batchNum++
                $hasErrors = Send-Batch $batch $elasticUrl $indexName

                if ($hasErrors) {
                    $fileFailed += $docCount
                    Write-Host "  [!] Batch $batchNum had errors" -ForegroundColor DarkYellow
                } else {
                    $totalIndexed += $docCount
                }

                $elapsed = [math]::Round($swFile.Elapsed.TotalSeconds, 1)
                $rate    = [math]::Round(($totalIndexed + $fileFailed) / $swTotal.Elapsed.TotalSeconds, 0)
                Write-Host "  Batch $batchNum done | Total indexed: $($totalIndexed.ToString('N0')) | $($rate.ToString('N0')) docs/sec | ${elapsed}s" -ForegroundColor DarkCyan

                $batch.Clear()
                $docCount = 0
            }
        }

        # Send remaining documents in final partial batch
        if ($docCount -gt 0) {
            $batchNum++
            $hasErrors = Send-Batch $batch $elasticUrl $indexName
            if ($hasErrors) {
                $fileFailed += $docCount
                Write-Host "  [!] Final batch $batchNum had errors" -ForegroundColor DarkYellow
            } else {
                $totalIndexed += $docCount
            }
        }

        $swFile.Stop()
        $fileTime = [math]::Round($swFile.Elapsed.TotalSeconds, 1)
        $fileRate = [math]::Round($totalIndexed / $swTotal.Elapsed.TotalSeconds, 0)

        Write-Host "  [+] File done in ${fileTime}s | $batchNum batches | $($fileRate.ToString('N0')) docs/sec" -ForegroundColor Green
        if ($fileFailed -gt 0) {
            Write-Host "  [!] $($fileFailed.ToString('N0')) documents failed in this file" -ForegroundColor Yellow
            $totalFailed += $fileFailed
        }
    }
    catch {
        Write-Host "  [*] Fatal error on $($file.Name): $_" -ForegroundColor Red
    }
    finally {
        if ($reader) { $reader.Close(); $reader.Dispose() }
        $batch.Clear()
    }

    Write-Host ""
}

$swTotal.Stop()
$totalTime = [math]::Round($swTotal.Elapsed.TotalSeconds, 1)
$totalRate = [math]::Round($totalIndexed / $swTotal.Elapsed.TotalSeconds, 0)

Write-Host "All imports complete." -ForegroundColor Cyan
Write-Host "  Total indexed : $($totalIndexed.ToString('N0'))" -ForegroundColor Green
Write-Host "  Total failed  : $($totalFailed.ToString('N0'))" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Green" })
Write-Host "  Total time    : ${totalTime}s at avg $($totalRate.ToString('N0')) docs/sec" -ForegroundColor Cyan
