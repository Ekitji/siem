# Scripts

## csvtondjsonv.ps1
Script that converts the saved CSV file to NDJSON format which is well supported by several SIEM solutions.

Place the script in same directory as the CSV files and run it with powershell `powershell -ep bypass .\csvtondjson.ps1`

## splitndjson.ps1
Use this script to split large NDJSON files (files larger then 1000MB/1GB).

Place the script in the same directory as your large NDJSON file and run it with powerhell `powershell -ep bypass .\splitndjson.ps1`
The NDJSON files will now be several smaller files in the "splitted" directory. Pre-configured to split at 970mb.

## importtoelastic.ps1
Elastic supports formats: PDF, TXT, CSV, log files and NDJSON and has Web GUI upload function which is limited to 100MB but can be extended to 1000MB (in the settings)
The script imports NDJSON data into Elasticsearch using the Bulk API in an efficient, batched way. There is no settings that need to be adjusted to use the Bulk API. Just make sure that each file dont exceed 1000MB for a smooth experience.

Place the script in the same directory as your NDJSON files and run it with powerhell `powershell -ep bypass .\importtoelastic.ps1`




### Use this for your local SIEM that you´ve installed
#### Setting up a local ELK is fairly easy using Windows platform.

- https://www.elastic.co/downloads/elasticsearch
- https://www.elastic.co/downloads/kibana
