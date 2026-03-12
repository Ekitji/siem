# Scripts

## csvtondjsonv.ps1
Script that converts the saved CSV file to NDJSON format which is well supported by several SIEM solutions.

Place the script in same directory as the CSV files and run it with powershell `powershell -ep bypass .\csvtondjson.ps1`

## importtoelastic.ps1
Elastic supports formats: PDF, TXT, CSV, log files and NDJSON and has Web GUI upload function which is limited to 100MB but can be extended to 1000MB (in the settings)
The script imports NDJSON data into Elasticsearch using the Bulk API in an efficient, batched way.

Place the script in the same directory as your NDJSON files and run it with powerhell `powershell -ep bypass .\importtoelastic.ps1`

### Use this on your local SIEM that you installed
#### Setting up a local ELK is fairly easy using Windows platform.

- https://www.elastic.co/downloads/elasticsearch
- https://www.elastic.co/downloads/kibana
