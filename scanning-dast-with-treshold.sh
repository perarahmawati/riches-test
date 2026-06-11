#!/bin/bash

URL_DAST_API="https://fortify-dast.kikoichi.dev/api"
URL_SSC="http://10.100.34.250:8280/ssc"
URL_SSC_API="http://10.100.34.250:8280/ssc/api/v1"
APITokenSSC="ZDNmNjY2MmItNWIwZS00ZmE5LTk4MzUtODhkYTVmNTU2N2I3"
cicdToken="b082eb7b-da90-4723-a9f6-38ad6cb45519"
CIToken="019a2e6d-d682-43fb-9f59-2909ac1e5683"
condition="no"

echo "--- Start Script for Scanning Fortify DAST 33---"
echo "URL_DAST_API: $URL_DAST_API"
echo "URL_SSC: $URL_SSC"
echo "APITokenSSC: $APITokenSSC"
echo "cicdToken: $cicdToken"

URL_DAST="$URL_DAST_API/v2/scans/start-scan-cicd"
BODY='{"cicdToken":"'"$cicdToken"'"}'

# Trigger DAST Scan
echo "-> Mengirim request ke: $URL_DAST"

# [DEBUGGING] Menjalankan curl verbose (-v) dan insecure (-k). 
# Log jaringan disimpan di curl_debug.log, response server di response.json
curl -v -k -sS -X POST -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" -d "$BODY" "$URL_DAST" > response.json 2> curl_debug.log

echo "================ DEBUG CURL TRIGGER (NETWORK LOG) ================"
cat curl_debug.log
echo "================ RAW RESPONSE BODY ================"
cat response.json
echo "=================================================================="

# Memasukkan isi file response ke dalam variabel
DASTSCANAPP=$(cat response.json)

# Hapus semua spasi dan newline dari output JSON untuk memudahkan Regex
CLEAN_DASTSCANAPP=$(echo "$DASTSCANAPP" | tr -d ' \n\r\t')

# Ambil value ID
hasil_dastscanapp=$(echo "$CLEAN_DASTSCANAPP" | grep -o '"id":[^,}]*' | cut -d':' -f2 | tr -d '"')
echo "Scan ID: $hasil_dastscanapp"

# Validasi jika Scan ID kosong, langsung stop pipeline!
if [ -z "$hasil_dastscanapp" ]; then
    echo "ERROR: Scan ID tidak ditemukan. Cek blok 'DEBUG CURL TRIGGER' di atas untuk melihat detail kegagalan jaringannya." >&2
    exit 1
fi

# ==================================== Cek Status Scan ================================
GETSTATUS="$URL_DAST_API/v2/scans/$hasil_dastscanapp/scan-summary"
statusscan=""
selesai=1

# Ambil data pertama
RUNSTATUS=$(curl -k -s -X GET -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" "$GETSTATUS")
CLEAN_RUNSTATUS=$(echo "$RUNSTATUS" | tr -d ' \n\r\t')

projectVersionId=$(echo "$CLEAN_RUNSTATUS" | grep -o '"applicationVersionId":[^,}]*' | cut -d':' -f2 | tr -d '"')
projectVersionName=$(echo "$CLEAN_RUNSTATUS" | grep -o '"applicationVersionName":"[^"]*"' | cut -d'"' -f4)
appn=$(echo "$CLEAN_RUNSTATUS" | grep -o '"applicationName":"[^"]*"' | cut -d'"' -f4)
appid=$(echo "$CLEAN_RUNSTATUS" | grep -o '"applicationId":[^,}]*' | cut -d':' -f2 | tr -d '"')
appstatscandes=$(echo "$CLEAN_RUNSTATUS" | grep -o '"scanStatusTypeDescription":"[^"]*"' | cut -d'"' -f4)

echo "App Version ID: $projectVersionId"
echo "App Version Name: $projectVersionName"
echo "App Name: $appn"
echo "App ID: $appid"
echo "ScanStatus Type Desc: $appstatscandes"
echo "--- Get Status DAST ---"

# Polling status scan hingga selesai
while [ "$selesai" -eq 1 ]; do
    RUNSTATUS=$(curl -k -s -X GET -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" "$GETSTATUS")
    CLEAN_RUNSTATUS=$(echo "$RUNSTATUS" | tr -d ' \n\r\t')
    statusscan=$(echo "$CLEAN_RUNSTATUS" | grep -o '"scanStatusTypeDescription":"[^"]*"' | cut -d'"' -f4)
    
    # Validasi safety jika status tiba-tiba kosong
    if [ -z "$statusscan" ]; then
        echo "ERROR: Gagal mengambil status scan. Pipeline dihentikan." >&2
        exit 1
    fi
    
    if [ "$statusscan" = "Complete" ]; then
        selesai=0
    fi
    
    echo "Status scan: $statusscan"
    
    if [ "$selesai" -eq 1 ]; then
        sleep 15
    fi
done

echo "Version App ID dari SSC: $projectVersionId"
echo "Version App name dari SSC: $projectVersionName"

# ==================================== Get Severity ================================
echo "--- Get Severity Hasil Scan DAST ---"
CRITICAL_LIMIT=100

CEK_SSC="$URL_SSC_API/projectVersions/$projectVersionId/issueSummaries?seriestype=ISSUE_FRIORITY&groupaxistype=ISSUE_FRIORITY"
RUNSCAN=$(curl -k -s -X GET -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" "$CEK_SSC")
CLEAN_SCAN=$(echo "$RUNSCAN" | tr -d ' \n\r\t')

# Loop Pertama: Cetak semua jenis isu dan jumlahnya ke layar
echo "$CLEAN_SCAN" | grep -o '{[^}]*"x":"[^"]*"[^}]*"y":[0-9]*[^}]*}' | while read -r block; do
    ISSUE_NAME=$(echo "$block" | grep -o '"x":"[^"]*"' | cut -d'"' -f4)
    ISSUE_QTY=$(echo "$block" | grep -o '"y":[0-9]*' | cut -d':' -f2)
    echo "$ISSUE_NAME = $ISSUE_QTY"
done

# Loop Kedua: Cari nilai spesifik untuk Critical
CRITICAL_BLOCK=$(echo "$CLEAN_SCAN" | grep -o '{[^}]*"Critical"[^}]*}')
CRITICAL_QTY=$(echo "$CRITICAL_BLOCK" | grep -o '"y":[0-9]*' | cut -d':' -f2)

# Default ke 0 jika API mengembalikan null atau nilai kosong
CRITICAL_QTY=${CRITICAL_QTY:-0}

if [ "$CRITICAL_QTY" -gt "$CRITICAL_LIMIT" ]; then
    echo "link application $URL_SSC/html/ssc/version/$projectVersionId/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6"
    
    if [ "$condition" = "yes" ]; then
        echo "Pipeline dihentikan karena temuan Critical melampaui batas!" >&2
        exit 1
    else
        echo "--- End of Scanning ---"
    fi
fi

# Pembersihan file temporary
rm -f curl_debug.log response.json

echo "--- End of Script ---"