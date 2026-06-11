#!/bin/bash

URL_SSC="http://10.100.34.250:8280/ssc"
URL_SSC_API="http://10.100.34.250:8280/ssc/api/v1"
URL_SC_CTRL="http://10.100.34.250:8280/scancentral-ctrl/"
SASTToken="d3f6662b-5b0e-4fa9-9835-88da5f5567b7"
APITokenSSC="ZDNmNjY2MmItNWIwZS00ZmE5LTk4MzUtODhkYTVmNTU2N2I3"
APP_NAME_SSC="riches-demo"
APP_VERSION_SSC="1.0"
BUILD="none" # none, mvn, gradle, msbuild
triggerOnly="no" # no / yes

echo "Fortify Trigger Scan SAST!"

argument_list="scancentral -url $URL_SC_CTRL start -bt $BUILD -upload -application $APP_NAME_SSC -version $APP_VERSION_SSC -uptoken $SASTToken -sargs -Xmx5924M -sargs -Xms400M"
OUTPUT=$($argument_list)
echo "Log: $OUTPUT"

# ==================================== Ambil Job Token ===============================
regex="Submitted job and received token:[[:space:]]+([0-9a-fA-F\-]{36})"
if [[ $OUTPUT =~ $regex ]]; then
    TOKEN="${BASH_REMATCH[1]}"
    echo "Job Token: $TOKEN"
else
    echo "No match found."
fi

sleep 120

# ==================================== Cek Scan Selesai ================================
if [ "$triggerOnly" = "no" ]; then
    CEK_SAST_API="$URL_SSC_API/cloudjobs/$TOKEN"
    jobState="PENDING"
    projectversionid=""
    selesai="PENDING" # PENDING, SCAN_RUNNING, UPLOAD_COMPLETED
    
    echo "Sleep 30s . . ."
    sleep 30
    
    while [ "$selesai" = "SCAN_RUNNING" ] || [ "$selesai" = "PENDING" ]; do
        sleep 30
        
        RUNSTATUS=$(curl -s -X GET -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" "$CEK_SAST_API")
        
        # Hapus semua spasi dan newline untuk mempermudah regex
        CLEAN_STATUS=$(echo "$RUNSTATUS" | tr -d ' \n\r\t')
        
        # Ambil value jobState
        jobState=$(echo "$CLEAN_STATUS" | grep -o '"jobState":"[^"]*"' | cut -d'"' -f4)
        echo "Status scan: $jobState"
        
        if [ "$jobState" = "UPLOAD_COMPLETED" ]; then
            selesai="UPLOAD_COMPLETED"
            # Ambil value pvId dan hapus tanda kutip jika bentuknya string
            projectversionid=$(echo "$CLEAN_STATUS" | grep -o '"pvId":[^,}]*' | cut -d':' -f2 | tr -d '"')
        fi
        
        if [ "$jobState" = "SCAN_CANCELED" ] || [ "$jobState" = "SCAN_FAILED" ]; then
            echo "Pipeline Stop karena scan telah dihentikan" >&2
            exit 1
        fi
    done
    
    echo "Berhasil dengan status: $jobState"
    echo "Version App ID dari SSC: $projectversionid"
    
    # ==================================== Get Severity ================================
    echo "--- Get Severity Hasil Scan SAST ---"
    CRITICAL_LIMIT=9999
    HIGH_LIMIT=9999
    
    CEK_SSC="$URL_SSC_API/projectVersions/$projectversionid/issueSummaries?seriestype=ISSUE_FRIORITY&groupaxistype=ISSUE_FRIORITY"
    RUNSCAN=$(curl -s -X GET -H "Authorization: FortifyToken $APITokenSSC" -H "Content-Type: application/json" "$CEK_SSC")
    
    # Hapus spasi dari raw output JSON
    CLEAN_SCAN=$(echo "$RUNSCAN" | tr -d ' \n\r\t')
    
    # Loop Pertama: Cetak semua jenis isu dan jumlahnya (x = y)
    echo "$CLEAN_SCAN" | grep -o '{[^}]*"x":"[^"]*"[^}]*"y":[0-9]*[^}]*}' | while read -r block; do
        ISSUE_NAME=$(echo "$block" | grep -o '"x":"[^"]*"' | cut -d'"' -f4)
        ISSUE_QTY=$(echo "$block" | grep -o '"y":[0-9]*' | cut -d':' -f2)
        echo "$ISSUE_NAME = $ISSUE_QTY"
    done
    
    # Loop Kedua: Cari nilai spesifik untuk Critical dan High
    # Mengisolasi blok object { ... "Critical" ... "y":<angka> ... } agar akurat
    CRITICAL_BLOCK=$(echo "$CLEAN_SCAN" | grep -o '{[^}]*"Critical"[^}]*}')
    HIGH_BLOCK=$(echo "$CLEAN_SCAN" | grep -o '{[^}]*"High"[^}]*}')
    
    # Ekstrak angka dari blok yang ditemukan
    CRITICAL_QTY=$(echo "$CRITICAL_BLOCK" | grep -o '"y":[0-9]*' | cut -d':' -f2)
    HIGH_QTY=$(echo "$HIGH_BLOCK" | grep -o '"y":[0-9]*' | cut -d':' -f2)
    
    # Set ke 0 jika tidak ada temuan
    CRITICAL_QTY=${CRITICAL_QTY:-0}
    HIGH_QTY=${HIGH_QTY:-0}
    
    if [ "$CRITICAL_QTY" -gt "$CRITICAL_LIMIT" ]; then
        echo "link application $URL_SSC/html/ssc/version/$projectversionid/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6"
        echo "Pipeline Stop karena terdapat temuan Critical ($CRITICAL_QTY)" >&2
        exit 1
    fi
    
    if [ "$HIGH_QTY" -gt "$HIGH_LIMIT" ]; then
        echo "link application $URL_SSC/html/ssc/version/$projectversionid/fix/d0/s0?filterSet=a243b195-0a59-3f8b-1403-d55b7a7d78e6"
        echo "Pipeline Stop karena terdapat temuan High ($HIGH_QTY)" >&2
        exit 1
    fi
    
    echo "--- End of Script ---"

elif [ "$triggerOnly" = "yes" ]; then
    echo "Scanning Fortify SAST - Trigger Only!"
fi