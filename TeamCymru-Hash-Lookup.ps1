<#
.SYNOPSIS
    Queries Team Cymru's Malware Hash Registry (MHR) for MD5 or SHA-1 hashes.
.DESCRIPTION
    Reads a text file containing one hash per line and performs a DNS TXT lookup.
    Drops SHA256 hashes automatically to prevent DNS protocol length errors.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit
}

$hashes = Get-Content -Path $FilePath
Write-Host "[*] Starting Team Cymru MHR lookups for $($hashes.Count) items..." -ForegroundColor Cyan

$results = foreach ($hash in $hashes) {
    $cleanHash = $hash.Trim()
    if ([string]::IsNullOrWhiteSpace($cleanHash)) { continue }

    # DNS Labels cannot exceed 63 characters. SHA256 is 64 characters.
    if ($cleanHash.Length -gt 63) {
        Write-Warning "Skipping SHA256 or invalid length hash: $cleanHash"
        continue
    }

    $query = "$cleanHash.malware.hash.cymru.com"
    $dnsResult = Resolve-DnsName -Name $query -Type TXT -ErrorAction SilentlyContinue

    if ($dnsResult -and $dnsResult.Strings) {
        $recordData = $dnsResult.Strings -join ' '
        $parts = $recordData -split ' '

        $timestamp = if ($parts.Count -ge 1) { $parts[0] } else { "Unknown" }
        $detection = if ($parts.Count -ge 2) { $parts[1] } else { "Unknown" }

        $dateSeen = "Unknown"
        if ($timestamp -match '^\d+$') {
            $origin = New-Object DateTime(1970, 1, 1, 0, 0, 0, 0, [DateTimeKind]::Utc)
            $dateSeen = $origin.AddSeconds([int]$timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        }

        [PSCustomObject]@{
            Hash            = $cleanHash
            DetectionRate   = "$detection%"
            FirstSeen       = $dateSeen
            Status          = "MALICIOUS / KNOWN"
        }
    }
}

if ($results) {
    Write-Host "`n[!] Found hits in the Malware Hash Registry:" -ForegroundColor Red
    $results | Format-Table -AutoSize
} else {
    Write-Host "`n[+] All valid hashes came back clean or unknown." -ForegroundColor Green
}
