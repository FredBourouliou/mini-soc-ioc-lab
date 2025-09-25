<#
.SYNOPSIS
    Mini SOC IOC Lab - PowerShell IOC Scanner
    Scans files and processes for Indicators of Compromise (IOCs)

.DESCRIPTION
    This script provides IOC detection capabilities for Windows environments:
    - File hash checking (MD5, SHA256)
    - Process scanning
    - IP/Domain detection in logs
    - Report generation (CSV/Markdown)

.PARAMETER Targets
    Paths to scan (files or directories)

.PARAMETER IOCFile
    Path to IOC list file

.PARAMETER OutputFormat
    Report format: CSV or Markdown (default: Markdown)

.PARAMETER OutputFile
    Output report file path (default: report.md)

.PARAMETER SkipProcesses
    Skip process scanning

.PARAMETER Verbose
    Enable verbose output

.EXAMPLE
    .\scan-ioc.ps1 -Targets "C:\Downloads" -IOCFile ".\ioc\ioc_list.txt"

.NOTES
    Author: SOC Team
    Version: 1.0
    Date: 2025-01-25
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$Targets,

    [Parameter(Mandatory=$true)]
    [string]$IOCFile,

    [Parameter(Mandatory=$false)]
    [ValidateSet('CSV', 'Markdown', 'JSON')]
    [string]$OutputFormat = 'Markdown',

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = 'report.md',

    [Parameter(Mandatory=$false)]
    [switch]$SkipProcesses,

    [Parameter(Mandatory=$false)]
    [string[]]$LogFiles
)

# Initialize variables
$script:Detections = @()
$script:IOCs = @{
    Hashes = @{
        MD5 = @{}
        SHA1 = @{}
        SHA256 = @{}
    }
    IPs = @{}
    Domains = @{}
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR" { Write-Error $logMessage }
        "WARNING" { Write-Warning $logMessage }
        "CRITICAL" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Verbose $logMessage }
    }

    # Also write to log file
    $logMessage | Out-File -FilePath "ioc_scan.log" -Append
}

# Load IOCs from file
function Load-IOCs {
    param([string]$FilePath)

    Write-Log "Loading IOCs from $FilePath"

    if (-not (Test-Path $FilePath)) {
        Write-Log "IOC file not found: $FilePath" -Level "ERROR"
        exit 1
    }

    $content = Get-Content $FilePath
    $lineNum = 0

    foreach ($line in $content) {
        $lineNum++
        $line = $line.Trim()

        # Skip comments and empty lines
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }

        # Parse IOC line format: TYPE|VALUE|METADATA
        $parts = $line -split '\|', 3

        if ($parts.Count -lt 2) {
            Write-Log "Invalid IOC format at line $lineNum" -Level "WARNING"
            continue
        }

        $iocType = $parts[0].Trim().ToUpper()
        $value = $parts[1].Trim()
        $metadata = if ($parts.Count -ge 3) { $parts[2].Trim() } else { "" }

        switch ($iocType) {
            "HASH" {
                if ($value -match '^(md5|sha1|sha256):(.+)$') {
                    $hashType = $Matches[1].ToUpper()
                    $hashValue = $Matches[2].ToLower()
                    $script:IOCs.Hashes[$hashType][$hashValue] = $metadata
                }
            }
            "IP" {
                if (Test-ValidIP $value) {
                    $script:IOCs.IPs[$value] = $metadata
                }
            }
            "DOMAIN" {
                $script:IOCs.Domains[$value.ToLower()] = $metadata
            }
        }
    }

    $totalIOCs = ($script:IOCs.Hashes.MD5.Count + $script:IOCs.Hashes.SHA1.Count +
                  $script:IOCs.Hashes.SHA256.Count + $script:IOCs.IPs.Count +
                  $script:IOCs.Domains.Count)

    Write-Log "Loaded $totalIOCs IOCs"
}

# Validate IP address
function Test-ValidIP {
    param([string]$IP)

    return $IP -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
}

# Calculate file hash
function Get-FileHashValue {
    param(
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash.ToLower()
    }
    catch {
        Write-Log "Failed to hash file $FilePath : $_" -Level "ERROR"
        return $null
    }
}

# Scan single file
function Scan-File {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath -PathType Leaf)) {
        return
    }

    Write-Verbose "Scanning file: $FilePath"

    # Calculate hashes
    $md5Hash = Get-FileHashValue -FilePath $FilePath -Algorithm MD5
    $sha256Hash = Get-FileHashValue -FilePath $FilePath -Algorithm SHA256

    # Check MD5
    if ($md5Hash -and $script:IOCs.Hashes.MD5.ContainsKey($md5Hash)) {
        $detection = @{
            Type = "HASH"
            SubType = "MD5"
            Value = $md5Hash
            Path = $FilePath
            Metadata = $script:IOCs.Hashes.MD5[$md5Hash]
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Severity = "HIGH"
        }
        $script:Detections += $detection
        Write-Log "IOC Match: MD5 $md5Hash - $FilePath" -Level "WARNING"
    }

    # Check SHA256
    if ($sha256Hash -and $script:IOCs.Hashes.SHA256.ContainsKey($sha256Hash)) {
        $detection = @{
            Type = "HASH"
            SubType = "SHA256"
            Value = $sha256Hash
            Path = $FilePath
            Metadata = $script:IOCs.Hashes.SHA256[$sha256Hash]
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Severity = "HIGH"
        }
        $script:Detections += $detection
        Write-Log "IOC Match: SHA256 $sha256Hash - $FilePath" -Level "WARNING"
    }
}

# Scan directory recursively
function Scan-Directory {
    param([string]$DirectoryPath)

    Write-Log "Scanning directory: $DirectoryPath"

    Get-ChildItem -Path $DirectoryPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        Scan-File -FilePath $_.FullName
    }
}

# Scan running processes
function Scan-Processes {
    Write-Log "Scanning running processes..."

    Get-Process | ForEach-Object {
        $proc = $_

        try {
            # Get process executable path
            $exePath = $proc.Path

            if ($exePath -and (Test-Path $exePath)) {
                # Calculate hash of executable
                $sha256Hash = Get-FileHashValue -FilePath $exePath -Algorithm SHA256

                if ($sha256Hash -and $script:IOCs.Hashes.SHA256.ContainsKey($sha256Hash)) {
                    $detection = @{
                        Type = "PROCESS"
                        PID = $proc.Id
                        Name = $proc.Name
                        Path = $exePath
                        Hash = $sha256Hash
                        Metadata = $script:IOCs.Hashes.SHA256[$sha256Hash]
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Severity = "CRITICAL"
                    }
                    $script:Detections += $detection
                    Write-Log "Malicious process detected: $($proc.Name) (PID: $($proc.Id))" -Level "CRITICAL"
                }
            }

            # Check command line for IPs (if available)
            if ($proc.CommandLine) {
                foreach ($ip in $script:IOCs.IPs.Keys) {
                    if ($proc.CommandLine -match [regex]::Escape($ip)) {
                        $detection = @{
                            Type = "PROCESS_NETWORK"
                            PID = $proc.Id
                            Name = $proc.Name
                            IOC = $ip
                            CommandLine = $proc.CommandLine.Substring(0, [Math]::Min(200, $proc.CommandLine.Length))
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Severity = "HIGH"
                        }
                        $script:Detections += $detection
                        Write-Log "Process with IOC IP: $($proc.Name) - $ip" -Level "WARNING"
                    }
                }
            }
        }
        catch {
            # Access denied or process exited - continue silently
        }
    }
}

# Scan log files
function Scan-Logs {
    param([string[]]$LogPaths)

    foreach ($logPath in $LogPaths) {
        if (-not (Test-Path $logPath)) {
            Write-Log "Log file not found: $logPath" -Level "WARNING"
            continue
        }

        Write-Log "Scanning log: $logPath"

        $lineNum = 0
        Get-Content $logPath -ReadCount 1000 | ForEach-Object {
            $lines = $_
            foreach ($line in $lines) {
                $lineNum++

                # Check for IP IOCs
                foreach ($ip in $script:IOCs.IPs.Keys) {
                    if ($line -match [regex]::Escape($ip)) {
                        $detection = @{
                            Type = "LOG_IP"
                            Path = $logPath
                            Line = $lineNum
                            IOC = $ip
                            Context = $line.Substring(0, [Math]::Min(200, $line.Length))
                            Metadata = $script:IOCs.IPs[$ip]
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Severity = "MEDIUM"
                        }
                        $script:Detections += $detection
                        Write-Log "Log IOC found: $ip in $logPath:$lineNum" -Level "WARNING"
                    }
                }

                # Check for Domain IOCs
                foreach ($domain in $script:IOCs.Domains.Keys) {
                    if ($line.ToLower() -match [regex]::Escape($domain)) {
                        $detection = @{
                            Type = "LOG_DOMAIN"
                            Path = $logPath
                            Line = $lineNum
                            IOC = $domain
                            Context = $line.Substring(0, [Math]::Min(200, $line.Length))
                            Metadata = $script:IOCs.Domains[$domain]
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Severity = "MEDIUM"
                        }
                        $script:Detections += $detection
                        Write-Log "Log IOC found: $domain in $logPath:$lineNum" -Level "WARNING"
                    }
                }
            }
        }
    }
}

# Generate Markdown report
function Generate-MarkdownReport {
    param([string]$OutputPath)

    $report = @"
# IOC Detection Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Total Detections:** $($script:Detections.Count)

## Summary

| Detection Type | Count |
|----------------|-------|
"@

    # Count by type
    $typeCounts = $script:Detections | Group-Object -Property Type

    foreach ($typeGroup in $typeCounts) {
        $report += "`n| $($typeGroup.Name) | $($typeGroup.Count) |"
    }

    $report += @"

## Detailed Findings

"@

    $detectionNum = 1
    foreach ($detection in $script:Detections) {
        $report += @"

### Detection #$detectionNum

- **Type:** $($detection.Type)
- **Severity:** $($detection.Severity)
- **Timestamp:** $($detection.Timestamp)
"@

        if ($detection.Path) { $report += "`n- **Path:** ``$($detection.Path)``" }
        if ($detection.Value) { $report += "`n- **Value:** ``$($detection.Value)``" }
        if ($detection.Hash) { $report += "`n- **Hash:** ``$($detection.Hash)``" }
        if ($detection.IOC) { $report += "`n- **IOC:** ``$($detection.IOC)``" }
        if ($detection.Metadata) { $report += "`n- **Metadata:** $($detection.Metadata)" }

        $detectionNum++
    }

    $report += @"

## Recommended Actions

- [ ] Isolate affected systems
- [ ] Collect forensic artifacts
- [ ] Check for lateral movement
- [ ] Review security logs for related activity
- [ ] Update IOC watchlists
- [ ] Document incident timeline
"@

    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[+] Report saved to: $OutputPath" -ForegroundColor Green
}

# Generate CSV report
function Generate-CSVReport {
    param([string]$OutputPath)

    $script:Detections | Select-Object Type, Severity, Value, Path, IOC, Metadata, Timestamp |
        Export-Csv -Path $OutputPath -NoTypeInformation

    Write-Host "[+] CSV report saved to: $OutputPath" -ForegroundColor Green
}

# Generate JSON report
function Generate-JSONReport {
    param([string]$OutputPath)

    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalDetections = $script:Detections.Count
        Detections = $script:Detections
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[+] JSON report saved to: $OutputPath" -ForegroundColor Green
}

# Main execution
function Main {
    Write-Host @"
╔═══════════════════════════════════════════╗
║      Mini SOC IOC Lab - Scanner v1.0     ║
║         PowerShell Edition                ║
╚═══════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    # Load IOCs
    Load-IOCs -FilePath $IOCFile

    # Scan targets
    if ($Targets) {
        foreach ($target in $Targets) {
            if (Test-Path $target -PathType Container) {
                Scan-Directory -DirectoryPath $target
            }
            elseif (Test-Path $target -PathType Leaf) {
                Scan-File -FilePath $target
            }
            else {
                Write-Log "Target not found: $target" -Level "WARNING"
            }
        }
    }

    # Scan processes
    if (-not $SkipProcesses) {
        Scan-Processes
    }

    # Scan logs
    if ($LogFiles) {
        Scan-Logs -LogPaths $LogFiles
    }

    # Generate report
    switch ($OutputFormat) {
        'CSV' { Generate-CSVReport -OutputPath $OutputFile }
        'JSON' { Generate-JSONReport -OutputPath $OutputFile }
        default { Generate-MarkdownReport -OutputPath $OutputFile }
    }

    # Summary
    Write-Host "`n[+] Scan complete. Total detections: $($script:Detections.Count)" -ForegroundColor Green

    if ($script:Detections.Count -gt 0) {
        Write-Host "[!] IOCs detected! Review the report for details." -ForegroundColor Yellow
        exit 1
    }
    else {
        Write-Host "[+] No IOCs detected." -ForegroundColor Green
        exit 0
    }
}

# Run main function
Main