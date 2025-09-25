/*
 * YARA Rules for Mini SOC IOC Lab
 * Educational examples for malware detection patterns
 * Author: SOC Team
 * Date: 2025-01-25
 */

rule Suspicious_Strings
{
    meta:
        description = "Detects suspicious strings commonly found in malware"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "medium"
        category = "generic"

    strings:
        // Network indicators
        $net1 = "cmd.exe" nocase
        $net2 = "powershell" nocase
        $net3 = "http://" nocase
        $net4 = "https://" nocase

        // System manipulation
        $sys1 = "CreateRemoteThread"
        $sys2 = "VirtualAllocEx"
        $sys3 = "WriteProcessMemory"
        $sys4 = "KERNEL32.DLL" nocase

        // Suspicious commands
        $cmd1 = "whoami" nocase
        $cmd2 = "net user" nocase
        $cmd3 = "reg add" nocase
        $cmd4 = "schtasks" nocase

        // Encoding/Encryption
        $enc1 = "base64" nocase
        $enc2 = "FromBase64String"
        $enc3 = "crypto" nocase

    condition:
        // Trigger if 3 or more suspicious strings found
        3 of them
}

rule Base64_Encoded_Executable
{
    meta:
        description = "Detects Base64 encoded PE executables"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "high"
        technique = "T1027"

    strings:
        // Base64 encoded "MZ" header (multiple variations)
        $b64_mz1 = "TVqQAA" // MZ\x90\x00
        $b64_mz2 = "TVpQAA" // MZ\x50\x00
        $b64_mz3 = "TVoAAA" // MZ\x00\x00
        $b64_mz4 = "TVpBAA" // MZ\x41\x00
        $b64_mz5 = "TVpAAA" // MZ\x40\x00

        // Base64 encoded "This program"
        $b64_stub = "VGhpcyBwcm9ncmFt"

    condition:
        // Detect if any Base64 MZ header variant is present
        any of ($b64_mz*) or $b64_stub
}

import "pe"

rule Suspicious_PE
{
    meta:
        description = "Detects PE files with suspicious characteristics"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "high"
        category = "executable"

    condition:
        // File must be a PE
        pe.is_pe and
        (
            // Suspicious section count
            pe.number_of_sections > 7 or
            pe.number_of_sections < 2 or

            // Suspicious timestamp (0 = likely packed/modified)
            pe.timestamp == 0 or

            // Entry point in last section (common in packers)
            pe.entry_point >= pe.sections[pe.number_of_sections - 1].virtual_address or

            // Very small or very large file
            filesize < 1024 or
            filesize > 100000000 or

            // No imports (suspicious for Windows PE)
            pe.number_of_imports == 0
        )
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-virus test file detection"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "info"
        category = "test"

    strings:
        // EICAR test string (safe test pattern)
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule Ransomware_Indicators
{
    meta:
        description = "Generic ransomware behavior indicators"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "critical"
        category = "ransomware"
        mitre = "T1486"

    strings:
        // Ransomware notes
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "BTC wallet" nocase
        $ransom4 = "decrypt your files" nocase
        $ransom5 = "payment instructions" nocase

        // Encryption-related
        $crypt1 = "CryptGenRandom"
        $crypt2 = "CryptEncrypt"
        $crypt3 = "AES" nocase
        $crypt4 = "RSA" nocase

        // File operations
        $file1 = "FindFirstFileW"
        $file2 = "FindNextFileW"
        $file3 = ".encrypted"
        $file4 = ".locked"

    condition:
        // Multiple ransomware indicators
        (2 of ($ransom*)) and (1 of ($crypt*)) or
        (3 of ($ransom*)) or
        (2 of ($crypt*) and 2 of ($file*))
}

rule Webshell_Detection
{
    meta:
        description = "Detects common webshell patterns"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "critical"
        category = "webshell"

    strings:
        // PHP webshells
        $php1 = "eval($_POST" nocase
        $php2 = "eval($_GET" nocase
        $php3 = "eval($_REQUEST" nocase
        $php4 = "system($_" nocase
        $php5 = "shell_exec($_" nocase
        $php6 = "<?php @eval" nocase

        // ASP/ASPX webshells
        $asp1 = "eval request" nocase
        $asp2 = "execute request" nocase
        $asp3 = "WScript.Shell" nocase

        // JSP webshells
        $jsp1 = "Runtime.getRuntime().exec" nocase
        $jsp2 = "processbuilder" nocase

        // Common backdoor passwords
        $pwd1 = "c99"
        $pwd2 = "r57"
        $pwd3 = "b374k"

    condition:
        any of ($php*) or
        any of ($asp*) or
        any of ($jsp*) or
        any of ($pwd*)
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects potential C2 communication patterns"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "high"
        category = "network"

    strings:
        // C2 patterns
        $c2_1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $c2_2 = "User-Agent: Mozilla/4.0" // Old user agent
        $c2_3 = "CONNECT " // Proxy tunneling

        // Data exfiltration
        $exfil1 = "upload.php"
        $exfil2 = "POST /upload"
        $exfil3 = "multipart/form-data"

        // DNS tunneling
        $dns1 = "nslookup"
        $dns2 = "dig "
        $dns3 = "8.8.8.8"
        $dns4 = "1.1.1.1"

    condition:
        2 of ($c2_*) or
        2 of ($exfil*) or
        3 of ($dns*)
}

rule Test_Detection_Sample
{
    meta:
        description = "Simple test rule for validation"
        author = "SOC Team"
        date = "2025-01-25"
        severity = "info"

    strings:
        $test1 = "MALWARE_TEST_SAMPLE"
        $test2 = "This is a test file for YARA detection"
        $test3 = { 4D 41 4C 57 41 52 45 } // "MALWARE" in hex

    condition:
        any of them
}