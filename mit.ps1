#requires -version 5.1

$ErrorActionPreference = "SilentlyContinue"

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Mitigation,
        [string]$State,
        [string]$Details = ""
    )

    $Results.Add([PSCustomObject]@{
        Category   = $Category
        Mitigation = $Mitigation
        State      = $State
        Details    = $Details
    }) | Out-Null
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $x = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $x.$Name
    }
    catch {
        return $null
    }
}

function Get-CIState {
    param($Value)

    switch ($Value) {
        0 { return "Off" }
        1 { return "Audit" }
        2 { return "Enforced" }
        default { return "Unknown ($Value)" }
    }
}

# ============================================================
# Administrator
# ============================================================

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdmin = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

Add-Result "Environment" "Running elevated" `
    $(if ($IsAdmin) { "Yes" } else { "No" }) `
    $(if ($IsAdmin) { "Administrator PowerShell" } else { "Run PowerShell as Administrator for complete results" })

# ============================================================
# Windows version
# ============================================================

try {
    $CV = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    $Version = "$($CV.ProductName) $($CV.DisplayVersion)"
    $Build = "$($CV.CurrentBuild).$($CV.UBR)"

    Add-Result "Environment" "Windows Version" $Version "Build $Build"
}
catch {}

# ============================================================
# Secure Boot
# ============================================================

try {
    $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

    if ($SecureBoot) {
        Add-Result "Boot Security" "Secure Boot" "ENABLED"
    }
    else {
        Add-Result "Boot Security" "Secure Boot" "DISABLED" "Expected if intentionally disabled for test signing / kernel debugging"
    }
}
catch {
    Add-Result "Boot Security" "Secure Boot" "Unavailable / Unknown" $_.Exception.Message
}

# ============================================================
# BCDEDIT
# ============================================================

$BcdText = (& bcdedit /enum '{current}' 2>&1 | Out-String)
$BcdLines = $BcdText -split "`r?`n"

function Get-BcdValue {
    param([string]$Name)

    foreach ($Line in $BcdLines) {
        if ($Line -match ("^\s*" + [regex]::Escape($Name) + "\s+(.+?)\s*$")) {
            return $Matches[1]
        }
    }

    return $null
}

$TestSigning       = Get-BcdValue "testsigning"
$Debug             = Get-BcdValue "debug"
$NoIntegrityChecks = Get-BcdValue "nointegritychecks"
$NX                = Get-BcdValue "nx"
$HypervisorLaunch  = Get-BcdValue "hypervisorlaunchtype"

Add-Result "Boot Configuration" "TESTSIGNING" `
    $(if ($TestSigning -match "Yes") { "ENABLED" } elseif ($TestSigning) { $TestSigning } else { "Not explicitly set" }) `
    "BCDEdit testsigning"

Add-Result "Boot Configuration" "Kernel Debugging" `
    $(if ($Debug -match "Yes") { "ENABLED" } elseif ($Debug) { $Debug } else { "Not explicitly set" }) `
    "BCDEdit debug"

Add-Result "Boot Configuration" "No Integrity Checks" `
    $(if ($NoIntegrityChecks -match "Yes") { "ENABLED - WARNING" } elseif ($NoIntegrityChecks) { $NoIntegrityChecks } else { "Not enabled" }) `
    "BCDEdit nointegritychecks"

Add-Result "Boot Configuration" "BCDEdit NX Policy" `
    $(if ($NX) { $NX } else { "Default / not explicitly set" })

Add-Result "Boot Configuration" "Hypervisor Launch Type" `
    $(if ($HypervisorLaunch) { $HypervisorLaunch } else { "Default / not explicitly set" })

# ============================================================
# Hypervisor
# ============================================================

try {
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem

    Add-Result "Virtualization" "Hypervisor Present" `
        $(if ($ComputerSystem.HypervisorPresent) { "YES" } else { "NO" })
}
catch {}

# ============================================================
# Device Guard / VBS / HVCI
# ============================================================

$DG = $null

try {
    $DG = Get-CimInstance `
        -Namespace "root\Microsoft\Windows\DeviceGuard" `
        -ClassName Win32_DeviceGuard `
        -ErrorAction Stop

    switch ($DG.VirtualizationBasedSecurityStatus) {
        0 { $VBSState = "DISABLED" }
        1 { $VBSState = "Enabled but NOT running" }
        2 { $VBSState = "RUNNING" }
        default { $VBSState = "Unknown ($($DG.VirtualizationBasedSecurityStatus))" }
    }

    Add-Result "VBS" "Virtualization Based Security" $VBSState

    $Running    = @($DG.SecurityServicesRunning)
    $Configured = @($DG.SecurityServicesConfigured)

    # Credential Guard
    if ($Running -contains 1) {
        $State = "RUNNING"
    }
    elseif ($Configured -contains 1) {
        $State = "Configured but NOT running"
    }
    else {
        $State = "Not running"
    }

    Add-Result "VBS" "Credential Guard" $State

    # HVCI / Memory Integrity
    if ($Running -contains 2) {
        $HVCIRunning = $true
        $State = "RUNNING"
    }
    elseif ($Configured -contains 2) {
        $HVCIRunning = $false
        $State = "Configured but NOT running"
    }
    else {
        $HVCIRunning = $false
        $State = "Not running"
    }

    Add-Result "Kernel Security" "Memory Integrity / HVCI" $State

    # Secure Launch
    if ($Running -contains 3) {
        $State = "RUNNING"
    }
    elseif ($Configured -contains 3) {
        $State = "Configured but NOT running"
    }
    else {
        $State = "Not running"
    }

    Add-Result "Kernel Security" "System Guard Secure Launch" $State

    # SMM Firmware Measurement
    if ($Running -contains 4) {
        $State = "RUNNING"
    }
    elseif ($Configured -contains 4) {
        $State = "Configured but NOT running"
    }
    else {
        $State = "Not running"
    }

    Add-Result "Kernel Security" "SMM Firmware Measurement" $State

    # Kernel CET / Hardware Stack Protection
    if ($Running -contains 5) {
        $KCETState = "RUNNING / ENFORCED"
    }
    elseif ($Running -contains 6) {
        $KCETState = "RUNNING / AUDIT MODE"
    }
    elseif ($Configured -contains 5) {
        $KCETState = "Configured but NOT running"
    }
    elseif ($Configured -contains 6) {
        $KCETState = "Configured in Audit mode but NOT running"
    }
    else {
        $KCETState = "Not running"
    }

    Add-Result "Kernel Security" `
        "Kernel-mode Hardware-enforced Stack Protection (CET/KCET)" `
        $KCETState

    # HVPT
    if ($Running -contains 7) {
        $State = "RUNNING"
    }
    elseif ($Configured -contains 7) {
        $State = "Configured but NOT running"
    }
    else {
        $State = "Not running"
    }

    Add-Result "Kernel Security" `
        "Hypervisor-Enforced Paging Translation (HVPT)" `
        $State

    # Kernel Code Integrity Policy
    Add-Result "Code Integrity" `
        "Kernel Code Integrity Policy" `
        (Get-CIState $DG.CodeIntegrityPolicyEnforcementStatus)

    # User-mode Code Integrity Policy
    Add-Result "Code Integrity" `
        "User-mode Code Integrity Policy" `
        (Get-CIState $DG.UsermodeCodeIntegrityPolicyEnforcementStatus)

    # Hardware security capabilities
    $Available = @($DG.AvailableSecurityProperties)

    $Capabilities = [ordered]@{
        1 = "Hypervisor Support"
        2 = "Secure Boot Capability"
        3 = "DMA Protection Capability"
        4 = "Secure Memory Overwrite"
        5 = "NX / Execute Disable Capability"
        6 = "SMM Security Mitigations"
        7 = "MBEC / GMET"
        8 = "APIC Virtualization"
    }

    foreach ($ID in $Capabilities.Keys) {
        Add-Result "Hardware Capability" `
            $Capabilities[$ID] `
            $(if ($Available -contains [int]$ID) { "AVAILABLE" } else { "Not reported" })
    }
}
catch {
    Add-Result "VBS" "Win32_DeviceGuard" "ERROR" $_.Exception.Message
    $HVCIRunning = $false
}

# ============================================================
# Microsoft Vulnerable Driver Blocklist
# ============================================================

$BlockList = Get-RegValue `
    "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" `
    "VulnerableDriverBlocklistEnable"

if ($HVCIRunning) {
    Add-Result "Kernel Security" `
        "Microsoft Vulnerable Driver Blocklist" `
        "ENFORCED via HVCI" `
        "Registry value: $BlockList"
}
elseif ($BlockList -eq 1) {
    Add-Result "Kernel Security" `
        "Microsoft Vulnerable Driver Blocklist" `
        "ENABLED"
}
elseif ($BlockList -eq 0) {
    Add-Result "Kernel Security" `
        "Microsoft Vulnerable Driver Blocklist" `
        "DISABLED"
}
else {
    Add-Result "Kernel Security" `
        "Microsoft Vulnerable Driver Blocklist" `
        "Not explicitly configured"
}

# ============================================================
# LSA Protection / RunAsPPL
# ============================================================

$RunAsPPL = Get-RegValue `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    "RunAsPPL"

if (($RunAsPPL -eq 1) -or ($RunAsPPL -eq 2)) {
    Add-Result "Credential Security" "LSA Protection / RunAsPPL" "ENABLED" "Value=$RunAsPPL"
}
elseif ($RunAsPPL -eq 0) {
    Add-Result "Credential Security" "LSA Protection / RunAsPPL" "DISABLED"
}
else {
    Add-Result "Credential Security" "LSA Protection / RunAsPPL" "Not explicitly configured"
}

# ============================================================
# Microsoft Defender
# ============================================================

try {
    $MP = Get-MpComputerStatus -ErrorAction Stop

    Add-Result "Microsoft Defender" "Antivirus" `
        $(if ($MP.AntivirusEnabled) { "ENABLED" } else { "DISABLED" })

    Add-Result "Microsoft Defender" "Real-time Protection" `
        $(if ($MP.RealTimeProtectionEnabled) { "ENABLED" } else { "DISABLED" })

    Add-Result "Microsoft Defender" "Behavior Monitor" `
        $(if ($MP.BehaviorMonitorEnabled) { "ENABLED" } else { "DISABLED" })

    Add-Result "Microsoft Defender" "IOAV Protection" `
        $(if ($MP.IoavProtectionEnabled) { "ENABLED" } else { "DISABLED" })

    if ($MP.PSObject.Properties.Name -contains "IsTamperProtected") {
        Add-Result "Microsoft Defender" "Tamper Protection" `
            $(if ($MP.IsTamperProtected) { "ENABLED" } else { "DISABLED" })
    }
}
catch {
    Add-Result "Microsoft Defender" "Defender Status" "Unavailable"
}

# ============================================================
# Process Exploit Protection
# ============================================================

$ProcessMitigationText = ""

if (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue) {
    try {
        $ProcessMitigationText = (
            Get-ProcessMitigation -System |
            Out-String -Width 260
        )

        Add-Result "Exploit Protection" `
            "System Process Mitigations" `
            "See detailed section below" `
            "DEP, ASLR, CFG, Dynamic Code, SEHOP and related process mitigations"
    }
    catch {
        $ProcessMitigationText = "Unable to query Get-ProcessMitigation."
    }
}
else {
    $ProcessMitigationText = "Get-ProcessMitigation cmdlet unavailable."
}

# ============================================================
# SMEP / SMAP
# ============================================================

Add-Result "Kernel CPU Mitigation" `
    "SMEP" `
    "WinDbg verification required" `
    'Use: ? (@cr4 & 0x100000)'

Add-Result "Kernel CPU Mitigation" `
    "SMAP" `
    "WinDbg verification required" `
    'Use: ? (@cr4 & 0x200000)'

# ============================================================
# DISPLAY RESULTS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " WINDOWS KERNEL / EXPLOIT MITIGATION AUDIT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$TableText = (
    $Results |
    Sort-Object Category, Mitigation |
    Format-Table -AutoSize |
    Out-String -Width 300
)

Write-Host $TableText

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " SYSTEM EXPLOIT PROTECTION DEFAULTS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow

Write-Host $ProcessMitigationText

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " SMEP / SMAP MANUAL WINDBG CHECK" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

Write-Host @'
In local kernel WinDbg:

r cr4

? (@cr4 & 0x100000)
    Non-zero = SMEP enabled

? (@cr4 & 0x200000)
    Non-zero = SMAP enabled
'@

# ============================================================
# SAVE REPORT
# ============================================================

if ($PSScriptRoot) {
    $OutputDirectory = $PSScriptRoot
}
else {
    $OutputDirectory = (Get-Location).Path
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$TXT  = Join-Path $OutputDirectory "Mitigation-Report-$Timestamp.txt"
$JSON = Join-Path $OutputDirectory "Mitigation-Report-$Timestamp.json"
$CSV  = Join-Path $OutputDirectory "Mitigation-Summary-$Timestamp.csv"

$FullReport = @"
WINDOWS KERNEL / EXPLOIT MITIGATION AUDIT
Generated: $(Get-Date)

============================================================
SUMMARY
============================================================

$TableText

============================================================
BCDEDIT
============================================================

$BcdText

============================================================
SYSTEM EXPLOIT PROTECTION DEFAULTS
============================================================

$ProcessMitigationText

============================================================
SMEP / SMAP
============================================================

SMEP:
    WinDbg: ? (@cr4 & 0x100000)
    Non-zero = Enabled

SMAP:
    WinDbg: ? (@cr4 & 0x200000)
    Non-zero = Enabled
"@

$FullReport | Set-Content -Path $TXT -Encoding UTF8

$Results |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $JSON -Encoding UTF8

$Results |
    Export-Csv -Path $CSV -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Reports saved:" -ForegroundColor Green
Write-Host "TXT  : $TXT"
Write-Host "JSON : $JSON"
Write-Host "CSV  : $CSV"
