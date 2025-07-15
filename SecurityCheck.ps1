# Supprimer les anciens scripts
Remove-Item "C:\Scripts\SecurityCheck*.ps1" -Force -ErrorAction SilentlyContinue

# Script de verification de securite Windows Server 2022
Write-Host "=== RAPPORT DE SECURITE WINDOWS SERVER 2022 ===" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Serveur: $env:COMPUTERNAME" -ForegroundColor Cyan

# TPM 2.0
Write-Host "`n========== TPM 2.0 ==========" -ForegroundColor Magenta
try {
    $TPMInfo = Get-Tpm
    Write-Host "TPM Present: $($TPMInfo.TpmPresent)" -ForegroundColor Green
    Write-Host "TPM Ready: $($TPMInfo.TpmReady)" -ForegroundColor Green
    Write-Host "TPM Activated: $($TPMInfo.TpmActivated)" -ForegroundColor Green
    Write-Host "TPM Enabled: $($TPMInfo.TpmEnabled)" -ForegroundColor Green
} catch {
    Write-Host "Erreur TPM: $($_.Exception.Message)" -ForegroundColor Red
}

# Secure Boot
Write-Host "`n========== SECURE BOOT ==========" -ForegroundColor Magenta
try {
    $SecureBoot = Confirm-SecureBootUEFI
    Write-Host "Secure Boot: $SecureBoot" -ForegroundColor Green
} catch {
    Write-Host "Secure Boot: Non supporte ou desactive" -ForegroundColor Red
}

# VBS et fonctionnalites de securite
Write-Host "`n========== VBS ET SECURITY FEATURES ==========" -ForegroundColor Magenta
$SecurityInfo = Get-ComputerInfo | Select-Object -Property "*VirtualizationBasedSecurity*", "*CredentialGuard*", "*DeviceGuard*"
$SecurityInfo | Format-List

# Windows Defender
Write-Host "`n========== WINDOWS DEFENDER ==========" -ForegroundColor Magenta
try {
    $DefenderStatus = Get-MpComputerStatus
    Write-Host "Antivirus Active: $($DefenderStatus.AntivirusEnabled)" -ForegroundColor Green
    Write-Host "Protection Temps Reel: $($DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Green
    Write-Host "Service AM: $($DefenderStatus.AMServiceEnabled)" -ForegroundColor Green
    Write-Host "Derniere MAJ: $($DefenderStatus.AntivirusSignatureLastUpdated)" -ForegroundColor Cyan
} catch {
    Write-Host "Erreur Windows Defender: $($_.Exception.Message)" -ForegroundColor Red
}

# Informations systeme
Write-Host "`n========== INFORMATIONS SYSTEME ==========" -ForegroundColor Magenta
$ComputerInfo = Get-ComputerInfo
Write-Host "OS: $($ComputerInfo.WindowsProductName)" -ForegroundColor Cyan
Write-Host "Version: $($ComputerInfo.WindowsVersion)" -ForegroundColor Cyan
Write-Host "Build: $($ComputerInfo.WindowsBuildLabEx)" -ForegroundColor Cyan

# Configuration LSA pour Credential Guard
Write-Host "`n========== CREDENTIAL GUARD CONFIG ==========" -ForegroundColor Magenta
try {
    $LSAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
    $LSAConfig = Get-ItemProperty -Path $LSAPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
    if ($LSAConfig) {
        Write-Host "LsaCfgFlags: $($LSAConfig.LsaCfgFlags)" -ForegroundColor Green
    } else {
        Write-Host "LsaCfgFlags: Non configure" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Erreur lecture LSA" -ForegroundColor Red
}

# Code Integrity
Write-Host "`n========== CODE INTEGRITY ==========" -ForegroundColor Magenta
$CIPolicyPath = "C:\Windows\System32\CodeIntegrity"
if (Test-Path $CIPolicyPath) {
    Write-Host "Dossier Code Integrity trouve" -ForegroundColor Green
    Get-ChildItem -Path $CIPolicyPath -File | Select-Object Name, Length, LastWriteTime | Format-Table
} else {
    Write-Host "Dossier Code Integrity non trouve" -ForegroundColor Yellow
}

Write-Host "`n=== FIN DU RAPPORT ===" -ForegroundColor Green
