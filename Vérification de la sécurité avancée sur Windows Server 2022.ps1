# Vérification de la sécurité avancée sur Windows Server 2022
# Script automatisé pour vérifier et configurer les fonctionnalités de sécurité avancées

# Exercice 1 : Vérification du TPM
Write-Host "=== Exercice 1 : Vérification du TPM ==="
Get-Tpm
Try { Get-TpmEndorsementKeyInfo } Catch { Write-Host "Get-TpmEndorsementKeyInfo non disponible." }
Try { Get-TpmOwnerInfo } Catch { Write-Host "Get-TpmOwnerInfo non disponible." }
Enable-TpmAutoProvisioning

# Exercice 2 : Vérification Secure Boot
Write-Host "`n=== Exercice 2 : Vérification Secure Boot ==="
Try { Confirm-SecureBootUEFI } Catch { Write-Host "Secure Boot non supporté ou non accessible." }
Try { Get-SecureBootPolicy } Catch { Write-Host "Get-SecureBootPolicy non disponible." }

# Exercice 3 : Activation de VBS
Write-Host "`n=== Exercice 3 : Activation de VBS ==="
systeminfo | findstr /C:"Hyper-V"
Get-ComputerInfo | Select-Object -Property "*guard*"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
Write-Host "Redémarrez le système pour appliquer les changements VBS."
Get-ComputerInfo | Select-Object -Property "*VirtualizationBasedSecurity*"

# Exercice 4 : Activation HVCI
Write-Host "`n=== Exercice 4 : Activation HVCI ==="
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord
Write-Host "Redémarrez le système pour appliquer les changements HVCI."
Get-ComputerInfo | Select-Object -Property "*CodeIntegrity*"
if (!(Test-Path "C:\temp")) { New-Item -Path "C:\temp" -ItemType Directory -Force }
msinfo32 /report C:\temp\systeminfo.txt
Get-Content C:\temp\systeminfo.txt | Select-String "Code Integrity"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus

# Exercice 5 : Activation Credential Guard
Write-Host "`n=== Exercice 5 : Activation Credential Guard ==="
Get-ComputerInfo | Select-Object -Property "*CredentialGuard*"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 1 -Type DWord
Write-Host "Redémarrez le système pour appliquer Credential Guard."
Get-ComputerInfo | Select-Object -Property "*CredentialGuard*"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -Property *
Get-WinEvent -FilterHashtable @{LogName="System"; ID=12} | Where-Object {$_.Message -match "Credential Guard"}

# Exercice 6 : Création d'une politique Application Control
Write-Host "`n=== Exercice 6 : Création d'une politique Application Control ==="
if (!(Test-Path "C:\DeviceGuard")) { New-Item -Path "C:\DeviceGuard" -ItemType Directory -Force }
New-CIPolicy -Level Publisher -FilePath "C:\DeviceGuard\InitialPolicy.xml" -UserPEs
ConvertFrom-CIPolicy -XmlFilePath "C:\DeviceGuard\InitialPolicy.xml" -BinaryFilePath "C:\DeviceGuard\DeviceGuardPolicy.bin"
Copy-Item "C:\DeviceGuard\DeviceGuardPolicy.bin" -Destination "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -Value 1 -Type DWord

# Exercice 7 : Configuration System Guard
Write-Host "`n=== Exercice 7 : Configuration System Guard ==="
Get-ComputerInfo | Select-Object -Property "*SystemGuard*"
Get-WmiObject -Namespace "root\cimv2" -Class "Win32_DeviceGuard"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableSystemGuardRuntimeAttestation" -Value 1 -Type DWord

# Exercice 8 : Vérification Windows Defender System Guard
Write-Host "`n=== Exercice 8 : Vérification Windows Defender System Guard ==="
Get-ComputerInfo | Select-Object -Property "*Guard*", "*Security*"
Get-MpComputerStatus
$SecurityReport = Get-ComputerInfo | Select-Object -Property "*Guard*", "*Security*", "*Tpm*"
$SecurityReport | Export-Csv -Path "C:\temp\SecurityReport.csv" -NoTypeInformation

# Exercice 9 : Vérification de la protection DMA
Write-Host "`n=== Exercice 9 : Vérification de la protection DMA ==="
Get-ComputerInfo | Select-Object -Property "*DMA*"
Get-PnpDevice | Where-Object {$_.FriendlyName -match "DMA"}
systeminfo | findstr /C:"Virtualization Enabled In Firmware"

# Exercice 10 : Test de sécurité complet
Write-Host "`n=== Exercice 10 : Test de sécurité complet ==="
Write-Host "Exécutez le script de vérification complet fourni par le formateur si disponible."
Write-Host "Résultats attendus : Toutes les fonctionnalités doivent être activées et opérationnelles. Aucune erreur dans le rapport de sécurité."
