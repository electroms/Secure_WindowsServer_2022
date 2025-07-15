# TP2 - Durcissement Windows Server 2022
# Bonnes Pratiques Zero Trust pour la Sécurisation des Services
# Merci de relire le code source dans son intégralité avant de l'éxécuter
# Prérequis : assurez-vous que le dossier temp est bien présent sur la racine du disque C: (sinon créer le)
# Certaines étapes peuvent prendre du temps notamment à la partie 3 dans la configuration du WDAC


# =========================
# Partie 1 : Moindre Privilège pour les Services
# =========================

# 1.1 Audit des privilèges des services actuels
Write-Host "=== Audit des privilèges des services ===" -ForegroundColor Cyan
$services = Get-WmiObject -Class Win32_Service
$report = foreach ($service in $services) {
    [PSCustomObject]@{
        ServiceName = $service.Name
        DisplayName = $service.DisplayName
        Account     = $service.StartName
        State       = $service.State
        RiskLevel   = if ($service.StartName -eq "LocalSystem") {"HIGH"}
                      elseif ($service.StartName -like "*Administrator*") {"MEDIUM"}
                      else {"LOW"}
    }
}
$report | Export-Csv -Path "C:\Audit_Services.csv" -NoTypeInformation

# 1.2 Création de comptes de service dédiés
Write-Host "=== Création d'un compte de service local ===" -ForegroundColor Cyan
$SecurePassword = ConvertTo-SecureString "P@ssw0rd!Service123" -AsPlainText -Force
if (-not (Get-LocalUser -Name "svc_webapp" -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name "svc_webapp" -Password $SecurePassword -Description "Service account for web application" -PasswordNeverExpires
}

# Ajouter le droit "Log on as a service"
Write-Host "=== Attribution du droit 'Log on as a service' ===" -ForegroundColor Cyan
secedit /export /cfg C:\temp\secpol.cfg
(Get-Content C:\temp\secpol.cfg) -replace "SeServiceLogonRight = .*", "SeServiceLogonRight = svc_webapp" | Out-File C:\temp\secpol_new.cfg
secedit /configure /db C:\temp\secedit.sdb /cfg C:\temp\secpol_new.cfg

# Création d'un service de test
Write-Host "=== Création d'un service de test ===" -ForegroundColor Cyan
sc.exe create "TestSecureService" binPath="C:\Windows\System32\notepad.exe" obj=".\svc_webapp" password="P@ssw0rd!Service123"

# 1.3 Configuration avancée des permissions
Write-Host "=== Configuration des permissions sur C:\SecureServices ===" -ForegroundColor Cyan
$dir = "C:\SecureServices"
if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory }
$acl = Get-Acl $dir
$acl.SetAccessRuleProtection($true, $false)
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("svc_webapp", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrateurs", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($adminRule)
Set-Acl -Path $dir -AclObject $acl
Get-Acl $dir | Format-List

# =========================
# Partie 2 : Monitoring des Modifications de Services
# =========================

Write-Host "=== Activation de l'audit des modifications de services ===" -ForegroundColor Cyan
auditpol /set /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

# Détection automatique des sous-catégories d'audit
Write-Host "=== DÉTECTION DES SOUS-CATÉGORIES D'AUDIT ===" -ForegroundColor Cyan
$subcategories = cmd /c "auditpol /list /subcategory:*"
$relevantLines = $subcategories | Where-Object { $_ -match "^\s*[A-Za-z].*" -and $_ -notmatch "^(Sous-catégorie|Subcategory|Category|Catégorie)" }
Write-Host "Sous-catégories détectées sur votre système :" -ForegroundColor Yellow
$relevantLines | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
$targetSubcategories = @()
foreach ($line in $relevantLines) {
    if ($line -match "System|Integrity|Extension|Security|Process") {
        $targetSubcategories += $line.Trim()
    }
}
Write-Host "`nSous-catégories pertinentes trouvées :" -ForegroundColor Green
$targetSubcategories | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
Write-Host "`n=== CONFIGURATION AVEC LES NOMS DÉTECTÉS ===" -ForegroundColor Cyan
foreach ($subcategory in $targetSubcategories) {
    Write-Host "Test de configuration : $subcategory" -ForegroundColor Yellow
    $result = cmd /c "auditpol /set /subcategory:`"$subcategory`" /success:enable /failure:enable 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Host " Configuré avec succès : $subcategory" -ForegroundColor Green
    } else {
        Write-Host " Échec : $subcategory" -ForegroundColor Red
        Write-Host "   Erreur : $result" -ForegroundColor Red
    }
}

# Export et modification de la stratégie locale d'audit
secedit /export /cfg C:\temp\audit_policy.cfg
$content = Get-Content C:\temp\audit_policy.cfg
$content = $content -replace "AuditSystemEvents = 0", "AuditSystemEvents = 3"
$content | Out-File C:\temp\audit_policy_new.cfg
secedit /configure /db C:\temp\secedit.sdb /cfg C:\temp\audit_policy_new.cfg

# Surveillance en temps réel et analyse des événements : scripts externes à exécuter
# .\ServiceMonitoring.ps1
# .\AnalyseEvents.ps1

# =========================
# Partie 3 : Contrôle d'Intégrité des Binaires
# =========================

Write-Host "=== Configuration de WDAC (Windows Defender Application Control) ===" -ForegroundColor Cyan
$PolicyPath = "C:\WDAC\BasePolicy.xml"
New-Item -Path "C:\WDAC" -ItemType Directory -Force
New-CIPolicy -FilePath $PolicyPath -Level Publisher -Fallback Hash -UserPEs

# Surveillance d'intégrité : scripts externes à exécuter
# .\IntegrityMonitoring.ps1
# .\Test-FileIntegrity.ps1

# =========================
# Partie 4 : Segmentation Réseau
# =========================

Write-Host "=== Configuration stricte du pare-feu Windows Defender ===" -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block

# Règles spécifiques pour services critiques
New-NetFirewallRule -DisplayName "RDP Access - Admin Network" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "192.168.1.100-192.168.1.110" -Action Allow
New-NetFirewallRule -DisplayName "Web Service - Limited Access" -Direction Inbound -Protocol TCP -LocalPort 80,443 -RemoteAddress "192.168.1.0/24" -Action Allow
New-NetFirewallRule -DisplayName "Block Outbound - Suspicious Ports" -Direction Outbound -Protocol TCP -RemotePort 4444,6666,8080 -Action Block

# Surveillance du trafic réseau : script externe à exécuter
# .\NetworkConnectionsMonitoring.ps1

# =========================
# Partie 5 : Détection Comportementale des Processus Anormaux
# =========================

# Installation et configuration de Sysmon (à adapter selon environnement)
# Télécharger Sysmon et placer le fichier de configuration sysmon-config.xml dans C:\temp
# .\Sysmon64.exe -accepteula -i C:\temp\sysmon-config.xml

# Détection comportementale : scripts externes à exécuter
# .\BehaviourDetection.ps1
# .\scoring.ps1

# =========================
# Partie 6 : Intégration et Tests
# =========================

Write-Host "=== Simulation d'attaque pour test des mesures ===" -ForegroundColor Cyan
# Test 1 : Création d'un service suspect
sc.exe create "TestMaliciousService" binPath="C:\Windows\System32\calc.exe" obj="LocalSystem"
# Test 2 : Exécution d'une commande PowerShell encodée
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-Process"))
Start-Process powershell.exe -ArgumentList "-EncodedCommand $encodedCommand"
# Test 3 : Tentative de modification d'un binaire système (commenté par sécurité)
# Copy-Item "C:\Windows\System32\calc.exe" "C:\Windows\System32\services.exe.bak"

# =========================
# Partie 7 : Automatisation et Maintenance
# =========================

Write-Host "=== Planification des tâches de sécurité ===" -ForegroundColor Cyan
# Tâche de vérification d'intégrité quotidienne
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\IntegrityCheck.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "DailyIntegrityCheck" -Action $action -Trigger $trigger -Principal $principal -Description "Vérification quotidienne de l'intégrité des fichiers système"

# Tâche de génération de rapport hebdomadaire
$weeklyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\WeeklySecurityReport.ps1"
$weeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00"
Register-ScheduledTask -TaskName "WeeklySecurityReport" -Action $weeklyAction -Trigger $weeklyTrigger -Principal $principal -Description "Rapport de sécurité hebdomadaire"

# Script de maintenance automatique : à exécuter séparément
# .\WeeklySecurityReport.ps1

Write-Host "=== Durcissement terminé. Veuillez exécuter les scripts complémentaires fournis si besoin. ===" -ForegroundColor Green
