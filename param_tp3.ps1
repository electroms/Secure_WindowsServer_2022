<#
.SYNOPSIS
Décrit le but général du script PowerShell.

.DESCRIPTION
Ce script exécute une série d'opérations automatisées pour répondre à un besoin spécifique. Il est conçu pour être utilisé dans un environnement Windows PowerShell et peut inclure des fonctionnalités telles que la gestion de fichiers, l'automatisation de tâches système, ou l'interaction avec des services externes.

.PARAMETER <NomDuParamètre>
Décrit le rôle de chaque paramètre utilisé dans le script.

.EXAMPLE
Exemple d'utilisation du script avec des paramètres appropriés.

.NOTES
Auteur : [Pierre-Henry Barge]
Date de création : [10.07.2025]
Version : 1.0

#>
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("RotateKRBTGT", "MonitorKerberos", "DetectAnomalies", "TestDelegation")]
    [string]$Action,
    [ValidateSet("First", "Second")]
    [string]$Phase,
    [int]$Hours = 24,
    [string]$ServiceAccount = "SVC-WebApp",
    [string]$TargetService = "HTTP/DC01.corporate.local",
    [string]$ResourceServiceAccount = "SVC-Database"
)

$LogFile = "C:\Logs\KRBTGT-Rotation.log"
function Write-Log {
    param($Message)
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Date - $Message" | Out-File -FilePath $LogFile -Append
}

function Rotate-KRBTGT {
    param([Parameter(Mandatory=$true)][ValidateSet("First", "Second")][string]$Phase)
    try {
        if ($Phase -eq "First") {
            Write-Log "Début de la première rotation KRBTGT"
            $NewPassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
            Set-ADAccountPassword -Identity krbtgt -NewPassword $NewPassword -Reset
            Write-Log "Première rotation terminée avec succès"
        }
        elseif ($Phase -eq "Second") {
            Write-Log "Début de la deuxième rotation KRBTGT"
            $NewPassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force
            Set-ADAccountPassword -Identity krbtgt -NewPassword $NewPassword -Reset
            Write-Log "Deuxième rotation terminée avec succès"
        }
        repadmin /syncall /AeD
        Write-Log "Réplication forcée"
    } catch {
        Write-Log "Erreur : $($_.Exception.Message)"
    }
}

function Monitor-Kerberos {
    # Nettoyage des jobs et abonnements
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
    Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue

    Write-Host "🔍 SURVEILLANCE KERBEROS EN TEMPS RÉEL" -ForegroundColor Green -BackgroundColor Black
    Write-Host "======================================" -ForegroundColor Green
    Write-Host "Appuyez sur Ctrl+C pour arrêter..." -ForegroundColor Yellow
    Write-Host ""

    $EventsToMonitor = @(4768, 4769, 4771, 4772, 4624, 4625)
    $SuspiciousPatterns = @("0x40810000", "0x40800000", "0x40810010", "0x60810010")

    while ($true) {
        try {
            $RecentEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = $EventsToMonitor
                StartTime = (Get-Date).AddSeconds(-5)
            } -ErrorAction SilentlyContinue

            foreach ($Event in $RecentEvents) {
                $TimeStamp = Get-Date -Format "HH:mm:ss"
                Write-Host "$TimeStamp - EventID: $($Event.Id) - $($Event.Message.Substring(0, [Math]::Min(80, $Event.Message.Length)))"
            }
            Write-Host "." -NoNewline -ForegroundColor DarkGreen
            Start-Sleep -Seconds 5
        } catch {
            Write-Host "!" -NoNewline -ForegroundColor Red
            Start-Sleep -Seconds 10
        }
    }
}

function Detect-KerberosAnomalies {
    param([int]$Hours = 24)
    # Exemple simple, à adapter selon vos besoins
    $since = (Get-Date).AddHours(-$Hours)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4769
        StartTime = $since
    } -ErrorAction SilentlyContinue

    $SuspiciousTickets = $events | Where-Object { $_.Message -match "0x40810000" }
    $ExpiredTickets = $events | Where-Object { $_.Message -match "expired" }
    $InvalidServices = $events | Where-Object { $_.Message -match "unknown" }
    $FailedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$since} -ErrorAction SilentlyContinue)
    $SuspiciousAccounts = $events | Where-Object { $_.Message -match "krbtgt" }

    return [PSCustomObject]@{
        SuspiciousTickets = $SuspiciousTickets.Count
        ExpiredTickets    = $ExpiredTickets.Count
        InvalidServices   = $InvalidServices.Count
        FailedLogins      = $FailedLogins.Count
        SuspiciousAccounts= $SuspiciousAccounts.Count
    }
}

function Show-SimpleReport {
    param($Report)
    Write-Host "Tickets suspects: $($Report.SuspiciousTickets)" -ForegroundColor Yellow
    Write-Host "Tickets expirés: $($Report.ExpiredTickets)" -ForegroundColor Yellow
    Write-Host "Services invalides: $($Report.InvalidServices)" -ForegroundColor Yellow
    Write-Host "Échecs connexion: $($Report.FailedLogins)" -ForegroundColor Yellow
    Write-Host "Comptes suspects: $($Report.SuspiciousAccounts)" -ForegroundColor Yellow
}

function Test-ConstrainedDelegation {
    param(
        [Parameter(Mandatory=$true)][string]$ServiceAccount,
        [Parameter(Mandatory=$true)][string]$TargetService,
        [string]$TestUser = "Administrateur"
    )
    # Vérifie la délégation contrainte (exemple simple)
    try {
        $adUser = Get-ADUser -Identity $ServiceAccount -Properties msDS-AllowedToDelegateTo
        if ($adUser.'msDS-AllowedToDelegateTo' -contains $TargetService) {
            return $true
        } elseif ($adUser.'msDS-AllowedToDelegateTo') {
            return $null
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

function Test-RBCD {
    param([string]$ResourceServiceAccount)
    try {
        $rbcdConfig = Get-ADUser -Identity $ResourceServiceAccount -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
        if ($rbcdConfig.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            Write-Host "✅ RBCD configurée sur $ResourceServiceAccount" -ForegroundColor Green
            $descriptor = $rbcdConfig.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            $rawSD = $descriptor
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ($rawSD, 0)
            Write-Host "Comptes autorisés à déléguer vers $ResourceServiceAccount :" -ForegroundColor Yellow
            foreach ($ace in $sd.DiscretionaryAcl) {
                try {
                    $sid = $ace.SecurityIdentifier
                    $principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    Write-Host "  - $principal" -ForegroundColor Gray
                } catch {
                    Write-Host "  - $sid" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "❌ Aucune RBCD configurée sur $ResourceServiceAccount" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Erreur lors de la vérification RBCD : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- MAIN EXECUTION ---
switch ($Action) {
    "RotateKRBTGT" {
        if (-not $Phase) { throw "Le paramètre -Phase est requis pour RotateKRBTGT." }
        Rotate-KRBTGT -Phase $Phase
    }
    "MonitorKerberos" {
        Monitor-Kerberos
    }
    "DetectAnomalies" {
        Write-Host "DÉMARRAGE ANALYSE KERBEROS" -ForegroundColor White
        Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
        $AnomaliesReport = Detect-KerberosAnomalies -Hours $Hours
        Show-SimpleReport -Report $AnomaliesReport
        try {
            if (!(Test-Path "C:\temp")) { 
                New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
            }
            $ReportFile = "C:\temp\KerberosReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $ReportContent = @"
RAPPORT KERBEROS - $(Get-Date)
==============================

Tickets suspects: $($AnomaliesReport.SuspiciousTickets)
Tickets expirés: $($AnomaliesReport.ExpiredTickets)
Services invalides: $($AnomaliesReport.InvalidServices)
Échecs connexion: $($AnomaliesReport.FailedLogins)
Comptes suspects: $($AnomaliesReport.SuspiciousAccounts)

Généré le: $(Get-Date)
"@
            $ReportContent | Out-File -FilePath $ReportFile -Encoding UTF8
            Write-Host "Rapport sauvegardé: $ReportFile" -ForegroundColor Green
        } catch {
            Write-Warning "Impossible de sauvegarder le rapport: $($_.Exception.Message)"
        }
        Write-Host "Analyse terminée." -ForegroundColor Green
    }
    "TestDelegation" {
        Write-Host "Début du test de délégation contrainte..." -ForegroundColor Cyan
        $result = Test-ConstrainedDelegation -ServiceAccount $ServiceAccount -TargetService $TargetService
        Write-Host "`n=== Résultat du test ===" -ForegroundColor Cyan
        switch ($result) {
            $true { Write-Host "✅ SUCCÈS : La délégation contrainte fonctionne" -ForegroundColor Green }
            $false { Write-Host "❌ ÉCHEC : La délégation contrainte ne fonctionne pas" -ForegroundColor Red }
            $null { Write-Host "⚠️  INDÉTERMINÉ : Configuration correcte mais test de ticket impossible" -ForegroundColor Yellow }
        }
        Write-Host "`n=== Test RBCD (Resource-Based Constrained Delegation) ===" -ForegroundColor Cyan
        Test-RBCD -ResourceServiceAccount $ResourceServiceAccount
    }
}
