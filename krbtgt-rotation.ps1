param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("First", "Second")]
    [string]$Phase
)

$LogFile = "C:\Logs\KRBTGT-Rotation.log"

function Write-Log {
    param($Message)
    $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Date - $Message" | Out-File -FilePath $LogFile -Append
}

function Test-ADModule {
    if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Module Active Directory non disponible"
        throw "Le module Active Directory PowerShell n'est pas installé"
    }
    
    if (!(Get-Module -Name ActiveDirectory)) {
        Write-Log "Import du module Active Directory"
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

function Generate-ComplexPassword {
    # Génère un mot de passe complexe de 32 caractères
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = ""
    for ($i = 0; $i -lt 32; $i++) {
        $password += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $password
}

function Test-DomainController {
    try {
        $dc = Get-ADDomainController -Discover
        Write-Log "Contrôleur de domaine détecté: $($dc.Name)"
        return $true
    } catch {
        Write-Log "Impossible de contacter un contrôleur de domaine"
        return $false
    }
}

function Wait-ForReplication {
    param([int]$WaitMinutes = 15)
    
    Write-Log "Attente de $WaitMinutes minutes pour la réplication..."
    Start-Sleep -Seconds ($WaitMinutes * 60)
}

try {
    # Vérifier les prérequis
    Test-ADModule
    
    if (!(Test-DomainController)) {
        throw "Impossible de contacter un contrôleur de domaine"
    }
    
    # Créer le répertoire de logs s'il n'existe pas
    $LogDir = Split-Path $LogFile -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    if ($Phase -eq "First") {
        Write-Log "=== DÉBUT DE LA PREMIÈRE ROTATION KRBTGT ==="
        
        # Générer un nouveau mot de passe complexe
        $NewPasswordString = Generate-ComplexPassword
        $NewPassword = ConvertTo-SecureString -String $NewPasswordString -AsPlainText -Force
        
        # Obtenir les informations actuelles du compte KRBTGT
        $krbtgtAccount = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
        Write-Log "Dernière modification du mot de passe KRBTGT: $($krbtgtAccount.PasswordLastSet)"
        
        # Effectuer la première rotation
        Set-ADAccountPassword -Identity krbtgt -NewPassword $NewPassword -Reset
        Write-Log "Première rotation du mot de passe KRBTGT terminée avec succès"
        
        # Forcer la réplication
        Write-Log "Démarrage de la réplication forcée..."
        $repadminResult = repadmin /syncall /AeD 2>&1
        Write-Log "Réplication forcée terminée"
        
        Write-Log "IMPORTANT: Attendez au moins 10 heures avant d'exécuter la deuxième phase"
        Write-Log "Cela permet aux tickets existants d'expirer naturellement"
        
    }
    elseif ($Phase -eq "Second") {
        Write-Log "=== DÉBUT DE LA DEUXIÈME ROTATION KRBTGT ==="
        
        # Vérifier qu'assez de temps s'est écoulé depuis la première rotation
        $krbtgtAccount = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
        $timeSinceLastChange = (Get-Date) - $krbtgtAccount.PasswordLastSet
        
        if ($timeSinceLastChange.TotalHours -lt 10) {
            $remainingTime = 10 - $timeSinceLastChange.TotalHours
            Write-Log "ATTENTION: Il ne s'est écoulé que $([math]::Round($timeSinceLastChange.TotalHours, 2)) heures depuis la première rotation"
            Write-Log "Il est recommandé d'attendre encore $([math]::Round($remainingTime, 2)) heures"
            Write-Host "Voulez-vous continuer malgré tout? (y/N): " -NoNewline
            $response = Read-Host
            if ($response -ne "y" -and $response -ne "Y") {
                Write-Log "Deuxième rotation annulée par l'utilisateur"
                exit 0
            }
        }
        
        # Générer un nouveau mot de passe complexe
        $NewPasswordString = Generate-ComplexPassword
        $NewPassword = ConvertTo-SecureString -String $NewPasswordString -AsPlainText -Force
        
        # Effectuer la deuxième rotation
        Set-ADAccountPassword -Identity krbtgt -NewPassword $NewPassword -Reset
        Write-Log "Deuxième rotation du mot de passe KRBTGT terminée avec succès"
        
        # Forcer la réplication
        Write-Log "Démarrage de la réplication forcée..."
        $repadminResult = repadmin /syncall /AeD 2>&1
        Write-Log "Réplication forcée terminée"
        
        Write-Log "=== ROTATION KRBTGT COMPLÈTE ==="
        Write-Log "Surveillez les logs d'événements pour détecter d'éventuels problèmes d'authentification"
    }
    
    # Vérifier la réplication
    Write-Log "Vérification de la réplication sur tous les contrôleurs de domaine..."
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        try {
            $krbtgtOnDC = Get-ADUser -Identity krbtgt -Server $dc.Name -Properties PasswordLastSet
            Write-Log "DC $($dc.Name): Dernière modification mot de passe - $($krbtgtOnDC.PasswordLastSet)"
        } catch {
            Write-Log "Erreur lors de la vérification sur $($dc.Name): $($_.Exception.Message)"
        }
    }
    
} catch {
    Write-Log "ERREUR CRITIQUE: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.Exception.StackTrace)"
    exit 1
}