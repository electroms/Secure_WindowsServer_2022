# Secure_WindowsServer_2022
Commun et clair pour documenter les trois scripts PowerShell que vous avez fournis :

---

````markdown
# Scripts PowerShell – Configuration et Sécurisation de Windows Server

Ce dépôt contient plusieurs scripts PowerShell conçus pour automatiser la configuration, le déploiement et le durcissement de serveurs Windows Server, notamment dans un environnement Active Directory avec les services DNS et DHCP.

## Contenu des scripts

### 1. `Configuration Active Directory avec DNS et DHCP.ps1`

Ce script automatise l'installation et la configuration des services suivants :
- **Active Directory Domain Services (AD DS)**
- **DNS Server**
- **DHCP Server**

Fonctionnalités :
- Promotion du serveur en tant que contrôleur de domaine
- Configuration initiale de la forêt et du domaine
- Installation et configuration du rôle DHCP avec une étendue réseau définie

### 2. `Durcissement Windows Server 2022.ps1`

Ce script applique une série de mesures de sécurité pour durcir un serveur Windows Server 2022 :
- Désactivation des services inutiles
- Configuration des politiques de sécurité locales
- Paramétrage des stratégies de mot de passe et de verrouillage de compte
- Désactivation des connexions anonymes et du partage non sécurisé
- Renforcement du pare-feu Windows

### 3. `param_tp3.ps1`

Script utilisé dans le cadre d’un TP (travaux pratiques) pour paramétrer automatiquement certains éléments système :
- Création et configuration de comptes utilisateurs
- Attribution de droits et permissions
- Configuration réseau de base
- Paramètres système pour l’environnement de test

## Prérequis

- Windows Server 2022 (ou version compatible)
- Exécution avec privilèges administrateur
- L’exécution de scripts doit être autorisée :  
  ```powershell
  Set-ExecutionPolicy RemoteSigned
````

## Utilisation

Exécutez chaque script dans PowerShell en tant qu'administrateur selon le besoin :

```powershell
# Exemple :
.\Configuration Active Directory avec DNS et DHCP.ps1
```

**⚠️ Attention :** Ces scripts modifient des paramètres système critiques. Il est recommandé de les tester d'abord dans un environnement de test ou de lab avant déploiement en production.

## Auteur

* Scripts réalisés dans le cadre d'un projet pédagogique ou d'une automatisation en environnement serveur Windows.

## Licence

Ces scripts sont distribués sans garantie. Utilisation à vos propres risques.

---

```

```
