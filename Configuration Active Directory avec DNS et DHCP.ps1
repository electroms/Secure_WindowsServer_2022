# Script PowerShell : Configuration Active Directory avec DNS et DHCP
# Domaine : corporate.local

# --- Phase 1 : Préparation du serveur ---

# 1.1 Configuration réseau
Write-Host "Configuration de l'adresse IP statique..."
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.1.10

# 1.2 Renommage du serveur
Write-Host "Renommage du serveur..."
Rename-Computer -NewName "DC01" -Restart

# --- Phase 2 : Installation et configuration d'Active Directory ---

# 2.1 Installation des rôles
Write-Host "Installation des rôles AD DS et outils de gestion..."
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name RSAT-AD-Tools, RSAT-DNS-Server

# 2.2 Promotion en contrôleur de domaine
Write-Host "Promotion du serveur en contrôleur de domaine..."
Import-Module ADDSDeployment
$SecureStringPwd = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Install-ADDSForest -DomainName "corporate.local" -DomainNetbiosName "CORPORATE" -InstallDns:$true -SafeModeAdministratorPassword $SecureStringPwd -Force:$true

# 2.3 Vérification de l'installation
Write-Host "Vérification des services AD..."
Get-Service -Name "ADWS", "DNS", "KDC", "NETLOGON" | Format-Table Name, Status
Write-Host "Test de la résolution DNS..."
nslookup corporate.local
nslookup dc01.corporate.local

# --- Phase 3 : Configuration du DNS ---

# 3.1 Vérification des zones DNS
Write-Host "Affichage des zones DNS..."
Get-DnsServerZone | Format-Table ZoneName, ZoneType, DynamicUpdate
Write-Host "Vérification des enregistrements A..."
Get-DnsServerResourceRecord -ZoneName "corporate.local" -RRType A

# 3.2 Configuration des redirecteurs DNS
Write-Host "Ajout des redirecteurs DNS publics..."
Add-DnsServerForwarder -IPAddress 8.8.8.8, 8.8.4.4

# 3.3 Création d'enregistrements personnalisés
Write-Host "Ajout d'un enregistrement A personnalisé..."
Add-DnsServerResourceRecordA -ZoneName "corporate.local" -Name "intranet" -IPv4Address "192.168.1.50"
Write-Host "Ajout d'un enregistrement CNAME personnalisé..."
Add-DnsServerResourceRecordCName -ZoneName "corporate.local" -Name "www" -HostNameAlias "intranet.corporate.local"

# --- Phase 4 : Installation et configuration du DHCP ---

# 4.1 Installation du rôle DHCP
Write-Host "Installation du rôle DHCP..."
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Write-Host "Autorisation du serveur DHCP dans AD..."
Add-DhcpServerInDC -DnsName "dc01.corporate.local" -IPAddress 192.168.1.10

# --- Phase 5 : Création de la structure organisationnelle ---

# 5.1 Création des unités d'organisation
Write-Host "Création des OUs principales..."
New-ADOrganizationalUnit -Name "Utilisateurs" -Path "DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "Ordinateurs" -Path "DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "Serveurs" -Path "DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "Groupes" -Path "DC=corporate,DC=local"

Write-Host "Création des sous-OUs par département..."
New-ADOrganizationalUnit -Name "Direction" -Path "OU=Utilisateurs,DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "RH" -Path "OU=Utilisateurs,DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "IT" -Path "OU=Utilisateurs,DC=corporate,DC=local"
New-ADOrganizationalUnit -Name "Commercial" -Path "OU=Utilisateurs,DC=corporate,DC=local"

# 5.2 Création d'utilisateurs de test
Write-Host "Création d'utilisateurs de test..."
$UserPwd = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-ADUser -Name "Jean Dupont" -GivenName "Jean" -Surname "Dupont" -SamAccountName "jdupont" -UserPrincipalName "jdupont@corporate.local" -Path "OU=Direction,OU=Utilisateurs,DC=corporate,DC=local" -AccountPassword $UserPwd -Enabled $true
New-ADUser -Name "Marie Martin" -GivenName "Marie" -Surname "Martin" -SamAccountName "mmartin" -UserPrincipalName "mmartin@corporate.local" -Path "OU=RH,OU=Utilisateurs,DC=corporate,DC=local" -AccountPassword $UserPwd -Enabled $true
New-ADUser -Name "Pierre Durand" -GivenName "Pierre" -Surname "Durand" -SamAccountName "pdurand" -UserPrincipalName "pdurand@corporate.local" -Path "OU=IT,OU=Utilisateurs,DC=corporate,DC=local" -AccountPassword $UserPwd -Enabled $true

# 5.3 Création de groupes de sécurité
Write-Host "Création de groupes de sécurité..."
New-ADGroup -Name "Administrateurs IT" -GroupScope Global -GroupCategory Security -Path "OU=Groupes,DC=corporate,DC=local"
New-ADGroup -Name "Utilisateurs RH" -GroupScope Global -GroupCategory Security -Path "OU=Groupes,DC=corporate,DC=local"
New-ADGroup -Name "Direction" -GroupScope Global -GroupCategory Security -Path "OU=Groupes,DC=corporate,DC=local"

Write-Host "Ajout d'utilisateurs aux groupes..."
Add-ADGroupMember -Identity "Administrateurs IT" -Members "pdurand"
Add-ADGroupMember -Identity "Utilisateurs RH" -Members "mmartin"
Add-ADGroupMember -Identity "Direction" -Members "jdupont"

# --- Phase 6 : Tests et validation ---

# 6.1 Tests DNS
Write-Host "Tests de résolution DNS..."
nslookup corporate.local
nslookup dc01.corporate.local
nslookup _ldap._tcp.corporate.local
nslookup -type=SRV _ldap._tcp.corporate.local

# 6.2 Tests d'authentification
Write-Host "Test d'authentification avec les utilisateurs créés (à lancer sur un poste client joint au domaine)..."
Write-Host 'runas /user:corporate\jdupont cmd'
