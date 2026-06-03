# Advanced Unified PUA Uninstaller
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen)

> **Pipeline de remédiation PowerShell de niveau SOC pour les Applications Potentiellement Indésirables sur endpoints Windows.**  
> Conçu pour les équipes de Réponse sur Incident, les équipes Sécurité IT et les administrateurs systèmes confrontés aux pirates de navigateurs, adwares et familles de PUA groupés.

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Menaces couvertes](#menaces-couvertes)
- [Architecture du pipeline](#architecture-du-pipeline)
- [Mécanismes de sécurité](#mécanismes-de-sécurité)
- [Utilisation](#utilisation)
- [Mode DryRun](#mode-dryrun)
- [Ce qui est nettoyé](#ce-qui-est-nettoyé)
- [Ajouter de nouvelles cibles PUA](#ajouter-de-nouvelles-cibles-pua)
- [Prérequis](#prérequis)
- [Avertissement](#avertissement)

---

## Vue d'ensemble

Ce script fournit un pipeline de nettoyage structuré, sécurisé et auditable pour les familles de PUA connues sur les systèmes Windows. Il va bien au-delà de la simple suppression de fichiers — il traite la **surface de persistance complète** de chaque menace : processus, services, tâches planifiées, clés de registre (y compris les ruches hors ligne), politiques de navigateur et artefacts d'installation.

Il a été conçu avec une approche **defensive-first** : chaque suppression est soumise à une pile de validation multi-couches pour prévenir la destruction accidentelle de fichiers système légitimes, même en présence de conditions adversariales (attaques par lien symbolique, collisions de nommage, payloads obfusqués).

---

## Menaces couvertes

| Famille PUA | Type | Vecteurs principaux |
|---|---|---|
| **Shift** | Pirate de navigateur / espace de travail | Application Electron, installation par setup, auto-lancement via clés Run |
| **PDF Pro Suite** | Adware / faux outil PDF | Distribution MSI, injection de browser helper |
| **PDFInstaller** | Dropper / vecteur infostealer | Basé sur `node.exe`, staging dans le répertoire temp |
| **ManualFinder** | Adware / fausse recherche de manuels | Payloads JS dans `%TEMP%`, tâches planifiées à préfixe aléatoire |
| **OneStart** | Pirate de navigateur + groupeur PDF | Basé sur Chromium, persistance dans `system32\config\systemprofile`, détournement de politiques |
| **EpiBrowser** | Pirate de navigateur | Basé sur Chromium, technique `ShimInclusionList` dans le registre |

> 📌 **Dépôt de référence pour l'intel PUA :** [xephora/Threat-Remediation-Scripts](https://github.com/xephora/Threat-Remediation-Scripts)

---

## Architecture du pipeline

Le script exécute un pipeline strictement ordonné en 5 phases :

```
CONFIG ──► RESOLVE ──► NORMALIZE ──► VALIDATE ──► DELETE
```

**Phase 1 — CONFIG**  
Chargement de la threat intelligence (applications cibles, racines protégées, exceptions en liste blanche) et initialisation du transcript d'audit dans `%TEMP%`.

**Phase 2 — RESOLVE**  
Découverte de tous les profils utilisateurs via une énumération à double source (système de fichiers `C:\Users\` + CIM `Win32_UserProfile` pour les SIDs actifs). Expansion de tous les chemins relatifs par profil, résolution des patterns glob directement depuis le disque.

**Phase 3 — NORMALIZE**  
Tous les chemins collectés sont normalisés en chemins absolus en minuscules via `[System.IO.Path]::GetFullPath()`. Les lignes de commande des tâches planifiées sont assainies (séquences d'échappement supprimées, variables d'environnement expansées, payloads PS en Base64 décodés).

**Phase 4 — VALIDATE**  
Chaque chemin passe par un filtre de rejet à 4 couches avant toute action (voir [Mécanismes de sécurité](#mécanismes-de-sécurité)).

**Phase 5 — DELETE**  
Exécution de la suppression dans un ordre strict : Services → Tâches planifiées → Processus → Désinstallateurs binaires → Désinstallateurs MSI → Fichiers/Dossiers → Registre HKLM → Registre HKU (avec montage de ruches hors ligne).

---

## Mécanismes de sécurité

Ce script est conçu en partant du principe qu'un PUA peut tenter de résister ou d'exploiter le processus de nettoyage lui-même.

### Protection contre les attaques TOCTOU / Lien symbolique
Avant toute suppression de répertoire, une vérification finale via `Get-Item` confirme que la cible **n'est pas un ReparsePoint**. Cela prévient une attaque où un malware remplacerait son propre répertoire par une jonction vers `C:\Windows` quelques instants avant la suppression.

```powershell
if ($FinalCheck.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Write-Warning "[!] Point de reparse détecté au dernier moment sur $Path ! Suppression annulée."
    continue
}
```

### Validation de l'en-tête PE (Magic Bytes)
Avant d'exécuter tout désinstallateur binaire, le script lit les 2 premiers octets du fichier pour vérifier la signature `MZ` (`0x4D 0x5A`). Les fichiers non-PE sont ignorés silencieusement.

### Protection filesystem multi-couches

| Couche | Ce qu'elle protège |
|---|---|
| `HardProtectedRoots` | `C:\Windows`, `System32`, `SysWOW64` (avec exceptions en liste blanche pour les chemins PUA connus dans system32) |
| `ContainerRoots` | `C:\`, `C:\Users`, `C:\Program Files`, `C:\ProgramData`, etc. |
| Regex containers de profil | Bloque la suppression brute de `AppData\Local`, `AppData\Roaming`, `Downloads`, `Desktop`, `Documents` |

### Rejet des namespaces Win32 et ADS
Les chemins correspondant aux namespaces device `\\?\` / `\\.\` ou aux Alternate Data Streams (pattern `:$DATA`) sont rejetés avant tout traitement.

### Validation du binaire de service
Avant de supprimer un service, le script lit son `ImagePath` dans le registre. Si le chemin du binaire ne correspond à aucun mot-clé PUA connu, la suppression est annulée avec un avertissement de collision de nommage.

### Décodage des payloads Base64 dans les tâches planifiées
Toutes les lignes de commande des tâches planifiées sont inspectées à la recherche de patterns PowerShell `-EncodedCommand`. Les payloads détectés sont décodés et ajoutés à la chaîne d'analyse avant la mise en correspondance — contrecarrant une technique d'obfuscation courante des PUAs.

### Boucle de ruches de registre inversée
La boucle de nettoyage HKU est structurée en **Montage unique par utilisateur → itération de toutes les applications**, et non l'inverse. Cela minimise les cycles de montage/démontage de NTUSER.DAT et évite la contention des handles de registre. Un GC forcé (`GC.Collect()` + `WaitForPendingFinalizers()`) est appelé avant `reg unload` pour libérer tout handle PowerShell qui bloquerait l'opération.

---

## Utilisation

**Prérequis :** PowerShell 5.1+ — Doit être exécuté en tant qu'**Administrateur**.

```powershell
# Exécution standard (nettoyage en conditions réelles)
.\CleanPUA.ps1

# Audit en mode simulation (aucune modification apportée au système)
.\CleanPUA.ps1 -DryRun
```

Un transcript horodaté est automatiquement sauvegardé dans :
```
%TEMP%\CleanPUA_YYYYMMDD_HHMMSS.log
```

---

## Mode DryRun

Le switch `-DryRun` active une simulation complète du pipeline sans aucune modification système. Chaque action qui *serait* effectuée est affichée avec le préfixe `[DRY-RUN]`.

Utilisez ce mode pour :
- Auditer une machine avant de lancer le nettoyage réel
- Valider la couverture de la threat intelligence avant déploiement
- Générer des logs de preuves pour les rapports d'incident

```
[!] MODE DRY-RUN ACTIF : Aucune modification ne sera apportee au systeme.
[DRY-RUN] Service identifie a neutraliser : ShiftUpdaterService (Etat actuel: Running)
[DRY-RUN] Tache malveillante ciblee (ShiftLaunchTask) | Motif: Nom suspect + Binaire malveillant concordants.
[DRY-RUN] Fichier/Dossier a supprimer : c:\users\john\appdata\local\shift
[DRY-RUN] Cle HKLM a supprimer : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{95fcf903...}_is1
```

---

## Ce qui est nettoyé

Pour chaque PUA ciblé, le script supprime :

- **Services Windows** — arrêtés puis supprimés via `sc.exe delete` (repli : suppression directe de la clé de registre)
- **Tâches planifiées** — mises en correspondance par préfixe de nom, chemin URI ou contenu de ligne de commande décodé
- **Processus en cours** — terminés via `taskkill /F /T /PID` (arbre de processus complet)
- **Désinstallateurs binaires** — exécutés silencieusement (`/VERYSILENT /NORESTART`) si présents
- **Paquets MSI** — désinstallés via `msiexec /X` avec auto-découverte dans les deux ruches de registre x86 et x64
- **Répertoires et fichiers utilisateur** — par profil, avec support des globs pour les artefacts d'installation dans Downloads/Temp
- **Répertoires globaux** — `ProgramData`, `Program Files (x86)`, etc.
- **Clés de registre HKLM** — suppression directe des clés
- **Clés de registre HKU** — par utilisateur, avec support des wildcards, y compris le montage des ruches hors ligne pour les sessions inactives
- **Clés Run** — entrées d'auto-démarrage par utilisateur avec correspondance par wildcard
- **Politiques d'extensions de navigateur** — entrées forcées Chrome/Edge `ExtensionInstallForcelist` et `ExtensionSettings` dans HKLM et HKCU

---

## Ajouter de nouvelles cibles PUA

Ajoutez une nouvelle entrée dans le tableau `$TargetApps`. Tous les champs sont optionnels (utilisez `$null` ou `@()` pour les champs inutilisés) :

```powershell
@{
    Name                 = "MonPUA"
    ServiceNames         = @("MonPUAService")
    ProcessNames         = @("monpua", "monpua-updater")
    ProcessPathFilters   = @("*\appdata\local\monpua\*")
    MSICode              = $null                               # ex. "{GUID}" ou $null pour auto-découverte
    UninstallerRelPath   = "AppData\Local\MonPUA\unins000.exe"
    InstallLocationHint  = "AppData\Local\MonPUA"             # utilisé pour l'auto-découverte MSI
    UserDirectories      = @("AppData\Local\MonPUA", "AppData\Roaming\MonPUA")
    UserFiles            = @("Desktop\MonPUA.lnk")
    UserGlobs            = @("Downloads\MonPUA*.exe")
    GlobalDirectories    = @("C:\Program Files (x86)\MonPUA")
    HKLMRegPaths         = @("HKLM:\SOFTWARE\MonPUA")
    HKURegPaths          = @("Software\MonPUA", "Software\Microsoft\Windows\CurrentVersion\Uninstall\MonPUA")
    HKURunKeys           = @("MonPUA", "MonPUAUpdate*")        # supporte les wildcards
    TaskPrefixes         = @("MonPUATache", "MonPUAUpdate-")
    TaskURIs             = @("\MonPUA")
}
```

**Auto-découverte MSI :** Si `MSICode` est `$null` et `InstallLocationHint` est renseigné, le script analyse les deux ruches `HKLM:\SOFTWARE\...\Uninstall` et WOW6432Node pour trouver une valeur `InstallLocation` correspondante et en extraire le GUID automatiquement.

---

## Prérequis

| Prérequis | Détails |
|---|---|
| Système d'exploitation | Windows 10 / 11, Windows Server 2016+ |
| PowerShell | 5.1 ou supérieur |
| Privilèges | **Administrateur** (obligatoire — vérifié à l'exécution) |
| Dépendances | Aucune — basé uniquement sur PowerShell natif et les APIs Windows |

---

## Avertissement

Ce script effectue des **opérations destructives irréversibles** sur des fichiers, clés de registre, services et tâches planifiées.

- Toujours tester avec `-DryRun` d'abord sur une machine hors production.
- Consulter le transcript de log après l'exécution.
- L'auteur décline toute responsabilité en cas de perte de données résultant d'une mauvaise utilisation ou d'une mauvaise configuration.
- La threat intelligence (définitions des cibles PUA) peut devenir obsolète. Toujours vérifier la couverture sur des échantillons récents avant déploiement.