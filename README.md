# PUA Uninstaller
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

> **PowerShell remediation pipeline for Potentially Unwanted Applications (PUAs) on Windows endpoints.**
> Built for Incident Response (IR) teams, IT Security engineers, and system administrators dealing with persistent browser hijackers, adwares, and bundled PUA families.

---

## Table of Contents

- [Overview](#overview)
- [Covered Threats](#covered-threats)
- [Pipeline Architecture](#pipeline-architecture)
- [Security Mechanisms](#security-mechanisms)
- [Usage](#usage)
- [DryRun Mode](#dryrun-mode)
- [What Is Cleaned](#what-is-cleaned)
- [Adding New PUA Targets](#adding-new-pua-targets)
- [Prerequisites](#prerequisites)
- [Disclaimer](#disclaimer)

---

## Overview

This script provides a structured, secure, and auditable cleanup pipeline for known PUA families on Windows systems. It goes far beyond basic file deletion by wiping the **complete persistence surface** of each threat: processes, services, scheduled tasks, registry keys (including offline user hives), browser policies, and installer stubs.

Engineered with a **defensive-first** approach, every deletion undergoes a multi-layered validation stack to prevent accidental destruction of legitimate system files, even under adversarial conditions (symlink attacks, naming collisions, obfuscated payloads).

---

## Covered Threats

| PUA Family | Type | Main Vectors |
|---|---|---|
| **Shift** | Browser hijacker / fake workspace | Electron app, standard setup installer, auto-launch via Run keys |
| **PulseBrowser** | Browser hijacker | Chromium-based, multi-profile user staging, dual HKLM/HKCU run key persistence |
| **PDFSpark** | Malware stager / Infostealer & Adware | Electron app (Nativefier), Delphi installer, sandbox evasion (WINE), cross-persistence via `OneBrowser` |
| **PDFPro Suite** | Adware / fake PDF utility | MSI distribution, browser helper injection |
| **PDFInstaller** | Dropper / Infostealer vector | `node.exe` based, staging inside the temp directory |
| **ManualFinder** | Adware / fake manual search tool | JS payloads in `%TEMP%`, randomized prefix scheduled tasks |
| **OneStart** | Browser hijacker + PDF bundler | Chromium-based, persistence in `system32\config\systemprofile`, policy hijacking |
| **EpiBrowser** | Browser hijacker | Chromium-based, uses the `ShimInclusionList` registry technique |

> 📌 **Reference repository for PUA Intel:** [xephora/Threat-Remediation-Scripts](https://github.com/xephora/Threat-Remediation-Scripts)

---

## Pipeline Architecture

The script executes a strictly sequenced 5-phase remediation pipeline:

```
CONFIG ──► RESOLVE ──► NORMALIZE ──► VALIDATE ──► DELETE
```

**Phase 1 — CONFIG** Loads the threat intelligence matrix, initializes the audit transcript inside `%TEMP%`, and automatically generates the dynamic security regex pattern based on the configured app names, services, and processes.

**Phase 2 — RESOLVE** Discovers all user profiles via a dual-source enumeration (filesystem scavenging of `C:\Users\` + CIM query of `Win32_UserProfile` for active SIDs). Expands all relative paths per profile and resolves file glob patterns directly from the disk.

**Phase 3 — NORMALIZE** All collected paths are resolved to absolute, lowercase strings using `[System.IO.Path]::GetFullPath()`. Scheduled task command lines are sanitized (escaping sequences removed, environment variables expanded, and Base64-encoded PowerShell payloads decoded).

**Phase 4 — VALIDATE** Every single path is fed into a 4-layer rejection engine before any deletion occurs (see [Security Mechanisms](#security-mechanisms)).

**Phase 5 — DELETE** Executes remediation in a non-destructive safety order: Services ──► Scheduled Tasks ──► Active Processes ──► Binary Uninstallers ──► MSI Packaged Uninstallers ──► WMI Event Subscriptions ──► Files/Directories ──► HKLM Registry ──► HKU Registry (including offline NTUSER.DAT mounting).

---

## Security Mechanisms

This script assumes a PUA might actively resist or try to exploit the remediation process itself.

### TOCTOU / Symlink Attack Mitigation
Right before a directory deletion occurs, a final check via `Get-Item` validates that the target **is not a ReparsePoint**. This distributes defense against attacks where a malware replaces its own folder with a junction pointing to `C:\Windows` right before the deletion execution.

```powershell
if ($FinalCheck.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Write-Warning "[!] Un point de reparse/lien symbolique a ete detecte au dernier moment sur $Path ! Suppression annulee."
    continue
}
```

### PE Header Validation (Magic Bytes)
Before executing any vendor binary uninstaller found on the disk, the script opens the file stream and reads the first 2 bytes to confirm the `MZ` signature (`0x4D 0x5A`). Non-PE files are silently ignored.

### Multi-Layered Filesystem Safeguards

| Guard Layer | What It Protects |
|---|---|
| HardProtectedRoots | `C:\Windows`, `System32`, `SysWOW64` (with explicit allowlisted exceptions for known PUA stubs inside system32) |
| ContainerRoots | `C:\`, `C:\Users`, `C:\Program Files`, `C:\ProgramData`, etc. |
| User Profile Regex | Blocks bulk deletion of root profile folders like `AppData\Local`, `AppData\Roaming`, `Downloads`, `Desktop`, `Documents` |

### Win32 Device Namespaces and ADS Rejection
Paths matching Win32 device namespaces (`\\?\` or `\\.\`) or Alternate Data Streams (pattern `:$DATA`) are instantly flagged and rejected before entering the deletion queue.

### Service Binary Verification (Automated Guard)
Before knocking out a service, the script parses its registry `ImagePath`. If the binary path does not match the dynamically generated regex keywords derived from the threat intel, the deletion is canceled to prevent naming collisions with legitimate services.

### Scheduled Task Base64 Decoding
All scheduled task action command lines are scanned for PowerShell `-EncodedCommand` arguments (and all its common aliases like `-enc`, `-encoded`, etc.). Detected payloads are decoded on-the-fly and appended to the analysis string before string matching, bypassing common obfuscation tricks.

### Inverted Registry Hive Loop
The HKU cleanup loop is structured as **Single mount per user ──► iterate all apps**, rather than mounting for each PUA. This minimizes registry churn and avoids handle leaks. A forced Garbage Collection (`GC.Collect()` + `WaitForPendingFinalizers()`) is called right before `reg unload` to free any locking PowerShell providers.

---

## Usage

**Prerequisite:** PowerShell 5.1+ — Must be executed from an **Elevated (Administrator)** shell.

```powershell
# Standard execution (Live system remediation)
.\CleanPUA.ps1

# Audit mode (Simulation only - no system changes)
.\CleanPUA.ps1 -DryRun
```

A timestamped audit transcript is automatically saved to:
```
%TEMP%\CleanPUA_YYYYMMDD_HHMMSS.log
```

---

## DryRun Mode

The `-DryRun` switch activates a full pipeline simulation. Every single action that *would* be executed on a live endpoint is logged with a `[DRY-RUN]` prefix.

Use this mode to:
- Audit an endpoint prior to running live remediation
- Validate threat intel coverage before wide deployment
- Generate tamper-proof evidence logs for incident documentation

```
[!] MODE DRY-RUN ACTIF : Aucune modification ne sera apporte au systeme.
[DRY-RUN] Service identifie a neutraliser : ShiftUpdaterService (Etat actuel: Running)
[DRY-RUN] Tache malveillante ciblee (ShiftLaunchTask) | Motif: Nom suspect + Binaire malveillant concordants.
[DRY-RUN] Fichier/Dossier a supprimer : c:\users\john\appdata\local\shift
[DRY-RUN] Cle HKLM a supprimer : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{95fcf903...}_is1
```

---

## What Is Cleaned

For every targeted PUA family, the script automatically remediates:

- **Windows Services** — Stopped and deleted via `sc.exe delete` (falls back to direct registry key deletion on error).
- **Scheduled Tasks** — Matched via name prefix, folder URI path, or decoded command line arguments.
- **Active Processes** — Terminated using `taskkill /F /T /PID` (kills the entire process tree).
- **Binary Uninstallers** — Executed silently (`/VERYSILENT /NORESTART`) with native integrity checks.
- **MSI Packages** — Cleaned via `msiexec /X` with an automated discovery engine scanning both x86 and x64 registry hives.
- **WMI Persistence** — Automatic scanning and deletion of malicious `__EventConsumer`, `__EventFilter`, and `__FilterToConsumerBinding` objects matching the threat intel signatures.
- **User Files & Directories** — Cleaned across all profiles, with glob support for temporary/download staging paths.
- **Global Roots** — Cleaned inside `ProgramData`, `Program Files`, and shared OS locations.
- **HKLM Registry Hives** — Full subkey recursive deletion.
- **HKLM Run Keys** — Automated machine-wide startup value removal (`PulseBrowser`, etc.).
- **HKU Registry Hives** — Scanned across active sessions and offline profiles (via manual hive loading), supporting wildcards and per-user `Run` key auto-starts.
- **Browser Policies** — Wipes malicious forced extensions (`ExtensionInstallForcelist` and `ExtensionSettings`) inside Google Chrome and Microsoft Edge configurations based on the automated regex signatures.

---

## Adding New PUA Targets

Simply append a new hashtable to the `$TargetApps` array. Every single field is optional (use `$null` or `@()` for unused fields):

```powershell
@{
    Name                 = "MyNewPUA"
    ServiceNames         = @("MyPUAService")
    ProcessNames         = @("mypua", "mypua-updater")
    ProcessPathFilters   = @("*\appdata\local\mypua\*")
    MSICode              = $null                               # e.g., "{GUID}" or $null for auto-discovery
    UninstallerRelPath   = "AppData\Local\MyPUA\unins000.exe"
    InstallLocationHint  = "AppData\Local\MyPUA"               # Used for automated MSI discovery
    UserDirectories      = @("AppData\Local\MyPUA", "AppData\Roaming\MyPUA")
    UserFiles            = @("Desktop\MyNewPUA.lnk")
    UserGlobs            = @("Downloads\MyPUA*.exe")
    GlobalDirectories    = @("C:\Program Files (x86)\MyPUA")
    HKLMRegPaths         = @("HKLM:\SOFTWARE\MyPUA")
    HKLMRunKeys          = @("MyPUAAutoStart*")                # Machine autoruns (supports wildcards)
    HKURegPaths          = @("Software\MyPUA")
    HKURunKeys           = @("MyPUA", "MyPUAUpdate*")          # User autoruns (supports wildcards)
    TaskPrefixes         = @("MyPUATask-", "MyPUAUpdate")
    TaskURIs             = @("\MyPUAFolder")
}
```

**Automated MSI Discovery:** If `MSICode` is left as `$null` and an `InstallLocationHint` is provided, the script automatically parses standard Windows Uninstall registry hives (including 32-bit redirections) to locate a matching software directory and dynamically extract the uninstallation GUID.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS Support | Windows 10 / 11, Windows Server 2016+ |
| PowerShell Engine | 5.1 or higher |
| Privileges | **Elevated (Administrator)** — Checked at runtime |
| Dependencies | None — 100% native PowerShell commands and core Windows binaries |

---

## Disclaimer

This script performs **irreversible, destructive operations** on files, registry paths, services, and scheduled tasks.

- Always run the script with the `-DryRun` switch on a non-production test device first.
- Inspect the generated transcript file thoroughly after execution.
- The author accepts no liability for data loss or system degradation caused by misuse or incorrect configuration of the target matrices.
- Cyber threat landscapes shift constantly. Ensure target definitions match recent malware or PUA variants before executing in corporate environments.
