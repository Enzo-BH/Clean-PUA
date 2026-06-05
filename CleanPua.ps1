<#
.SYNOPSIS
    Advanced Unified PUA Uninstaller
.DESCRIPTION
    Pipeline: CONFIG -> RESOLVE -> NORMALIZE -> VALIDATE -> DELETE
    Features: 
    - Strict path normalization and failsafe validation.
    - Inverted offline registry loop (Mount once per user).
    - MSI Discovery in both x86 and x64 registry hives.

    __________REPO A CHECKER SI NOUVEAUX PUAs :__________
    https://github.com/xephora/Threat-Remediation-Scripts
#>

param (
    [switch]$DryRun
)

#  VERIFICATION DES PRIVILEGES ADMINISTRATEUR REQUIS
$isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run elevated. (Administrator privileges required)' }

#  INITIALISATION DU TRANSCRIPT DE LOG DANS LE DOSSIER TEMPORAIRE
$LogFile = Join-Path -Path $env:TEMP -ChildPath "CleanPUA_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try {
    Start-Transcript -Path $LogFile -Force -ErrorAction Stop
} catch {
    Write-Warning "[!] Impossible de demarrer le Transcript (Environnement restreint/CI-CD). Poursuite de l'execution..."
}
#  NOTIFICATION SI LE MODE SIMULATION DRY-RUN EST ACTIVE
if ($DryRun) {
    Write-Host "[!] MODE DRY-RUN ACTIF : Aucune modification ne sera apportee au systeme." -ForegroundColor Yellow
}

Write-Host "[*] INITIALISATION SOC PIPELINE" -ForegroundColor Cyan

#  DOUBLE DECOUVERTE DES PROFILS
Write-Host "[-] Collecte des profils utilisateurs (Fichiers & Registre)..." -ForegroundColor Gray
$FileSystemProfiles = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | 
    Where-Object { 
        -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and 
        $_.Name -notmatch "^(All Users|Default User)$" 
    } | 
    Select-Object -ExpandProperty FullName
#  NORMALISATION EN MINUSCULES DES RACINES DE PROFILS DISQUE
$ProfileRoots = $FileSystemProfiles | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() }
#  COLLECTE DES PROFILS VALIDES DANS LE REGISTRE AVEC SIDS ACTIFS
$RegistryProfiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special }

# STRUCTURE WHITELIST
$HardProtectedRoots = @( "c:\windows", "c:\windows\system32", "c:\windows\syswow64" )
$ContainerRoots = @(
    "c:\", "c:\users", "c:\programdata", "c:\program files", "c:\program files (x86)",
    "c:\users\public", "c:\users\default", "c:\users\administrator", "c:\users\localservice"
)
# ALLOWLIST A SUPPRIMER 
$ProtectedWindowsExceptions = @(
    "c:\windows\system32\config\systemprofile\appdata\local\onestart.ai",
    "c:\windows\system32\config\systemprofile\pdfeditor"
)
#  THREAT INTEL
$TargetApps = @(
    @{
        Name                 = "Shift"
        ServiceNames         = @("ShiftUpdaterService", "ShiftUpdateSvc")
        ProcessNames         = @("shift", "shift-worker", "shift-updater", "Shift--Calendars", "Shift--Browser")
        ProcessPathFilters   = @("*\appdata\local\shift\*", "*\appdata\local\shift-updater\*", "*\appdata\local\shiftdata\*") 
        MSICode              = $null
        UninstallerRelPath   = "AppData\Local\Shift\unins000.exe" 
        InstallLocationHint  = $null
        UserDirectories      = @("AppData\Local\Shift", "AppData\Local\shift-updater", "AppData\Local\ShiftData", "AppData\Roaming\Shift", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Shift")
        UserFiles            = @("Desktop\Shift Browser.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Shift\Shift Browser.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Shift.lnk")
        UserGlobs            = @("Downloads\Shift - *.exe", "Downloads\Shift*.exe", "Downloads\Shift*.msi")
        GlobalDirectories    = @()
        HKLMRegPaths         = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{95fcf903-63b1-44bd-ab77-358a5bd30aae}_is1")
        HKURegPaths          = @("Software\Shift", "SOFTWARE\Clients\StartMenuInternet\Shift", "Software\Classes\ShiftHTML", "Software\Microsoft\Windows\CurrentVersion\Uninstall\{95fcf903-63b1-44bd-ab77-358a5bd30aae}_is1", "SOFTWARE\Classes\CLSID\{635EFA6F-08D6-4EC9-BD14-8A0FDE975159}")
        HKURunKeys           = @("ShiftAutoLaunch_*", "Shift") 
        TaskPrefixes         = @("ShiftLaunchTask", "ShiftUpdateTask", "OneLaunchStartupTask")
        TaskURIs             = @()
    },
    @{
        Name                 = "PulseBrowser"
        ServiceNames         = @()
        ProcessNames         = @("pulsebrowser", "updater", "UpdaterSetup")
        ProcessPathFilters   = @("*\appdata\local\pulsesoftware\*", "*\appdata\local\temp\pulsesoftware*")
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = "AppData\Local\PulseSoftware"
        UserDirectories      = @("AppData\Local\PulseSoftware", "AppData\Local\PulseSoftware\PulseBrowser", "AppData\Local\PulseSoftware\PulseBrowserUpdater")
        UserFiles            = @()
        UserGlobs            = @("Downloads\PulseBrowser*.exe", "AppData\Local\Temp\PulseSoftware*")
        GlobalDirectories    = @()
        HKLMRegPaths         = @()
        HKLMRunKeys          = @("PulseBrowser", "PulseBrowserUpdaterTaskUser*")
        HKURegPaths          = @("Software\PulseBrowser", "Software\PulseSoftware", "Software\Microsoft\Windows\CurrentVersion\Run\PulseBrowser*", "Software\Microsoft\Windows\CurrentVersion\Run\PulseBrowserUpdaterTaskUser*")
        HKURunKeys           = @("PulseBrowserUpdaterTaskUser*", "PulseBrowser")
        TaskPrefixes         = @("PulseBrowser","PulseBrowserUpdater","PulseSoftware")
        TaskURIs             = @("\PulseSoftware")
    },
    @{
        Name                 = "PDFSpark"
        ServiceNames         = @("Obupdate", "OBUpdateService")
        ProcessNames         = @("PDFSpark", "PDFSparkWare", "pdfsetup", "OBUpdateService", "OBUpdater", "onebrowser")
        ProcessPathFilters   = @("*\appdata\local\programs\pdf_spark\*", "*\appdata\local\onebrowser\*", "*\program files (x86)\onebrowser\*") 
        MSICode              = $null
        UninstallerRelPath   = "AppData\Local\Programs\PDF_Spark\unins000.exe" 
        InstallLocationHint  = "AppData\Local\Programs\PDF_Spark"
        UserDirectories      = @("AppData\Local\Programs\PDF_Spark", "AppData\Roaming\pdfspark-nativefier*", "AppData\Local\OneBrowser", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneBrowser")
        UserFiles            = @("Desktop\PDFSpark.lnk", "Desktop\PDF Spark.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneBrowser.lnk")
        UserGlobs            = @("Downloads\PDFSparkOnSoft_*.exe", "Downloads\PDFSparkWare_*.exe", "Downloads\pdfsetup*.exe")
        GlobalDirectories    = @("C:\Program Files (x86)\OneBrowser")
        HKLMRegPaths         = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PDF_Spark_is1", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PDF_Spark_is1")
        HKURegPaths          = @("Software\PDF_Spark", "Software\SparkOnSoft", "Software\OneBrowser", "Software\Microsoft\Windows\CurrentVersion\Uninstall\PDF_Spark_is1")
        HKURunKeys           = @("PDFSpark", "OneBrowser") 
        TaskPrefixes         = @("OBUpdate", "PDFSpark")
        TaskURIs             = @("\OBUpdate")
    },
    @{
        Name                 = "PDFPro Suite"
        ServiceNames         = @("PDFProSuiteCoreService", "PDFProUpdateSvc", "DocuFlexSvc")
        ProcessNames         = @("pdfprosuite", "pdfpro", "DocuFlex", "pdfpro-update")
        ProcessPathFilters   = @("*\appdata\local\pdfprosuite\*", "*\appdata\local\browserhelper\*")
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = "AppData\Local\PDFProSuite" 
        UserDirectories      = @("AppData\Local\PDFProSuite", "AppData\Local\BrowserHelper", "AppData\Roaming\PDFProSuite", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDFProSuite")
        UserFiles            = @("AppData\Roaming\Microsoft\Windows\Start Menu\Programs\pdf pro suite.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDFProSuite\pdf pro suite.lnk", "Desktop\pdf pro suite.lnk")
        UserGlobs            = @("Downloads\*pdfpro*.msi", "Downloads\*docuflex*.exe", "AppData\Local\Temp\*pdfpro*")
        GlobalDirectories    = @("C:\Program Files (x86)\PDF Pro Suite")
        HKLMRegPaths         = @()
        HKURegPaths          = @("Software\PDF Pro Suite", "Software\DocuFlex")
        HKURunKeys           = @("PDFProSuite", "PDFPro Updater")
        TaskPrefixes         = @("PDFProSuite-core-update-", "PDFProSuite-standalone-update-", "PDFProSuite-update")
        TaskURIs             = @("\PDFPro", "\DocuFlex") 
    },
    @{
        Name                 = "PDFInstaller"
        ServiceNames         = @("PDFInstallerService", "PDFInstSvc")
        ProcessNames         = @("node", "clipboard", "DocuFlex", "pdfinstaller")
        ProcessPathFilters   = @("*\pdfinstaller\*", "*\infostealerpdf\*", "*\pdfinst\*") 
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = $null
        UserDirectories      = @("AppData\Local\PDFInstaller", "AppData\Roaming\INFOSTEALERPDF", "AppData\Local\PDFInst")
        UserFiles            = @()
        UserGlobs            = @("AppData\Local\Temp\*pdfinst*.tmp")
        GlobalDirectories    = @()
        HKLMRegPaths         = @()
        HKURegPaths          = @("Software\PDFInstaller", "Software\Microsoft\Windows\CurrentVersion\Uninstall\PDFInstaller")
        HKURunKeys           = @("PDFInstaller", "PDFInstaller Updater", "PDFInstallerTask")
        TaskPrefixes         = @("PDFInstaller", "PDFUpdater", "PDFInstallerTask") 
        TaskURIs             = @("\PDF")
    },
    @{
        Name                 = "ManualFinder"
        ServiceNames         = @()
        ProcessNames         = @("ManualFinderApp", "node", "mshta", "wscript", "cscript", "OpenMyManual")
        ProcessPathFilters   = @("*\manualfinder\*", "*\openmymanual\*") 
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = $null
        UserDirectories      = @("AppData\Local\ManualFinder", "AppData\Local\Programs\OpenMyManual", "AppData\Roaming\ManualFinder")
        UserFiles            = @()
        UserGlobs            = @("Downloads\ManualFinder*.msi", "Downloads\ManualFinder*.exe", "AppData\Local\Temp\*of.js", "AppData\Local\Temp\*or.js", "AppData\Local\Temp\*ro.js")
        GlobalDirectories    = @("C:\ProgramData\ManualFinder")
        HKLMRegPaths         = @()
        HKURegPaths          = @("Software\ManualFinder", "Software\OpenMyManual")
        HKURunKeys           = @("ManualFinder", "OpenMyManual")
        TaskPrefixes         = @("ffe2391a-", "697ea700-", "ManualFinder_", "sys_component_health_") 
        TaskURIs             = @("\ManualFinder", "\OpenMyManual")
    },
    @{
        Name                 = "OneStart"
        ServiceNames         = @("OneStartService", "OneStartSvc", "onestartbar_service", "OneStartUpdater")
        ProcessNames         = @("OneStart", "UpdaterSetup","onestartapp","onestartbar", "onestart-worker")
        ProcessPathFilters   = @("*\onestart.ai\*", "*\appdata\local\programs\onestart\*", "*\appdata\roaming\pdf editor\*")        
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = $null
        UserDirectories      = @("AppData\Local\OneStart.ai", "AppData\Roaming\OneStart", "AppData\Roaming\NodeJs", "AppData\Roaming\PDF Editor", "OneStart.ai", "AppData\Local\Programs\OneStart")
        UserFiles            = @("Desktop\OneStart.lnk", "AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\OneStart.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneStart.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\PDF Editor.lnk","AppData\Local\Programs\OneStart")
        UserGlobs            = @("Downloads\OneStart*.exe", "Downloads\*OneStart*.msi")
        GlobalDirectories    = @("C:\WINDOWS\system32\config\systemprofile\AppData\Local\OneStart.ai", "C:\WINDOWS\system32\config\systemprofile\PDFEditor","C:\ProgramData\OneStart.ai","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneStart.ai")
        HKLMRegPaths         = @("Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASAPI32", "Registry::HKLM\Software\WOW6432Node\Microsoft\Tracing\OneStart_RASMANCS", "Registry::HKLM\Software\Microsoft\MediaPlayer\ShimInclusionList\onestart.exe")
        HKURegPaths          = @("Software\Clients\StartMenuInternet\OneStart.IOZDYLUF4W5Y3MM3N77XMXEX6A", "Software\OneStart.ai", "Software\Microsoft\Windows\CurrentVersion\Uninstall\OneStart.ai OneStart", "Software\PDFEditor")
        HKURunKeys           = @("OneStartUpdate", "OneStartBarUpdate", "OneStartBar", "OneStart", "OneStartChromium", "OneStartUpdaterTaskUser*", "PDFEditor*")
        TaskPrefixes         = @("OneStartUser", "OneStartAutoLaunchTask", "PDFEditorScheduledTask", "sys_component_health_")
        TaskURIs             = @("\OneStart")
    },
    @{
        Name                 = "EpiBrowser"
        ServiceNames         = @("EpiBrowserService", "EpiBrowserUpdateSvc", "EpiSvc")
        ProcessNames         = @("epibrowser", "epistart", "epi-updater") 
        ProcessPathFilters   = @("*\episoftware\*", "*\epibrowser\*")
        MSICode              = $null
        UninstallerRelPath   = $null
        InstallLocationHint  = $null
        UserDirectories      = @("AppData\Local\EPISoftware", "AppData\Local\EpiBrowser", "AppData\Local\Temp\epibrowser-bin", "AppData\Roaming\EpiBrowser")
        UserFiles            = @("AppData\Roaming\Microsoft\Windows\Start Menu\Programs\EpiBrowser.lnk", "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\EpiStart.lnk")
        UserGlobs            = @()
        GlobalDirectories    = @("C:\Program Files (x86)\EpiBrowser", "C:\ProgramData\EPISoftware")
        HKLMRegPaths         = @("Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\epibrowser.exe")
        HKURegPaths          = @("Software\EPISoftware", "Software\Microsoft\Windows\CurrentVersion\Uninstall\EPISoftware EpiBrowser", "Software\Classes\EPIHTML*", "Software\Classes\EPIPDF*", "Software\Clients\StartMenuInternet\EpiBrowser*", "Software\Microsoft\Windows\CurrentVersion\App Paths\epibrowser.exe")
        HKURunKeys           = @("EpiBrowserStartup", "EpiBrowserUpdate", "EpiBrowser")
        TaskPrefixes         = @("EpiBrowserStartup", "EpiBrowserUpdate","EpiBrowser", "EpiBrowser-")
        TaskURIs             = @("\EpiBrowser")
    }
)

Write-Host "[*] STARTING UNIFIED CLEANUP SEQUENCE..." -ForegroundColor Cyan

#  RECUPERATION PREALABLE DE TOUTES LES TACHES PLANIFIEES DU SYSTEME
$RawTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
#  ANALYSE ET NORMALISATION EN BOUCLE DU CONTENU DES TACHES PLANIFIEES
$ProcessedTasks = foreach ($Task in $RawTasks) {
    if (-not $Task.Actions) { continue }
    $SanitizedActions = @()
    foreach ($Action in $Task.Actions) {
        if (-not $Action.Execute) { continue }

        $WorkingDir = if ($Action.WorkingDirectory) { $Action.WorkingDirectory } else { "" }
        $RawCommand = "$($Action.Execute) $($Action.Arguments) $WorkingDir"
        $CleanCommand = $RawCommand -replace '\^', '' -replace '`', '' -replace '\s+', ' '

        #  DETECTION ET DECODAGE AUTOMATIQUE DES PAYLOADS POWERSHELL EN BASE64
        $PsEncRegex = '(?i)\b-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)[\s:]+["'']?([A-Za-z0-9+/=]{10,})["'']?'
        if ($CleanCommand -match $PsEncRegex) {
            try {
                $Base64Payload = $Matches[2]
                $DecodedBytes = [Convert]::FromBase64String($Base64Payload)
                $DecodedCommand = [Text.Encoding]::Unicode.GetString($DecodedBytes)
                $CleanCommand += " " + $DecodedCommand
            } catch {}
        }
        $FullCommandLower = $CleanCommand.ToLowerInvariant() -replace '\${?env:', '%' -replace '}', '%'
        #  TRADUCTION ET REECRITURE ALIAS DES VARIABLES D ENVIRONNEMENT EN CHEMINS BRUTS
        $FullCommandLower = $FullCommandLower -replace '%homedrive%%homepath%', 'c:\users\*' -replace '%userprofile%', 'c:\users\*' `
            -replace '%homepath%', '\users\*' -replace '%username%', '*' -replace '%localappdata%', 'appdata\local' -replace '%appdata%', 'appdata\roaming' `
            -replace '%temp%', 'appdata\local\temp' -replace '%allusersprofile%', 'c:\programdata' -replace '%programdata%', 'c:\programdata' `
            -replace '%public%', 'c:\users\public' -replace '%programfiles%', 'c:\program files'  -replace '%programfiles\(x86\)%', 'c:\program files (x86)'
        $SanitizedActions += $FullCommandLower
    }
    #  OBJET ALEGER POUR CORRESPONDANCE RAPIDE
    [PSCustomObject]@{ TaskObject  = $Task 
                       TaskName    = $Task.TaskName
                       TaskPath    = $Task.TaskPath
                       FullTaskURI = "$($Task.TaskPath)$($Task.TaskName)"
                       CmdLines    = $SanitizedActions
                    }
}

#  CAPTURE DES PROCESSUS EN COURS D'EXECUTION SUR LA MACHINE
$AllLocalProcs = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue
#  BOUCLE PRINCIPALE DE REMEDIATION ITERATIVE DE LA THREAT INTEL
for ($i = 0; $i -lt $TargetApps.Count; $i++) {
    $App = $TargetApps[$i]
    Write-Host "[>] Cible: $($App.Name)" -ForegroundColor White

    #  ARRET DES SERVICES
    if ($App.ServiceNames -and $App.ServiceNames.Count -gt 0) {
        foreach ($SvcName in $App.ServiceNames) {
            $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
            if ($Service) {

                # VALIDATION DE SECU SI CA POINTE VERS UN ENDROIT CRITIQUE
                $SvcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"
                $ImagePath = (Get-ItemProperty -Path $SvcRegPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
                $PuaKeywords = "appdata|local|roaming|temp|onestart|shift|pdf\s*pro|docuflex|pdf\s*spark|onebrowser|obupdate|obupdater|pdfinstaller|pdfinst|manualfinder|openmymanual|pdf\s*editor|epibrowser|episoftware"
                
                if ($ImagePath -and $ImagePath -notmatch $PuaKeywords) {
                    Write-Warning "[!] Conflit de nommage detecte : Le service '$SvcName' pointe vers un binaire potentiellement sain ($ImagePath)"
                    continue
                }

                if ($DryRun) {
                    Write-Host " [DRY-RUN] Service identifie a neutraliser : $SvcName (Etat actuel: $($Service.Status))" -ForegroundColor DarkYellow
                } else {
                    Write-Host " [!] Neutralisation du Service : $SvcName" -ForegroundColor Red
                    
                    # FORCE L'ARRET ET ATTENTE DE LA TRANSITION DU SERVICE CONTROL MANAGER
                    if ($Service.Status -eq 'Running') {
                        Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
                        $Timeout = 10
                        while ((Get-Service -Name $SvcName -ErrorAction SilentlyContinue).Status -match 'Pending|Running' -and $Timeout -gt 0) {
                            Start-Sleep -Seconds 1
                            $Timeout--
                        }
                    }
                    #  SUPPRESSION SCM OU PURGE DIRECTE DE LA CLE SANS LE REGISTRE SI ECHEC
                    $scDelete = Start-Process -FilePath "sc.exe" -ArgumentList "delete `"$SvcName`"" -Wait -PassThru -WindowStyle Hidden
                    Start-Sleep -Milliseconds 500 # Laisse un instant au SCM pour se mettre à jour
                    if ($scDelete.ExitCode -ne 0) {
                        Write-Host "   [!] Echec sc delete. Tentative de suppression directe via Registre..." -ForegroundColor Yellow
                        if (Test-Path $SvcRegPath) {
                            Remove-Item -Path $SvcRegPath -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }
    }
    # SCHEDULE TASKS 
    foreach ($PTask in $ProcessedTasks) {
        $KillReason = $null
        
        # check métadonnées
        $MetaMatch = $false
        if ($App.TaskPrefixes) {
            foreach ($Prefix in $App.TaskPrefixes) {
                if ($Prefix -and $PTask.TaskName -like "$Prefix*") { $MetaMatch = $true; break }
            }
        }
        if (-not $MetaMatch -and $App.TaskURIs) {
            foreach ($Uri in $App.TaskURIs) {
                if ($Uri -and $PTask.FullTaskURI -like "*$Uri*") { $MetaMatch = $true; break }
            }
        }

        # check contenu de commande pré-traité
        foreach ($Cmd in $PTask.CmdLines) {
            $PathMatch = $false
            if ($App.ProcessPathFilters) {
                foreach ($pf in $App.ProcessPathFilters) {
                    $CleanFilter = $pf.ToLowerInvariant().Trim('*')
                    if ($Cmd -like "*$CleanFilter*") { $PathMatch = $true; break }
                }
            }

            $ExecMatch = $false
            if ($App.ProcessNames) {
                foreach ($pn in $App.ProcessNames) {
                    $EscapedPn = [regex]::Escape($pn)
                    if ($Cmd -match "\b$EscapedPn(\.exe)?\b") { $ExecMatch = $true; break }
                }
            }

            if ($PathMatch) {
                $KillReason = "Chemin malveillant repere dans l'action de la tâche."
                break
            }
            if ($MetaMatch -and $ExecMatch) {
                $KillReason = "Nom suspect + Binaire malveillant concordants."
                break
            }
        }

        # SUPPRESSION DE LA TACHE
        if ($KillReason) {
            if ($DryRun) {
                Write-Host " [DRY-RUN] Tache malveillante ciblee ($($PTask.TaskName)) | Motif: $KillReason" -ForegroundColor DarkYellow
                Write-Host "           Path : $($PTask.FullTaskURI)" -ForegroundColor Gray
            } else {
                if (Get-ScheduledTask -TaskName $PTask.TaskName -TaskPath $PTask.TaskPath -ErrorAction SilentlyContinue) {
                    Write-Host " [-] SUPPRESSION DE LA TACHE : $($PTask.FullTaskURI)" -ForegroundColor Red
                    Write-Host "     [i] Motif IR : $KillReason" -ForegroundColor Gray
                    try { Disable-ScheduledTask -TaskName $PTask.TaskName -TaskPath $PTask.TaskPath -ErrorAction SilentlyContinue | Out-Null } catch {}
                    Unregister-ScheduledTask -TaskName $PTask.TaskName -TaskPath $PTask.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
    }

    #  PROCESSUS
    #  TRACKING ET TERMINATION RADICALE DES ARBRES DE PROCESSUS ACTIFS
    if ($App.ProcessNames -or ($App.ProcessPathFilters -and $App.ProcessPathFilters.Count -gt 0)) {
        foreach ($p in $AllLocalProcs) {
            # Pour eviter d'avoir des errors de windows si des processus sont proteger (refuse de relever leur chemin)
            if (-not $p.ExecutablePath) { continue }

            $KillProcess = $false

            $NameMatch = $false
            if ($App.ProcessNames) {
                foreach ($pn in $App.ProcessNames) {
                    if ($pn -notlike "*.exe") { $targetExe = "$pn.exe" } else { $targetExe = $pn }
                    if ($p.Name -ieq $targetExe -or $p.Name -ieq $pn) { $NameMatch = $true; break }
                }
            }
             
            $PathMatch = $false
            if ($App.ProcessPathFilters -and $App.ProcessPathFilters.Count -gt 0) {
                foreach ($Filter in $App.ProcessPathFilters) {
                    if ($p.ExecutablePath -like $Filter) { $PathMatch = $true; break }
                }
            }

            if ($NameMatch) {
                if ($App.ProcessPathFilters -and $App.ProcessPathFilters.Count -gt 0) {
                    if ($PathMatch) { $KillProcess = $true }
                } else {
                    $KillProcess = $true
                }
            }
            #  si un process s'execute depuis le path d'un pua = kill
            if (-not $KillProcess -and $PathMatch) {
                $KillProcess = $true
            }
            #  EXECUTION FORCEE DE TASKKILL SUR L ARBRE DE PROCESSUS (PID)
            if ($KillProcess) {
                if ($DryRun) {
                    Write-Host "   [DRY-RUN] Processus identifie a abattre (Arbre complet) : $($p.Name) (PID: $($p.ProcessId))" -ForegroundColor DarkYellow
                } else {
                    Write-Host "   [!] Target Active -> Termination de l'arbre : $($p.Name) (PID: $($p.ProcessId))" -ForegroundColor Red
                    Start-Process -FilePath "taskkill.exe" -ArgumentList "/F /T /PID $($p.ProcessId)" -Wait -NoNewWindow
                    Start-Sleep -Milliseconds 500
                }
            }
        }
    }

    #  BINARY UNINSTALLER
    if ($App.UninstallerRelPath) {
        $found = $null
        foreach ($ProfilePath in $FileSystemProfiles) {
            $testPath = Join-Path $ProfilePath $App.UninstallerRelPath
            if (Test-Path $testPath) { $found = $testPath; break }
        }
        if ($found) {
            if ($DryRun) {
                Write-Host " [DRY-RUN] Uninstaller binaire a lancer : $found" -ForegroundColor DarkYellow
            } else {
                Write-Host " [!] Lancement Uninstaller: $found" -ForegroundColor Gray
                try {
                    # OUVERTURE EN LECTURE SEUL SANS CHARGEMENT EN RAM
                    $stream = [System.IO.File]::OpenRead($found)

                    if ($stream.Length -lt 2) {
                        Write-Warning "   [!] '$found' est trop petit pour etre un executable valide."
                        $stream.Close()
                        $stream = $null
                    } else {
                        # ALLOCATION D'UN BUFFER DE 2 OCTETS + LECTURE
                        $hdr = New-Object byte[] 2
                        $null = $stream.Read($hdr, 0, 2)
                        # FERMETURE IMMEDIATE POUR LIBERER LES VERROU WINDOWS
                        $stream.Close()
                        $stream = $null
                        
                        if ($hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) {   # "MZ"
                            Write-Warning "   [!] '$found' n'est pas un executable PE valide. Lancement ignorer (suppression manuelle prendra le relais)."
                        } else {
                            $proc = Start-Process $found -ArgumentList "/VERYSILENT /NORESTART" -Wait -PassThru -ErrorAction Stop
                            if ($proc.ExitCode -eq 0) {
                                Write-Host "   [+] Succes : desinstallateur binaire termine." -ForegroundColor Green
                            } else {
                                Write-Warning "   [!] Uninstaller code retour $($proc.ExitCode)."
                            }
                        }
                    }
                } catch {
                    Write-Warning "   [!] Echec lancement uninstaller ($found) : $($_.Exception.Message). Poursuite avec suppression manuelle."
                } finally {
                    # SI LE CODE A PLANTER AVANT LE close() LIBERATION DUv FICHIER ICI
                    if ($null -ne $stream) { 
                        $stream.Close() 
                    }
                }
            }
        }
    }

    #  MSI UNINSTALLER 
    $DetectedMSI = $App.MSICode
    if (-not $DetectedMSI -and $App.InstallLocationHint) {
        $UninstallBases = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($Base in $UninstallBases) {
            $Keys = Get-ChildItem -Path $Base -ErrorAction SilentlyContinue
            foreach ($Key in $Keys) {
                $loc = (Get-ItemProperty -Path $Key.PSPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation
                if ($loc) {
                    # Normalisation complete de la valeur du registre
                    $CleanLoc = $loc.Trim([char[]]@('"', "'", ' ', '\')).ToLowerInvariant()
                    # Normalisation complete du Hint configure dans la Threat Intel
                    $CleanHint = $App.InstallLocationHint.Trim([char[]]@('"', "'", ' ', '\')).ToLowerInvariant()
                    
                    #  immunisee contre le formatage
                    if ($CleanLoc -and $CleanHint -and ($CleanLoc -eq $CleanHint -or $CleanLoc -like "*\$CleanHint")) {
                        $DetectedMSI = $Key.PSChildName
                        $TargetApps[$i].HKLMRegPaths += "$Base\$DetectedMSI"
                        break
                    }
                }
            }
            if ($DetectedMSI) { break } 
        }
    }
    if ($DetectedMSI) {
        # CHECK STRICTEMENT QUE C'EST UN GUID MSI VALIDE
        if ($DetectedMSI -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
            if ($DryRun) {
                Write-Host " [DRY-RUN] Desinstallation MSI prevue pour le GUID : $DetectedMSI" -ForegroundColor DarkYellow
            } else {
                Write-Host " [!] Lancement Desinstallation MsiExec: $DetectedMSI" -ForegroundColor Gray
                
                # ON CAPTURE LE PROCESSUS ET CHECK LE CODE DE RETOUR
                $procMsi = Start-Process "msiexec.exe" -ArgumentList "/X$DetectedMSI /qn /norestart" -Wait -PassThru
                if ($procMsi.ExitCode -eq 0 -or $procMsi.ExitCode -eq 3010) {
                    Write-Host "   [+] Succes : MsiExec a termine la desinstallation (Code: $($procMsi.ExitCode))." -ForegroundColor Green
                } else {
                    Write-Warning "   [!] MsiExec a echoue avec le code retour $($procMsi.ExitCode)."
                }
            }
        } else {
            # SI C4EST UN FAUX MSI 
            Write-Warning "   [!] Le code detecte '$DetectedMSI' n'est pas un GUID MSI valide. Msiexec ignore la desinstallation binaire ou manuelle prendra le relais."
        }
    }

    #  SUPRESSION DIRECTORIES, SHEETS & TASKS
    Write-Host "[>] Application: $($App.Name)" -ForegroundColor White
    $RawPaths = @()
    #  RESOLUTION 
    foreach ($ProfilePath in $FileSystemProfiles) {
        if ($App.UserDirectories) {
            foreach ($Item in $App.UserDirectories) { if ($Item) { $RawPaths += Join-Path $ProfilePath $Item } }
        }
        if ($App.UserFiles) {
            foreach ($Item in $App.UserFiles) { if ($Item) { $RawPaths += Join-Path $ProfilePath $Item } }
        }
        if ($App.UserGlobs) {
            foreach ($Glob in $App.UserGlobs) {
                if ($Glob) {
                    $GlobParent = Join-Path $ProfilePath (Split-Path $Glob -Parent)
                    $GlobLeaf = Split-Path $Glob -Leaf
                    if (Test-Path $GlobParent) {
                        Get-ChildItem -Path $GlobParent -Filter $GlobLeaf -ErrorAction SilentlyContinue | ForEach-Object { $RawPaths += $_.FullName }
                    }
                }
            }
        }
    }
    if ($App.GlobalDirectories) {
        foreach ($Item in $App.GlobalDirectories) { if ($Item) { $RawPaths += $Item } }
    }
    #  NORMALISATION
    $NormalizedPaths = @()
    foreach ($Path in $RawPaths) {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
            try {
                # Résolution sécurisée du chemin absolu
                $Norm = [System.IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant()
                $NormalizedPaths += $Norm
            } catch {
                #  incident et passe au chemin suivant
                Write-Warning "[!] Normalisation impossible pour le chemin corrompu : $Path. Erreur: $($_.Exception.Message)"
                continue
            }
        }
    }
    $NormalizedPaths = $NormalizedPaths | Select-Object -Unique

    #  VALIDATION ET CONTROLE ANTI REJECT
    $ValidatedPaths = @()
    foreach ($Path in $NormalizedPaths) {
        $Reject = $false
        # Sécurite anti namespaces Win32/Device et ADS
        if ($Path -match '^\\\\(?:\?|\.)\\') { 
            Write-Warning "[REJECT] Path de type Win32/Device Namespace interdit (Securite) : $Path"
            $Reject = $true 
        }  
        if ($Path -match ':[^\\/:]+(?::\$DATA)?$') {
            Write-Warning "[REJECT] Alternate Data Stream (ADS) detecte et rejete (Securite) : $Path"
            $Reject = $true
        }        
        # PROTECTION CRITIQUE ABSOLUE 
        if (-not $Reject) {
            foreach ($Root in $HardProtectedRoots) {
                $RootWithSlash = if ($Root -notlike "*\") { "$Root\" } else { $Root }
                if ($Path -eq $Root -or $Path.StartsWith($RootWithSlash)) {
                    $IsAllowedException = $false
                    foreach ($ExceptionPath in $ProtectedWindowsExceptions) {
                        if ($Path -eq $ExceptionPath -or $Path.StartsWith("$ExceptionPath\")) {
                            $IsAllowedException = $true
                            break
                        }
                    }
                    if (-not $IsAllowedException) {
                        Write-Host " [REJECT] Racine systeme critique protegee : $Path" -ForegroundColor Yellow
                        $Reject = $true
                        break
                    }
                }
            }
        }
        # PROTECTION CONTAINER 
        if (-not $Reject) {
            # On combine ex: C:\Users\Bob
            foreach ($Root in ($ContainerRoots + $ProfileRoots)) {
                if ($Path -eq $Root) {
                    Write-Host " [REJECT] Interdiction d'effacer le dossier container principal : $Path" -ForegroundColor Yellow
                    $Reject = $true
                    break
                }
            }
        }
        # PROTECTION DES CONTAINERS UTILISATEURS
        if (-not $Reject) {
            if ($Path -match '(?i)\\(appdata\\local|appdata\\roaming|appdata\\locallow|downloads|desktop|documents)$') {
                Write-Host " [REJECT] Tentative de suppression brute d'un container de profil : $Path" -ForegroundColor Yellow
                $Reject = $true
            }
        }
        if (-not $Reject) {
            $ValidatedPaths += $Path
        }
    }
    #  EXECUTION
    foreach ($Path in $ValidatedPaths) {
        if ($DryRun) {
            Write-Host " [DRY-RUN] Fichier/Dossier a supprimer : $Path" -ForegroundColor DarkYellow
        } else {
            $FinalCheck = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            if ($null -eq $FinalCheck) { continue }
            
            # Si le malware a remplace le dossier par une jonction vers C:\Windows juste avant le clic
            if ($FinalCheck.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-Warning "[!] Un point de reparse/lien symbolique a ete detecte au dernier moment sur $Path ! Suppression annulee."
                continue
            }

            Write-Host " [-] SUPPRESSION : $Path" -ForegroundColor Red
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Continue
            if (-not (Test-Path -LiteralPath $Path)) {
                Write-Host "   [+] Succes : Cible supprimee du disque dur." -ForegroundColor Green
            }
        }
    }

    # NETTOYAGE DEES CLES DU REGISTRE HKLM
    if ($App.HKLMRegPaths) {
        foreach ($p in $App.HKLMRegPaths) {
            if ($p -and (Test-Path $p)) { 
                if ($DryRun) {
                    Write-Host " [DRY-RUN] Cle HKLM a supprimer : $p" -ForegroundColor DarkYellow
                } else {
                    Remove-Item $p -Recurse -Force -ErrorAction Continue 
                    if (-not (Test-Path $p)) {
                        Write-Host "   [+] Succes : Cle HKLM retiree du Registre." -ForegroundColor Green
                    }
                }
            }
        }
    }
    if ($App.HKLMRunKeys) {
        $HKLMRunBases = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($Base in $HKLMRunBases) {
            if (Test-Path $Base) {
                $RunKeyItem = Get-Item -Path $Base -ErrorAction SilentlyContinue
                foreach ($k in $App.HKLMRunKeys) {
                    if ($k) {
                        $MatchingProps = $RunKeyItem.Property | Where-Object { $_ -like $k }
                        foreach ($PropName in $MatchingProps) {
                            if ($DryRun) {
                                Write-Host " [DRY-RUN] Valeur Run HKLM a supprimer : $PropName dans $Base" -ForegroundColor DarkYellow
                            } else {
                                Write-Host " [-] Suppression Registre HKLM (RunKey) : $PropName" -ForegroundColor Red
                                Remove-ItemProperty -Path $Base -Name $PropName -Force -ErrorAction SilentlyContinue
                                Write-Host "   [+] Valeur de demarrage HKLM '$PropName' supprimee." -ForegroundColor Green
                            }
                        }
                    }
                }
            }
        }
    }
}

Write-Host "[*] USER REGISTER CLEANUP..." -ForegroundColor Cyan
#  REGISTRE UTILISATEUR
foreach ($RegProfile in $RegistryProfiles) {
    $SID = $RegProfile.SID
    $ActiveHivePath = "Registry::HKU\$SID"
    $RootPath = $null
    $NeedsUnmount = $false
    # On securise le nom temporaire (les tirets peuvent parfois poser probleme)
    $TempName = "SOC_TEMP_$($SID.Replace('-', '_'))"
    
    Write-Host "[>] Profil : $($RegProfile.LocalPath)" -ForegroundColor White

    #  MONTAGE OU ReCUPeRATION DE LA RUCHE
    if (Test-Path -LiteralPath $ActiveHivePath -ErrorAction SilentlyContinue) {
        #  la ruche est deja chargee (Session active)
        $RootPath = $ActiveHivePath
        $NeedsUnmount = $false
        Write-Host " [i] Ruche deja chargee (Session active)" -ForegroundColor Gray
    } else {
        #  la ruche est hors ligne
        $NtUserDat = Join-Path $RegProfile.LocalPath "NTUSER.DAT"
        if (Test-Path -LiteralPath $NtUserDat) {
            $procLoad = Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKU\$TempName`" `"$NtUserDat`"" -Wait -PassThru -WindowStyle Hidden
            if ($procLoad.ExitCode -eq 0) {
                $RootPath = "Registry::HKU\$TempName"
                $NeedsUnmount = $true
                Write-Host " [+] Montage NTUSER.DAT reussi" -ForegroundColor Gray
            } else {
                Write-Host " [X] Impossible de monter NTUSER.DAT (Fichier verrouille ou acces refuse)" -ForegroundColor DarkGray
                continue
            }
        } else {
            continue
        }
    }

    try {
        #  TRAITEMENT DU REGISTRE

        # NETTOYAGE DES BROWSER POLICIES DETOURNEES
        Write-Host "   [-] Analyse des Browser Policies..." -ForegroundColor Gray
        $PolicyPaths = @(
            "Software\Policies\Google\Chrome\ExtensionInstallForcelist",
            "Software\Policies\Google\Chrome\ExtensionSettings",
            "Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
            "Software\Policies\Microsoft\Edge\ExtensionSettings"
        )

        foreach ($RelPath in $PolicyPaths) {
            #  on vérifie la machine (HKLM) et l'utilisateur en cours ($RootPath)
            $PathsToCheck = @(
                "HKLM:\$RelPath",
                "$RootPath\$RelPath"
            )

            foreach ($Path in $PathsToCheck) {
                if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) {
                    $Key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
                    if ($null -eq $Key) { continue }

                    foreach ($Property in $Key.Property) {
                        $Value = (Get-ItemProperty -LiteralPath $Path -Name $Property -ErrorAction SilentlyContinue).$Property
                        
                        # on ne supprime que si match empreinte d'un PUA
                        if ($Value -match 'onestart|shift|epibrowser|docuflex|pdf\s*pro|pulse|spark') {
                                if ($DryRun) {
                                Write-Host "     [DRY-RUN] Politique PUA detectee : $Property = $Value dans $Path" -ForegroundColor DarkYellow
                            } else {
                                Write-Host "     [-] SUPPRESSION ENTREE POLITIQUE : $Property ($Value)" -ForegroundColor Red
                                Remove-ItemProperty -LiteralPath $Path -Name $Property -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
            }
        }

        $RunPath = "$RootPath\Software\Microsoft\Windows\CurrentVersion\Run"

        # RECUPERATION DES RUN KEY
        $RunKeyItem = Get-Item -LiteralPath $RunPath -ErrorAction SilentlyContinue

        for ($j = 0; $j -lt $TargetApps.Count; $j++) {
            $App = $TargetApps[$j]
            # REG KEYS
            if ($App.HKURunKeys) { 
                if ($null -ne $RunKeyItem) {
                    foreach ($k in $App.HKURunKeys) { 
                        if ($k) {
                            $MatchingProps = $RunKeyItem.Property | Where-Object { $_ -like $k }
                            foreach ($PropName in $MatchingProps) {
                                if ($DryRun) {
                                    Write-Host " [DRY-RUN] Valeur RunKey a supprimer : $PropName ($SID)" -ForegroundColor DarkYellow
                                } else {
                                    Write-Host " [-] Suppression Registre (RunKey) : $PropName" -ForegroundColor Red
                                    Remove-ItemProperty -LiteralPath $RunPath -Name $PropName -Force -ErrorAction SilentlyContinue 
                                    Write-Host "   [+] RunKey '$PropName' supprimee avec succes." -ForegroundColor Green
                                }
                            }
                        }
                    }
                }
            }
            # REG PATHS
            if ($App.HKURegPaths) {
                foreach ($p in $App.HKURegPaths) { 
                    if ($p) {
                        if ($p -match '\*') {
                            $ParentPath = Split-Path -Path "$RootPath\$p" -Parent
                            $LeafFilter = Split-Path -Path $p -Leaf

                            if (Test-Path -LiteralPath $ParentPath -ErrorAction SilentlyContinue) {
                                $MatchingKeys = Get-ChildItem -LiteralPath $ParentPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like $LeafFilter }
                                foreach ($Key in $MatchingKeys) {
                                    if ($DryRun) {
                                        Write-Host " [DRY-RUN] Cle Registre HKU (Wildcard) a supprimer : $($Key.PSChildName) ($SID)" -ForegroundColor DarkYellow
                                    } else {
                                        Write-Host " [-] Registre : $($Key.Name)" -ForegroundColor DarkRed
                                        Remove-Item -LiteralPath $Key.PSPath -Recurse -Force -ErrorAction Continue 
                                        if (-not (Test-Path -LiteralPath $Key.PSPath)) {
                                            Write-Host "   [+] Succes : Cle HKU (Wildcard) supprimee." -ForegroundColor Green
                                        }
                                    }
                                }
                            }
                        } else {
                            $ExactPath = "$RootPath\$p"
                            if (Test-Path -LiteralPath $ExactPath -ErrorAction SilentlyContinue) { 
                                if ($DryRun) {
                                    Write-Host " [DRY-RUN] Cle Registre HKU a supprimer : $p ($SID)" -ForegroundColor DarkYellow
                                } else {
                                    Write-Host " [-] Registre : HKU\$SID\$p" -ForegroundColor DarkRed
                                    Remove-Item -LiteralPath $ExactPath -Recurse -Force -ErrorAction Continue 
                                    if (-not (Test-Path -LiteralPath $ExactPath)) {
                                        Write-Host "   [+] Succes : Cle HKU exacte supprimee." -ForegroundColor Green
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    finally {
        #  POUR LA RUCHES OFFLINE
        if ($NeedsUnmount) {
            Write-Host " [-] Liberation des ressources pour $SID..." -ForegroundColor Gray

            # NETTOYAGE POUR EVITER DES VERROUS
            $RunKeyItem = $null
            $MatchingProps = $null
            $MatchingKeys = $null
            $Key = $null
            
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
            Start-Sleep -Seconds 1.25

            #  DEMONTAGE
            $procUnload = Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKU\$TempName`"" -Wait -PassThru -WindowStyle Hidden

            if ($procUnload.ExitCode -ne 0) {
                Write-Host " [!] echec du demontage (Code: $($procUnload.ExitCode))." -ForegroundColor Yellow
            } else {
                Write-Host " [+] Demontage de la ruche reussi." -ForegroundColor Green
            }
        }
    } 
}

try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
Write-Host "`n[*] SOC Pipeline Execution Completed." -ForegroundColor Cyan
