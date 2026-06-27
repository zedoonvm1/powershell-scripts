#Requires -Version 7.0

[CmdletBinding()]
param()

# ── Privilege check ───────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script requires Administrator privileges.' -ForegroundColor Red
    Write-Host 'Please re-run from an elevated PowerShell session.' -ForegroundColor Yellow
    exit 1
}

$ProgressPreference = 'SilentlyContinue'

# ── ANSI palette ──────────────────────────────────────────────────────────────
$e          = [char]27
$Orange     = "${e}[38;2;255;140;0m"
$Gold       = "${e}[38;2;255;215;0m"
$DkOrange   = "${e}[38;2;200;90;10m"
$MarsRed    = "${e}[38;2;180;55;15m"
$MarsOrange = "${e}[38;2;210;115;55m"
$MarsCrater = "${e}[38;2;120;30;8m"
$Gray       = "${e}[38;2;155;155;155m"
$Green      = "${e}[38;2;80;220;80m"
$Red        = "${e}[91m"
$Reset      = "${e}[0m"
$Bold       = "${e}[1m"

# ── Tool groups ───────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    'Spokwn' = @(
        'https://github.com/spokwn/JournalTrace/releases/latest/download/JournalTrace.exe'
        'https://github.com/spokwn/PathsParser/releases/latest/download/PathsParser.exe'
        'https://github.com/spokwn/BAM-parser/releases/latest/download/BAMParser.exe'
        'https://github.com/spokwn/prefetch-parser/releases/latest/download/PrefetchParser.exe'
        'https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe'
        'https://github.com/spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe'
        'https://github.com/spokwn/Replaceparser/releases/latest/download/Replaceparser.exe'
        'https://github.com/spokwn/BamDeletedKeys/releases/latest/download/BamDeletedKeys.exe'
        'https://github.com/spokwn/Tool/releases/latest/download/espouken.exe'
        'https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe'
    )
    'Nirsoft' = @(
        'https://www.nirsoft.net/utils/winprefetchview-x64.zip'
        'https://www.nirsoft.net/utils/lastactivityview.zip'
        'https://www.nirsoft.net/utils/executedprogramslist.zip'
        'https://www.nirsoft.net/utils/userassistview.zip'
        'https://www.nirsoft.net/utils/alternatestreamview-x64.zip'
        'https://www.nirsoft.net/utils/hashmyfiles-x64.zip'
        'https://www.nirsoft.net/utils/jumplistsview.zip'
        'https://www.nirsoft.net/utils/opensavefilesview-x64.zip'
        'https://www.nirsoft.net/utils/usbdeview-x64.zip'
        'https://www.nirsoft.net/utils/turnedontimesview.zip'
        'https://www.nirsoft.net/utils/regscanner-x64.zip'
        'https://www.nirsoft.net/utils/browserdownloadsview-x64.zip'
        'https://www.nirsoft.net/utils/clipboardic.zip'
        'https://www.nirsoft.net/utils/driverview-x64.zip'
        'https://www.nirsoft.net/utils/fileaccesserrorview-x64.zip'
        'https://www.nirsoft.net/utils/previousfilesrecovery-x64.zip'
        'https://www.nirsoft.net/utils/recentfilesview.zip'
        'https://www.nirsoft.net/utils/shellbagsview.zip'
        'https://www.nirsoft.net/utils/taskschedulerview-x64.zip'
        'https://www.nirsoft.net/utils/uninstallview-x64.zip'
        'https://www.nirsoft.net/utils/usbdrivelog.zip'
        'https://www.nirsoft.net/utils/networkusageview-x64.zip'
    )
    'Eric Zimmerman' = @(
        'https://download.ericzimmermanstools.com/net9/PECmd.zip'
        'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'
        'https://download.ericzimmermanstools.com/net9/JLECmd.zip'
        'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'
        'https://download.ericzimmermanstools.com/net9/bstrings.zip'
        'https://download.ericzimmermanstools.com/net9/RecentFileCacheParser.zip'
        'https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/ShellBagsExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip'
        'https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.308/dotnet-sdk-9.0.308-win-x64.exe'
        'https://download.ericzimmermanstools.com/net9/SBECmd.zip'
		'https://download.ericzimmermanstools.com/net9/WxTCmd.zip'
		'https://download.ericzimmermanstools.com/net9/AmcacheParser.zip'
    )
    'Generic Tools' = @(
        'https://github.com/winsiderss/si-builds/releases/download/3.2.25275.112/systeminformer-build-canary-setup.exe'
        'https://www.voidtools.com/Everything-1.4.1.1029.x64-Setup.exe'
        'https://www.dropbox.com/scl/fi/q428cz9l0uq50bg3azh57/AccessData_FTK_Imager_4.7.1.exe?rlkey=o6w5ot98zb3wpo12n4rlwowhb&st=230sgk3i&dl=1'
        'https://download.ccleaner.com/rcsetup154.exe'
        'https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip'
        'https://mh-nexus.de/downloads/HxDPortableSetup.zip'
        'https://www.winitor.com/tools/pestudio/current/pestudio.zip'
        'https://download.sysinternals.com/files/Strings.zip'
        'https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe'
        'https://github.com/Col-E/Recaf/releases/download/2.21.14/recaf-2.21.14-J8-jar-with-dependencies.jar'
        'https://download.sysinternals.com/files/ProcessExplorer.zip'
        'https://download.sysinternals.com/files/Autoruns.zip'
        'https://download.sysinternals.com/files/ProcessMonitor.zip'
        'https://download.sysinternals.com/files/TCPView.zip'
        'https://github.com/Yamato-Security/hayabusa/releases/download/v3.7.0/hayabusa-3.7.0-win-x64.zip'
        'https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/download/RL/RedLotusTaskSentinel.exe'
        'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/go-winpmem_amd64_1.0-rc2_signed.exe'
        'https://github.com/zedoonvm1/unfinishedtools/releases/download/beta/MarsPixelDumpAnalyzer.exe'
        'https://github.com/RLDuck/Registry-Scanner/releases/download/1.0/RegistryScanner.exe'
    )
    'Red Lotus' = @(
        'https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/download/RL/RedLotusTaskSentinel.exe'
        'https://github.com/ItzIceHere/RedLotus-Mod-Analyzer/releases/download/RL/RedLotusModAnalyzer.exe'
        'https://github.com/ItzIceHere/RedLotusAltChecker/releases/download/RL/RedLotusAltChecker.exe'
    )
    'Orbdiff' = @(
        'https://github.com/Orbdiff/BAMReveal/releases/download/v1.2.5/BAMReveal.exe'
        'https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.6/pv++.exe'
        'https://github.com/Orbdiff/MFT-HardLink/releases/download/v1.2/HardLink.exe'
    )
    'Detect' = @(
        'https://detect.ac/tool/ToolsDownloader++'
    )
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-NextSSFolder {
    $i = 1
    while (Test-Path "C:\ss$i") { $i++ }
    return "C:\ss$i"
}

function Get-FilenameFromUrl {
    param([string]$Url)
    $path = ([System.Uri]$Url).AbsolutePath
    return [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($path))
}

function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$GroupFolder,
        [System.Collections.Generic.List[string]]$FailedList
    )

    $filename = Get-FilenameFromUrl -Url $Url
    $isZip    = $filename -match '\.zip$'

    if ($isZip) {
        $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $tempZip    = Join-Path $GroupFolder $filename
        $extractDir = Join-Path $GroupFolder $baseName
        Write-Host "    ${DkOrange}↓ ${Orange}$filename${Reset} " -NoNewline
        try {
            Invoke-WebRequest -Uri $Url -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
            $null = New-Item -ItemType Directory -Path $extractDir -Force
            Expand-Archive -Path $tempZip -DestinationPath $extractDir -Force
            Remove-Item -Path $tempZip -Force
            Write-Host "${Green}✓${Reset}"
        } catch {
            Write-Host "${Red}✗${Reset}"
            $FailedList.Add($Url)
            if (Test-Path $tempZip) { Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue }
        }
    } else {
        $destPath = Join-Path $GroupFolder $filename
        Write-Host "    ${DkOrange}↓ ${Orange}$filename${Reset} " -NoNewline
        try {
            Invoke-WebRequest -Uri $Url -OutFile $destPath -UseBasicParsing -ErrorAction Stop
            Write-Host "${Green}✓${Reset}"
        } catch {
            Write-Host "${Red}✗${Reset}"
            $FailedList.Add($Url)
        }
    }
}

function Show-Banner {
    Clear-Host

    # Mars planet (rust reds with crater spots)
    $mr = $MarsRed; $mo = $MarsOrange; $mc = $MarsCrater; $r = $Reset
    Write-Host ""
    Write-Host "             ${mr}▄▄█████████████▄▄${r}"
    Write-Host "           ${mr}███${mo}▓▓░░░░░░░░░▓▓${mr}███${r}"
    Write-Host "         ${mr}████${mo}░░░${mc}▓▓▓${mo}░░░░░░░░░${mr}████${r}"
    Write-Host "        ${mr}███${mo}░░░░░░░░░░${mc}▓▓${mo}░░░░░${mr}███${r}"
    Write-Host "       ${mr}███${mo}░░${mc}▓▓${mo}░░░░░░░░░░░░░░${mr}███${r}"
    Write-Host "      ${mr}███${mo}░░░░░░░░${mc}▓▓${mo}░░░░░░░░░${mr}███${r}"
    Write-Host "      ${mr}███${mo}░░░${mc}▓${mo}░░░░░░░░░${mc}▓▓${mo}░░░${mr}███${r}"
    Write-Host "       ${mr}███${mo}░░░░░░${mc}▓${mo}░░░░░░░░░░${mr}███${r}"
    Write-Host "        ${mr}███${mo}░░░░░░░░░░░░░░░${mr}███${r}"
    Write-Host "         ${mr}████████████████████${r}"
    Write-Host ""

    # MarsPixel wordmark — gradient gold → dark orange top to bottom
    Write-Host "${Gold}${Bold}  ███╗   ███╗ █████╗ ██████╗ ███████╗    ██████╗ ██╗██╗  ██╗███████╗██╗      ${Reset}"
    Write-Host "${Gold}${Bold}  ████╗ ████║██╔══██╗██╔══██╗██╔════╝    ██╔══██╗██║╚██╗██╔╝██╔════╝██║      ${Reset}"
    Write-Host "${Orange}${Bold}  ██╔████╔██║███████║██████╔╝███████╗    ██████╔╝██║ ╚███╔╝ █████╗  ██║      ${Reset}"
    Write-Host "${Orange}${Bold}  ██║╚██╔╝██║██╔══██║██╔══██╗╚════██║    ██╔═══╝ ██║ ██╔██╗ ██╔══╝  ██║      ${Reset}"
    Write-Host "${DkOrange}${Bold}  ██║ ╚═╝ ██║██║  ██║██║  ██║███████║    ██║     ██║██╔╝ ██╗███████╗███████╗ ${Reset}"
    Write-Host "${DkOrange}${Bold}  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ${Reset}"
    Write-Host ""
    Write-Host "${Gray}                    Anti-Cheat Forensics Collector  •  v1.0${Reset}"
    Write-Host "${DkOrange}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

$ssFolder   = Get-NextSSFolder
$totalTools = ($Groups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

Write-Host "  ${Orange}Output folder  ${Gold}$ssFolder${Reset}"
Write-Host "  ${Orange}Total tools    ${Gold}$totalTools${Reset} ${Gray}across $($Groups.Count) groups${Reset}"
Write-Host ""

# ── Download mode prompt ──────────────────────────────────────────────────────
Write-Host "  ${Gold}Download mode:${Reset}"
Write-Host ""
Write-Host "    ${DkOrange}[A]${Orange}  All tools ${Gray}($totalTools files)${Reset}"
Write-Host "    ${DkOrange}[C]${Orange}  Choose specific groups${Reset}"
Write-Host ""
$mode = (Read-Host "  >").Trim().ToUpper()

[string[]]$selectedNames = @()

if ($mode -eq 'A') {
    $selectedNames = @($Groups.Keys)
} elseif ($mode -eq 'C') {
    Write-Host ""
    $groupKeys = @($Groups.Keys)
    Write-Host "  ${Gold}Available groups:${Reset}"
    Write-Host ""
    for ($i = 0; $i -lt $groupKeys.Count; $i++) {
        $cnt = $Groups[$groupKeys[$i]].Count
        Write-Host "    ${DkOrange}[$($i + 1)]${Orange} $($groupKeys[$i]) ${Gray}($cnt tools)${Reset}"
    }
    Write-Host ""
    Write-Host "  ${Gold}Enter group numbers separated by commas ${Gray}(e.g. 1,3,5)${Gold}:${Reset}"
    $raw = (Read-Host "  >").Trim()

    foreach ($part in ($raw -split ',')) {
        $part = $part.Trim()
        if ($part -match '^\d+$') {
            $idx = [int]$part - 1
            if ($idx -ge 0 -and $idx -lt $groupKeys.Count) {
                $selectedNames += $groupKeys[$idx]
            }
        }
    }

    if ($selectedNames.Count -eq 0) {
        Write-Host ""
        Write-Host "  ${Red}No valid groups selected. Exiting.${Reset}"
        exit 0
    }
} else {
    Write-Host ""
    Write-Host "  ${Red}Invalid choice. Exiting.${Reset}"
    exit 0
}

# ── Confirmation ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${Gold}Selected groups:${Reset}"
Write-Host ""
$totalSelected = 0
foreach ($name in $selectedNames) {
    $cnt = $Groups[$name].Count
    $totalSelected += $cnt
    Write-Host "    ${Orange}• $name ${Gray}($cnt tools)${Reset}"
}
Write-Host ""
Write-Host "  ${Gold}Files to download: ${Orange}$totalSelected${Reset}"
Write-Host ""
$confirm = (Read-Host "  ${Gold}Proceed? [Y/N]  >${Reset}").Trim().ToUpper()
if ($confirm -ne 'Y') {
    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ── Setup output folder + AV exclusion ───────────────────────────────────────
Write-Host ""
Write-Host "  ${Orange}Creating ${Gold}$ssFolder${Orange}...${Reset}" -NoNewline
$null = New-Item -ItemType Directory -Path $ssFolder -Force
Write-Host " ${Green}✓${Reset}"

Write-Host "  ${Orange}Adding Windows Defender exclusion...${Reset}" -NoNewline
if (-not (Get-Command -Name 'Add-MpPreference' -ErrorAction SilentlyContinue)) {
    Write-Host " ${Gray}skipped (Defender not present)${Reset}"
} else {
    try {
        Add-MpPreference -ExclusionPath $ssFolder -ErrorAction Stop
        Write-Host " ${Green}✓${Reset}"
    } catch {
        Write-Host " ${Red}✗ (non-fatal — $_)${Reset}"
    }
}

# ── Download ──────────────────────────────────────────────────────────────────
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {
    $urls     = $Groups[$groupName]
    $groupDir = Join-Path $ssFolder $groupName
    $null = New-Item -ItemType Directory -Path $groupDir -Force

    Write-Host ""
    Write-Host "  ${Gold}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    foreach ($url in $urls) {
        Invoke-FileDownload -Url $url -GroupFolder $groupDir -FailedList $failed
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
$succeeded = $totalSelected - $failed.Count
Write-Host ""
Write-Host "  ${DkOrange}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host "  ${Green}✓ Downloaded : $succeeded / $totalSelected${Reset}"

if ($failed.Count -gt 0) {
    Write-Host "  ${Red}✗ Failed     : $($failed.Count)${Reset}"
    Write-Host ""
    Write-Host "  ${Red}Failed URLs:${Reset}"
    foreach ($f in $failed) {
        Write-Host "    ${Gray}$f${Reset}"
    }
}

Write-Host ""
Write-Host "  ${Orange}Tools saved to ${Gold}$ssFolder${Reset}"
Write-Host "  ${DkOrange}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""
