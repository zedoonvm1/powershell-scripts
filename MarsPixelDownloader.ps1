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

# ── Required Assemblies & Connection Optimizations ───────────────────────────
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12, Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}
[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

# ── ANSI palette (MarsPixel) ──────────────────────────────────────────────────
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
    'Orbdiff' = @(
        'https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.8/pv++.exe'
        'https://github.com/Orbdiff/BAMReveal/releases/download/v1.3.1/BAMReveal.exe'
        'https://github.com/Orbdiff/MFT-HardLink/releases/download/v1.2/HardLink.exe'
        'https://github.com/Orbdiff/Fileless/releases/download/v1.3/fileless.exe'
        'https://github.com/Orbdiff/StringsParser/releases/download/v1.2.1b/stringsparser.1.2.1b.exe'
        'https://github.com/Orbdiff/AmcacheParser/releases/download/v1.0/AmcacheParser.exe'
        'https://github.com/Orbdiff/UserAssistView/releases/download/v1.0/UserAssistView.exe'
        'https://github.com/Orbdiff/USBDetector/releases/download/v1.1/USBDetector.exe'
        'https://github.com/Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe'
        'https://github.com/Orbdiff/JARParser/releases/download/v1.2/JARParser.exe'
        'https://github.com/Orbdiff/InjGen/releases/download/fork/InjGen.exe'
    )
    'Tonynoh' = @(
        'https://github.com/MeowTonynoh/MeowClientFucker/releases/download/V1.1/MeowClientFucker.exe'
        'https://github.com/MeowTonynoh/MeowResolver/releases/download/v.1.1/MeowResolver.exe'
        'https://github.com/MeowTonynoh/MeowImportsChecker/releases/download/MeowImportsChecker/MeowImportsChecker.exe'
    )
    'Spokwn' = @(
        'https://github.com/spokwn/JournalTrace/releases/latest/download/JournalTrace.exe'
        'https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe'
        'https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe'
    )
    'Nirsoft' = @(
        'https://www.nirsoft.net/utils/lastactivityview.zip'

    )
    'Generic Tools' = @(
        'https://github.com/winsiderss/si-builds/releases/download/4.0.26245.218/systeminformer-build-canary-setup.exe'
        'https://www.voidtools.com/Everything-1.4.1.1029.x64-Setup.exe'
        'https://github.com/Inkenal/RegistryScanner/releases/download/main/RegistryScanner.exe'
        'https://github.com/Inkenal/TaskParser/releases/download/main/VigilsTaskParser.exe'
        'https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip'
        'https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe'
        'https://github.com/zedoonvm1/MarsPixelDumpAnalyzer/releases/download/Dev/MarsPixelDumpAnalyzer.exe'
        'https://mh-nexus.de/downloads/HxDPortableSetup.zip'
        'https://github.com/Sorted1/StormSS-Fuser-Finder/releases/download/Main/Storm.Fuser.Finder.zip'
        'https://github.com/Yamato-Security/hayabusa/releases/download/v4.1.0/hayabusa-4.1.0-win-x64.zip'
        'https://github.com/Col-E/Recaf/releases/download/2.21.14/recaf-2.21.14-J8-jar-with-dependencies.jar'
        'https://github.com/piespeas/MSC-Event-Viewer/releases/download/BETA/Event.Viewer.MSC.exe'
    )
    'Eric Zimmerman' = @(
        'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'
        'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'
        'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip'
        'https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip'
        'https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.308/dotnet-sdk-9.0.308-win-x64.exe'
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
    param(
        [string]$Url,
        [System.Net.Http.HttpResponseMessage]$Response = $null
    )

    if ($Response -and $Response.Content.Headers.ContentDisposition -and -not [string]::IsNullOrWhiteSpace($Response.Content.Headers.ContentDisposition.FileName)) {
        return $Response.Content.Headers.ContentDisposition.FileName.Trim('"')
    }

    if ($Response -and $Response.RequestMessage -and $Response.RequestMessage.RequestUri) {
        $finalPath = $Response.RequestMessage.RequestUri.AbsolutePath
        $finalName = [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($finalPath))
        if (-not [string]::IsNullOrWhiteSpace($finalName) -and [System.IO.Path]::HasExtension($finalName)) {
            return $finalName
        }
    }

    if ($Url -match '/ToolsDownloader\+\+$') {
        return 'ToolsDownloader++.exe'
    }

    $path = ([System.Uri]$Url).AbsolutePath
    return [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($path))
}

# ── Shared HTTP client (one connection pool for the whole run) ────────────────
# Connections + TLS sessions to github.com / objects.githubusercontent.com are reused
# instead of being re-handshaked for every file.
$HttpHandler = [System.Net.Http.SocketsHttpHandler]::new()
$HttpHandler.PooledConnectionLifetime       = [TimeSpan]::FromMinutes(5)
$HttpHandler.EnableMultipleHttp2Connections = $true
$HttpHandler.AutomaticDecompression         = [System.Net.DecompressionMethods]'GZip, Deflate, Brotli'
$HttpHandler.ConnectTimeout                 = [TimeSpan]::FromSeconds(15)

$HttpClient = [System.Net.Http.HttpClient]::new($HttpHandler)
$HttpClient.Timeout = [TimeSpan]::FromMinutes(10)
$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('MarsPixel-ToolsDownloader/2.0')

$BufferSize = 1048576   # 1 MB writes

# Zip extraction runs on a background thread so the NEXT download starts immediately.
# Downloads themselves stay strictly one at a time.
$ExtractBlock = {
    param($Zip, $Dir)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip, $Dir)
        $true
    } catch {
        try {
            if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue }
            $null = New-Item -ItemType Directory -Path $Dir -Force
            Expand-Archive -Path $Zip -DestinationPath $Dir -Force
            $true
        } catch { $false }
    } finally {
        Remove-Item -Path $Zip -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$GroupFolder,
        [System.Collections.Generic.List[string]]$FailedList,
        [System.Collections.Generic.List[object]]$ExtractList
    )

    $filename = Get-FilenameFromUrl -Url $Url
    if ([string]::IsNullOrWhiteSpace($filename)) {
        Write-Host "    ${Red}✗ URL has no downloadable filename: $Url${Reset}"
        $FailedList.Add($Url)
        return
    }

    Write-Host "    ${DkOrange}↓ ${Orange}$filename${Reset} " -NoNewline

    $ok      = $false
    $pending = $null

    # Up to 3 attempts per file.
    for ($attempt = 1; $attempt -le 3 -and -not $ok; $attempt++) {
        $targetFile = $null
        $tempZip    = $null
        try {
            $response = $HttpClient.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            [void]$response.EnsureSuccessStatusCode()

            $betterName = Get-FilenameFromUrl -Url $Url -Response $response
            if (-not [string]::IsNullOrWhiteSpace($betterName)) { $filename = $betterName }

            $isZip    = $filename -match '\.zip$'
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($filename)
            $ext      = [System.IO.Path]::GetExtension($filename)

            # Reserve a unique path atomically (CreateNew).
            $n = 1
            while ($true) {
                $suffix     = if ($n -eq 1) { '' } else { "_$n" }
                $dest       = Join-Path $GroupFolder ("{0}{1}{2}" -f $baseName, $suffix, $ext)
                $extractDir = Join-Path $GroupFolder ("{0}{1}" -f $baseName, $suffix)
                if ($isZip -and (Test-Path $extractDir)) { $n++; continue }
                try {
                    $fs = [System.IO.FileStream]::new($dest, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferSize, [System.IO.FileOptions]::SequentialScan)
                    break
                } catch [System.IO.IOException] { $n++ }
            }
            if ($isZip) { $tempZip = $dest } else { $targetFile = $dest }

            $ns = $null
            try {
                $ns = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $ns.CopyTo($fs, $BufferSize)
            } finally {
                $fs.Dispose()
                if ($ns) { $ns.Dispose() }
                $response.Dispose()
            }

            if ($isZip) {
                $pending = Start-ThreadJob -ScriptBlock $ExtractBlock -ArgumentList $tempZip, $extractDir
            }
            $ok = $true
        } catch {
            if ($targetFile -and (Test-Path $targetFile)) { Remove-Item -Path $targetFile -Force -ErrorAction SilentlyContinue }
            if ($tempZip -and (Test-Path $tempZip))       { Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue }
            if ($attempt -lt 3) { Start-Sleep -Milliseconds (400 * $attempt) }
        }
    }

    if ($ok) {
        Write-Host "${Green}✓${Reset}"
        if ($pending) { $ExtractList.Add([PSCustomObject]@{ Job = $pending; Url = $Url }) }
    } else {
        Write-Host "${Red}✗${Reset}"
        $FailedList.Add($Url)
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
if (-not $totalTools) { $totalTools = 0 }

if ($Groups.Count -eq 0 -or $totalTools -eq 0) {
    Write-Host "  ${Gray}No tools configured. Add groups to `$Groups and re-run.${Reset}"
    Write-Host ""
    exit 0
}

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

# ── Download (strictly one by one) ────────────────────────────────────────────
$failed      = [System.Collections.Generic.List[string]]::new()
$extractJobs = [System.Collections.Generic.List[object]]::new()

foreach ($groupName in $selectedNames) {
    $urls     = $Groups[$groupName]
    $groupDir = Join-Path $ssFolder $groupName
    $null = New-Item -ItemType Directory -Path $groupDir -Force

    Write-Host ""
    Write-Host "  ${Gold}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    foreach ($url in $urls) {
        Invoke-FileDownload -Url $url -GroupFolder $groupDir -FailedList $failed -ExtractList $extractJobs
    }
}

# Wait for background unzips still running
foreach ($x in $extractJobs) {
    $r = @(Receive-Job -Job $x.Job -Wait -AutoRemoveJob)
    if ($r.Count -eq 0 -or $r[-1] -ne $true) {
        $failed.Add($x.Url)
        Write-Host "  ${Red}✗ extract failed: $($x.Url)${Reset}"
    }
}

$HttpClient.Dispose()
$HttpHandler.Dispose()

# ── Rename ToolsDownloader++ ───────────────────────────────────────────────────
$toolsDownloader = Get-ChildItem -Path $ssFolder -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -eq 'ToolsDownloader++' -and $_.Extension -eq '' } |
    Select-Object -First 1

if ($toolsDownloader) {
    try {
        Rename-Item -LiteralPath $toolsDownloader.FullName -NewName 'ToolsDownloader++.exe' -Force -ErrorAction Stop
        Write-Host "  ${Green}✓ Renamed ToolsDownloader++ -> ToolsDownloader++.exe${Reset}"
    } catch {
        Write-Host "  ${Red}✗ Failed to rename ToolsDownloader++: $($_.Exception.Message)${Reset}"
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
