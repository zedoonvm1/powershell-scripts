#Requires -Version 5.1

function Show-Banner {
    $duck1 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡏⠉⢻⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣾⣿⣿⣶⣶⣶⣦⣤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⠏⠉⠉⠉⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀
"@

    $duck2 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⣤⣶⣾⣷⣄⠀⠀⠀⠀⠀
⠀⠀⣶⣤⣤⣤⣤⣤⣤⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⠛⢻⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⢀⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠈⢿⣿⣿⣏⡈⠛⠿⠿⣿⣿⣿⠿⠿⠟⠋⣁⣴⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⣿⣿⣶⣦⣤⣤⣤⣤⣤⣴⣶⣿⣿⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠻⠿⠿⠿⢿⡿⠿⠿⠿⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀
"@

    $duck3 = @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡄⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣧⣾⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"@

    Write-Host $duck1 -ForegroundColor Yellow
    Write-Host $duck2 -ForegroundColor White
    Write-Host $duck3 -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "                    Made by " -NoNewline
    Write-Host "zedoon (aka Yaz) " -NoNewline -ForegroundColor White
    Write-Host "@" -NoNewline -ForegroundColor Blue
    Write-Host " Mars MC SS team " -NoNewline -ForegroundColor Yellow
    Write-Host "&" -NoNewline -ForegroundColor Blue
    Write-Host " RL forensics" -ForegroundColor Red
    Write-Host ""
    Write-Host "                    Doomsday Client Scanner v1.0" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NtdllDecompressor {
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        IntPtr WorkSpace
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat,
        out uint CompressBufferWorkSpaceSize,
        out uint CompressFragmentWorkSpaceSize
    );
    
    public static byte[] Decompress(byte[] compressed) {
        if (compressed.Length < 8) return null;
        if (compressed[0] != 0x4D || compressed[1] != 0x41 || compressed[2] != 0x4D) {
            return null;
        }
        
        int uncompSize = BitConverter.ToInt32(compressed, 4);
        
        uint wsComp, wsFrag;
        if (RtlGetCompressionWorkSpaceSize(4, out wsComp, out wsFrag) != 0) return null;
        
        IntPtr workspace = Marshal.AllocHGlobal((int)wsFrag);
        byte[] result = new byte[uncompSize];
        
        try {
            int finalSize;
            byte[] compData = new byte[compressed.Length - 8];
            Array.Copy(compressed, 8, compData, 0, compData.Length);
            
            uint status = RtlDecompressBufferEx(4, result, uncompSize, 
                compData, compData.Length, out finalSize, workspace);
            
            if (status != 0) return null;
            return result;
        }
        finally {
            Marshal.FreeHGlobal(workspace);
        }
    }
}
"@

function Get-SystemIndexes {
    param([string]$FilePath)
    
    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)
        
        $isCompressed = ($data[0] -eq 0x4D -and $data[1] -eq 0x41 -and $data[2] -eq 0x4D)
        
        if ($isCompressed) {
            $data = [NtdllDecompressor]::Decompress($data)
            if ($data -eq $null) {
                Write-Warning "Failed to decompress: $FilePath"
                return @()
            }
        }
        
        $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
        if ($sig -ne "SCCA") {
            Write-Warning "Invalid file signature: $FilePath"
            return @()
        }
        
        $stringsOffset = [BitConverter]::ToUInt32($data, 100)
        $stringsSize = [BitConverter]::ToUInt32($data, 104)
        
        $filenames = @()
        $pos = $stringsOffset
        $endPos = $stringsOffset + $stringsSize
        
        while ($pos -lt $endPos -and $pos -lt $data.Length - 2) {
            $nullPos = $pos
            while ($nullPos -lt $data.Length - 1) {
                if ($data[$nullPos] -eq 0 -and $data[$nullPos + 1] -eq 0) {
                    break
                }
                $nullPos += 2
            }
            
            if ($nullPos -gt $pos) {
                $strLen = $nullPos - $pos
                if ($strLen -gt 0 -and $strLen -lt 2048) {
                    try {
                        $filename = [System.Text.Encoding]::Unicode.GetString($data, $pos, $strLen)
                        if ($filename.Length -gt 0) {
                            $filenames += $filename
                        }
                    }
                    catch { }
                }
            }
            
            $pos = $nullPos + 2
            
            if ($filenames.Count -gt 1000) { break }
        }
        
        return $filenames
    }
    catch {
        Write-Warning "Error parsing $FilePath : $_"
        return @()
    }
}

function Test-FileInSizeRange {
    param(
        [string]$Path,
        [long]$MinBytes = 200KB,
        [long]$MaxBytes = 15MB
    )
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        return $false
    }
    
    try {
        $size = (Get-Item $Path -ErrorAction Stop).Length
        return ($size -ge $MinBytes -and $size -le $MaxBytes)
    }
    catch {
        return $false
    }
}

$script:BytePatterns = @(
    @{
        Name = "Pattern #1"
        Bytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
    },
    @{
        Name = "Pattern #2"
        Bytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
    },
    @{
        Name = "Pattern #3"
        Bytes = "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3"
    }
)

$script:ClassPatterns = @(
    "net/java/f",
    "net/java/g",
    "net/java/h",
    "net/java/i",
    "net/java/k",
    "net/java/l",
    "net/java/m",
    "net/java/r",
    "net/java/s",
    "net/java/t",
    "net/java/y"
)

function ConvertHex-ToBytes {
    param([string]$hexString)
    
    $bytes = New-Object byte[] ($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Search-BytePattern {
    param(
        [byte[]]$data,
        [byte[]]$pattern
    )
    
    $patternLength = $pattern.Length
    $dataLength = $data.Length
    
    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($data[$i + $j] -ne $pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $true
        }
    }
    return $false
}

function Search-ClassPattern {
    param(
        [byte[]]$data,
        [string]$className
    )
    
    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($className)
    return Search-BytePattern -data $data -pattern $classBytes
}

function Test-ZipMagicBytes {
    param([string]$Path)
    
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($fileStream)
        
        if ($fileStream.Length -lt 2) {
            $reader.Close()
            $fileStream.Close()
            return $false
        }
        
        $byte1 = $reader.ReadByte()
        $byte2 = $reader.ReadByte()
        
        $reader.Close()
        $fileStream.Close()
        
        return ($byte1 -eq 0x50 -and $byte2 -eq 0x4B)
        
    } catch {
        return $false
    }
}

function Find-SingleLetterClasses {
    param([string]$Path)
    
    $singleLetterClasses = @()
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        foreach ($entry in $jar.Entries) {
            if ($entry.FullName -like "*.class") {
                $className = $entry.FullName
                
                $parts = $className -split '/'
                $filename = $parts[-1]
                
                $classNameOnly = $filename -replace '\.class$', ''
                
                if ($classNameOnly -match '^[a-zA-Z]$') {
                    $fullPath = ($parts[0..($parts.Length-2)] -join '/') + '/' + $classNameOnly
                    $singleLetterClasses += $fullPath
                }
            }
        }
        
        $jar.Dispose()
        
    } catch {
    }
    
    return $singleLetterClasses
}

function Test-DoomsdayClient {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    $result = [PSCustomObject]@{
        IsDetected = $false
        Confidence = "NONE"
        BytePatternMatches = @()
        ClassNameMatches = @()
        SingleLetterClasses = @()
        IsRenamedJar = $false
        Error = $null
    }
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        $result.Error = "File not found"
        return $result
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        $hasPKHeader = Test-ZipMagicBytes -Path $Path
        
        if ($hasPKHeader -and $fileExtension -ne ".jar") {
            $result.IsRenamedJar = $true
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        
        if (-not $hasPKHeader) {
            $result.Error = "File is not a JAR/ZIP file (missing PK header)"
            return $result
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        $classFiles = $jar.Entries | Where-Object { $_.FullName -like "*.class" }
        $classCount = $classFiles.Count
        
        if ($classCount -gt 30) {
            $jar.Dispose()
            $result.Error = "Skipped: Too many classes ($classCount) - likely legitimate library"
            return $result
        }
        
        if ($classCount -eq 0) {
            $jar.Dispose()
            $result.Error = "No .class files found in JAR"
            return $result
        }
        
        $allBytes = @()
        
        foreach ($entry in $classFiles) {
            $stream = $entry.Open()
            $reader = New-Object System.IO.BinaryReader($stream)
            $bytes = $reader.ReadBytes([int]$entry.Length)
            $allBytes += $bytes
            $reader.Close()
            $stream.Close()
        }
        
        $jar.Dispose()
        
        foreach ($pattern in $script:BytePatterns) {
            $patternBytes = ConvertHex-ToBytes -hexString $pattern.Bytes
            
            if (Search-BytePattern -data $allBytes -pattern $patternBytes) {
                $result.BytePatternMatches += $pattern.Name
            }
        }
        
        foreach ($className in $script:ClassPatterns) {
            if (Search-ClassPattern -data $allBytes -className $className) {
                $result.ClassNameMatches += $className
            }
        }
        
        $result.SingleLetterClasses = Find-SingleLetterClasses -Path $Path
        
        $byteMatchCount = $result.BytePatternMatches.Count
        $classMatchCount = $result.ClassNameMatches.Count
        $singleLetterCount = $result.SingleLetterClasses.Count
        
        if ($byteMatchCount -ge 2) {
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        elseif ($byteMatchCount -eq 1 -and ($classMatchCount -ge 5 -or $singleLetterCount -ge 5)) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($byteMatchCount -eq 1) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        elseif ($singleLetterCount -ge 8 -and $classMatchCount -ge 3) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($singleLetterCount -ge 5 -or $classMatchCount -ge 5) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        
        if ($result.IsRenamedJar -and $result.Confidence -eq "NONE") {
            $result.Confidence = "MEDIUM"
        }
        
    } catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Start-DoomsdayScan {
    Show-Banner
    
    if (-not (Test-Administrator)) {
        Write-Host ""
        Write-Host "ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Administrator privileges required!"
        Write-Host ""
        Write-Host "Please launch CMD or PowerShell as admin!" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    
    Write-Host "[*] Extracting file indexes..." -ForegroundColor Cyan
    Write-Host ""
    
    $systemPath = "C:\Windows\" + "Pre" + "fetch"
    $javaFiles = Get-ChildItem -Path $systemPath -Filter "JAVA*.EXE-*.pf" -ErrorAction SilentlyContinue
    
    if ($javaFiles.Count -eq 0) {
        Write-Host "[!] No relevant files found" -ForegroundColor Yellow
        return
    }
    
    $allJarPaths = @()
    $fileMetadata = @{}
    $processedFiles = 0
    
    foreach ($sysFile in $javaFiles) {
        $processedFiles++
        Write-Progress -Activity "Extracting Indexes" `
                      -Status "Processing file $processedFiles of $($javaFiles.Count)" `
                      -PercentComplete (($processedFiles / $javaFiles.Count) * 100)
        
        $indexes = Get-SystemIndexes -FilePath $sysFile.FullName
        
        if ($indexes.Count -eq 0) {
            continue
        }
        
        $indexNum = 0
        foreach ($index in $indexes) {
            $indexNum++
            
            if ($index -match '\\VOLUME\{[^\}]+\}\\') {
                $relativePath = $index -replace '\\VOLUME\{[^\}]+\}\\', ''
                $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
                
                foreach ($drive in $drives) {
                    $testPath = Join-Path $drive.Root $relativePath
                    
                    if (Test-Path $testPath -PathType Leaf) {
                        $allJarPaths += $testPath
                        
                        if (-not $fileMetadata.ContainsKey($testPath)) {
                            $fileMetadata[$testPath] = @{
                                SourceFile = $sysFile.Name
                                IndexNumber = $indexNum
                            }
                        }
                    }
                }
            }
            else {
                $allJarPaths += $index
                
                if (-not $fileMetadata.ContainsKey($index)) {
                    $fileMetadata[$index] = @{
                        SourceFile = $sysFile.Name
                        IndexNumber = $indexNum
                    }
                }
            }
        }
    }
    
    Write-Progress -Activity "Extracting Indexes" -Completed
    
    Write-Host ""
    Write-Host "[+] Total files in size range: $($allJarPaths.Count)" -ForegroundColor Green
    
    if ($allJarPaths.Count -eq 0) {
        Write-Host "[!] No files found in 200KB-15MB range" -ForegroundColor Yellow
        return
    }
    
    $uniquePaths = $allJarPaths | Select-Object -Unique
    Write-Host "[+] Unique files to scan: $($uniquePaths.Count)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "[*] Scanning files for Doomsday Client..." -ForegroundColor Cyan
    Write-Host ""
    
    $existingPaths = @()
    $missingCount = 0
    
    Write-Host "[*] Checking file existence..." -ForegroundColor Cyan
    Write-Host ""
    
    $checkCount = 0
    foreach ($path in $uniquePaths) {
        $checkCount++
        
        if (Test-Path $path -PathType Leaf) {
            if (Test-FileInSizeRange -Path $path -MinBytes 200KB -MaxBytes 15MB) {
                $existingPaths += $path
            }
        } else {
            $extension = [System.IO.Path]::GetExtension($path).ToUpper()
            
            if ($path -match '\.' -and $extension -ne ".LOG" -and $extension -ne ".TMP") {
                $missingCount++
                Write-Host "  [SKIPPED] File deleted [$missingCount]: " -ForegroundColor Yellow -NoNewline
                Write-Host $path -ForegroundColor Gray
            }
        }
    }
    
    Write-Host ""
    Write-Host "[+] Total files checked: $checkCount" -ForegroundColor Cyan
    Write-Host "[+] Files exist and in size range (200KB-15MB): $($existingPaths.Count)" -ForegroundColor Green
    Write-Host "[!] Files deleted/missing: $missingCount" -ForegroundColor Yellow
    Write-Host ""
    
    if ($existingPaths.Count -eq 0) {
        Write-Host "[!] No files exist to scan" -ForegroundColor Yellow
        return
    }
    
    $detections = @()
    $scanned = 0
    $skipped = 0
    
    foreach ($path in $existingPaths) {
        $scanned++
        
        $filename = [System.IO.Path]::GetFileName($path)
        
        Write-Progress -Activity "Scanning for Doomsday Client" `
                      -Status "[$scanned/$($existingPaths.Count)]" `
                      -PercentComplete (($scanned / $existingPaths.Count) * 100)
        
        Write-Host "`r[$scanned/$($existingPaths.Count)]" -NoNewline -ForegroundColor Cyan
        
        try {
            $result = Test-DoomsdayClient -Path $path
            
            if ($result.Error -and $result.Error -like "Skipped:*") {
                $skipped++
            }
            
            if ($result.IsDetected) {
                Write-Host "`r                              `r" -NoNewline
                
                $detections += [PSCustomObject]@{
                    Path = $path
                    SourceFile = $fileMetadata[$path].SourceFile
                    IndexNumber = $fileMetadata[$path].IndexNumber
                    Confidence = $result.Confidence
                    IsRenamedJar = $result.IsRenamedJar
                    BytePatterns = $result.BytePatternMatches.Count
                    ClassMatches = $result.ClassNameMatches.Count
                    SingleLetterClasses = $result.SingleLetterClasses.Count
                }
                
                Write-Host "[!] DETECTION: " -ForegroundColor Red -NoNewline
                Write-Host $path
                Write-Host "    Confidence: " -NoNewline
                
                switch ($result.Confidence) {
                    "HIGH"   { Write-Host "HIGH" -ForegroundColor Red }
                    "MEDIUM" { Write-Host "MEDIUM" -ForegroundColor Yellow }
                    "LOW"    { Write-Host "LOW" -ForegroundColor Gray }
                }
                
                if ($result.IsRenamedJar) {
                    Write-Host "    Renamed JAR detected!" -ForegroundColor Red
                }
                if ($result.BytePatternMatches.Count -gt 0) {
                    Write-Host "    Byte patterns: $($result.BytePatternMatches.Count)" -ForegroundColor Red
                }
                Write-Host ""
            }
        }
        catch {
            Write-Host "`r                              `r" -NoNewline
            Write-Host "Error scanning $filename : $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`r                              `r" -NoNewline
    
    Write-Progress -Activity "Scanning for Doomsday Client" -Completed
    Write-Host ""
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total indexes extracted: $($allJarPaths.Count)"
    Write-Host "Files in size range: $($uniquePaths.Count)"
    Write-Host "Files exist: $($existingPaths.Count)"
    Write-Host "Files scanned: $scanned"
    Write-Host "Files skipped (>30 classes): $skipped" -ForegroundColor Gray
    Write-Host "Doomsday Client detections: " -NoNewline
    
    if ($detections.Count -gt 0) {
        Write-Host $detections.Count -ForegroundColor Red
        
        Write-Host ""
        Write-Host "Detections by confidence:" -ForegroundColor Yellow
        $high = ($detections | Where-Object { $_.Confidence -eq "HIGH" }).Count
        $medium = ($detections | Where-Object { $_.Confidence -eq "MEDIUM" }).Count
        $low = ($detections | Where-Object { $_.Confidence -eq "LOW" }).Count
        
        if ($high -gt 0) { Write-Host "  HIGH: $high" -ForegroundColor Red }
        if ($medium -gt 0) { Write-Host "  MEDIUM: $medium" -ForegroundColor Yellow }
        if ($low -gt 0) { Write-Host "  LOW: $low" -ForegroundColor Gray }
        
        Write-Host ""
        Write-Host "DOOMSDAY CLIENT DETECTED ON THIS SYSTEM!" -ForegroundColor Red
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "DETECTION DETAILS" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        
        $detectionNum = 1
        foreach ($detection in $detections) {
            Write-Host "[$detectionNum] " -NoNewline -ForegroundColor Red
            Write-Host $detection.Path -ForegroundColor White
            Write-Host "    Source File: " -NoNewline
            Write-Host $detection.SourceFile -ForegroundColor Cyan
            Write-Host "    Index Number: " -NoNewline
            Write-Host "#$($detection.IndexNumber)" -ForegroundColor Cyan
            Write-Host "    Confidence: " -NoNewline
            
            switch ($detection.Confidence) {
                "HIGH"   { Write-Host "HIGH" -ForegroundColor Red }
                "MEDIUM" { Write-Host "MEDIUM" -ForegroundColor Yellow }
                "LOW"    { Write-Host "LOW" -ForegroundColor Gray }
            }
            
            if ($detection.IsRenamedJar) {
                Write-Host "    Renamed JAR: " -NoNewline
                Write-Host "YES" -ForegroundColor Red
            }
            
            if ($detection.BytePatterns -gt 0) {
                Write-Host "    Byte Patterns: " -NoNewline
                Write-Host $detection.BytePatterns -ForegroundColor Red
            }
            
            if ($detection.ClassMatches -gt 0) {
                Write-Host "    Class Matches: " -NoNewline
                Write-Host $detection.ClassMatches -ForegroundColor Yellow
            }
            
            if ($detection.SingleLetterClasses -gt 0) {
                Write-Host "    Single-Letter Classes: " -NoNewline
                Write-Host $detection.SingleLetterClasses -ForegroundColor Yellow
            }
            
            Write-Host ""
            $detectionNum++
        }
        
    } else {
        Write-Host "0" -ForegroundColor Green
        Write-Host ""
        Write-Host "No Doomsday Client detected!" -ForegroundColor Green
    }
    
    Write-Host ""
}

Start-DoomsdayScan