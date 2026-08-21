# Syft·Grype 설치 (Windows 11 / PowerShell)
#
# 앞선 버전은 https://get.anchore.io/syft 를 받아 `powershell -File` 로 실행했는데,
# 그 URL이 내려주는 것은 `#!/bin/sh` POSIX 스크립트다. PowerShell은 그것을 실행할 수
# 없고(게다가 -File 은 .ps1 확장자만 받는다) 조용히 실패했다. Anchore는 Windows용
# 설치 스크립트를 제공하지 않으므로 여기서는 릴리스 ZIP을 직접 받는다.
#
# 받은 파일은 릴리스의 checksums.txt 와 SHA-256을 대조한다. 취약점 스캐너를
# 검증 없이 설치하는 것은 앞뒤가 맞지 않는다.
#
# 폐쇄망에서는 이 스크립트를 쓸 수 없다. 인터넷 되는 구간에서 ZIP과
# checksums.txt 를 함께 받아 반입하고, 해시를 확인한 뒤 압축을 풀어 PATH에 두거나
# SYFT_BIN/GRYPE_BIN 으로 경로를 지정한다.
#
#   .\scripts\install-tools.ps1
#   .\scripts\install-tools.ps1 -SyftVersion 1.50.0 -GrypeVersion 0.115.0
#   .\scripts\install-tools.ps1 -Force        # 이미 설치돼 있어도 다시 받는다

[CmdletBinding()]
param(
    [string]$SyftVersion  = "",
    [string]$GrypeVersion = "",
    [string]$InstallDir   = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
# Invoke-WebRequest 의 진행률 표시줄은 Windows PowerShell 5.1에서 큰 파일 다운로드를
# 수십 배 느리게 만든다.
$ProgressPreference = "SilentlyContinue"

# 최신 태그를 못 알아냈을 때 쓰는 하한선이다. "권장 버전"이 아니라 "확실히 존재하는
# 버전"일 뿐이므로, 가능하면 최신을 쓰고 필요하면 -SyftVersion 으로 직접 고른다.
$Fallback = @{ syft = "1.50.0"; grype = "0.115.0" }

if (-not $InstallDir) {
    $InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:LOCALAPPDATA\SBOMSight\bin" }
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { throw "지원하지 않는 아키텍처입니다: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

function Resolve-LatestVersion([string]$Name) {
    # GitHub의 releases/latest 는 실제 태그로 302 리다이렉트한다. API 키가 필요 없다.
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/anchore/$Name/releases/latest" `
            -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
        $location = $response.Headers.Location
    } catch {
        # PowerShell 5.1은 3xx를 예외로 던진다. 응답에서 Location을 꺼낸다.
        $location = $_.Exception.Response.Headers.Location
    }
    if ($location -and "$location" -match "/tag/v(?<v>[0-9][0-9.]*)$") {
        return $Matches.v
    }
    Write-Host "[!] $Name 최신 버전을 알아내지 못했습니다. 고정 버전 $($Fallback[$Name]) 을 씁니다."
    Write-Host "    최신을 쓰려면: -${Name}Version <버전>"
    return $Fallback[$Name]
}

function Get-ExpectedHash([string]$ChecksumsPath, [string]$FileName) {
    foreach ($line in Get-Content $ChecksumsPath) {
        # "<sha256>  <filename>" 형식
        if ($line -match "^(?<hash>[0-9a-fA-F]{64})\s+(?<name>\S+)\s*$" -and $Matches.name -eq $FileName) {
            return $Matches.hash.ToLower()
        }
    }
    throw "checksums.txt 에 $FileName 항목이 없습니다."
}

function Install-Tool([string]$Name, [string]$Version) {
    $existing = Get-Command $Name -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Host "[skip] $Name 이미 설치됨: $($existing.Source)"
        Write-Host "       다시 받으려면 -Force"
        return
    }

    if (-not $Version) { $Version = Resolve-LatestVersion $Name }
    $arch    = Get-Arch
    $zipName = "${Name}_${Version}_windows_${arch}.zip"
    $sumName = "${Name}_${Version}_checksums.txt"
    $base    = "https://github.com/anchore/$Name/releases/download/v$Version"

    $work = Join-Path ([System.IO.Path]::GetTempPath()) "sbomsight-$Name-$Version"
    New-Item -ItemType Directory -Force -Path $work | Out-Null

    try {
        Write-Host "[download] $zipName"
        $zipPath = Join-Path $work $zipName
        $sumPath = Join-Path $work $sumName
        Invoke-WebRequest -Uri "$base/$zipName" -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri "$base/$sumName" -OutFile $sumPath -UseBasicParsing

        $expected = Get-ExpectedHash $sumPath $zipName
        $actual   = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
        if ($actual -ne $expected) {
            throw "SHA-256 불일치입니다. 설치를 중단합니다.`n  기대: $expected`n  실제: $actual"
        }
        Write-Host "[verify] SHA-256 확인 ($($expected.Substring(0,16))…)"

        Expand-Archive -Path $zipPath -DestinationPath $work -Force
        $binary = Join-Path $work "$Name.exe"
        if (-not (Test-Path $binary)) { throw "압축 안에 $Name.exe 가 없습니다." }
        Copy-Item $binary (Join-Path $InstallDir "$Name.exe") -Force
        Write-Host "[install] $Name $Version -> $InstallDir"
    } finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-Tool "syft"  $SyftVersion
Install-Tool "grype" $GrypeVersion

Write-Host ""
Write-Host "설치 위치: $InstallDir"
if (($env:Path -split ';') -notcontains $InstallDir) {
    Write-Host "PATH에 없습니다. 다음을 실행한 뒤 새 터미널을 여세요:"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$InstallDir`", 'User')"
    Write-Host "또는 .env 에 경로를 지정하세요:"
    Write-Host "  SYFT_BIN=$InstallDir\syft.exe"
    Write-Host "  GRYPE_BIN=$InstallDir\grype.exe"
}
Write-Host ""
Write-Host "취약점 DB 준비 (인터넷 필요):  grype db update"
Write-Host "오프라인 운영:                 GRYPE_DB_AUTO_UPDATE=false 로 두고 grype db import <archive>"
