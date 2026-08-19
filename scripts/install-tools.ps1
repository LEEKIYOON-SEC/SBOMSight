# Syft·Grype 설치 (Windows 11 / PowerShell)
#
# 폐쇄망에서는 이 스크립트를 쓸 수 없다. 인터넷 되는 구간에서 바이너리를
# 내려받아 반입한 뒤 PATH에 두거나 SYFT_BIN/GRYPE_BIN으로 경로를 지정한다.
$ErrorActionPreference = "Stop"

$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:LOCALAPPDATA\SBOMSight\bin" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Install-Tool([string]$Name) {
    $existing = Get-Command $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[skip] $Name 이미 설치됨: $($existing.Source)"
        return
    }
    Write-Host "[install] $Name -> $InstallDir"
    $script = Invoke-RestMethod -Uri "https://get.anchore.io/$Name"
    $tmp = New-TemporaryFile
    Set-Content -Path $tmp -Value $script
    & powershell -ExecutionPolicy Bypass -File $tmp -b $InstallDir
    Remove-Item $tmp -Force
}

Install-Tool "syft"
Install-Tool "grype"

Write-Host ""
Write-Host "설치 위치: $InstallDir"
Write-Host "PATH에 없다면 다음을 실행하세요:"
Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$InstallDir`", 'User')"
Write-Host ""
Write-Host "취약점 DB 준비 (인터넷 필요):  grype db update"
Write-Host "오프라인 운영:                 GRYPE_DB_AUTO_UPDATE=false 로 두고 grype db import <archive>"
