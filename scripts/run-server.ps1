# SBOMSight 웹 서버 기동 (Windows 11 / PowerShell)
#
# 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가 담긴다. 그래서 기본
# 바인딩은 127.0.0.1이며, 외부에 노출하려면 SBOMSIGHT_HOST를 명시적으로
# 바꿔야 한다.
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

$EnvFile = ".env"
if (Test-Path $EnvFile) {
    Write-Host "[i] .env 로드"
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#=]+)\s*=\s*(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

$BindHost = if ($env:SBOMSIGHT_HOST) { $env:SBOMSIGHT_HOST } else { "127.0.0.1" }
$Port = if ($env:SBOMSIGHT_PORT) { $env:SBOMSIGHT_PORT } else { "8000" }

python -c "import fastapi" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] 의존성이 없습니다. 먼저 실행하세요:"
    Write-Host "    python -m pip install -r requirements.txt"
    exit 1
}

$GrypeBin = if ($env:GRYPE_BIN) { $env:GRYPE_BIN } else { "grype" }
if (-not (Get-Command $GrypeBin -ErrorAction SilentlyContinue)) {
    Write-Host "[!] grype를 찾을 수 없습니다. scripts\install-tools.ps1 로 설치하거나"
    Write-Host "    GRYPE_BIN 환경변수로 경로를 지정하세요. (설치 전에는 스캔이 실패합니다)"
}

if ($BindHost -ne "127.0.0.1" -and $BindHost -ne "localhost") {
    Write-Host "[!] 주의: $BindHost 로 바인딩합니다. 스캔 결과에는 내부 자산 정보가 담기므로"
    Write-Host "    신뢰할 수 없는 네트워크에 노출하지 마세요."
}

Write-Host "[i] http://${BindHost}:${Port}"
python -m uvicorn server.app:app --host $BindHost --port $Port @args
