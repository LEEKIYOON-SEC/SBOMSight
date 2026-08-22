# SBOMSight 웹 서버 기동 (Windows 11 / PowerShell)
#
# ⚠ 이 파일은 반드시 **UTF-8 BOM**으로 저장한다. Windows PowerShell 5.1은
#   BOM이 없는 .ps1을 시스템 ANSI 코드페이지(한국어 Windows에서는 CP949)로
#   읽는다. 그러면 한글 주석과 문자열의 UTF-8 바이트가 오독되고, CP949에서
#   유효하지 않은 trail 바이트를 만난 자리에서 **뒤따르는 ASCII 문자가 통째로
#   먹힌다** — 닫는 따옴표가 사라져 파서가 죽는다.
#   tests/test_scripts.py 가 BOM 유무를 검사한다.
#
# 업로드된 SBOM과 스캔 결과에는 내부 자산 정보가 담긴다. 그래서 기본
# 바인딩은 127.0.0.1이며, 외부에 노출하려면 -Listen 을 주거나 SBOMSIGHT_HOST를
# 명시적으로 바꿔야 한다.
#
#   .\scripts\run-server.ps1            로컬에서만 (기본)
#   .\scripts\run-server.ps1 -Listen    내부망에 개방 + 방화벽 규칙 안내
[CmdletBinding()]
param(
    [switch]$Listen,
    [string]$BindAddress = "",
    [int]$BindPort = 0
)

$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

$EnvFile = ".env"
if (Test-Path $EnvFile) {
    Write-Host "[i] .env 로드"
    # -Encoding UTF8 이 없으면 PowerShell 5.1이 .env 도 ANSI로 읽는다.
    Get-Content $EnvFile -Encoding UTF8 | ForEach-Object {
        if ($_ -match '^\s*([^#=]+)\s*=\s*(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

# 우선순위: 명령행 인자 > -Listen > .env / 환경변수 > 기본값
$BindHost =
    if ($BindAddress)            { $BindAddress }
    elseif ($Listen)             { "0.0.0.0" }
    elseif ($env:SBOMSIGHT_HOST) { $env:SBOMSIGHT_HOST }
    else                         { "127.0.0.1" }

$Port =
    if ($BindPort -gt 0)         { "$BindPort" }
    elseif ($env:SBOMSIGHT_PORT) { $env:SBOMSIGHT_PORT }
    else                         { "8000" }

# 가상환경이 있으면 활성화 여부와 무관하게 그 python을 쓴다. 활성화를 잊고
# 실행하면 전역 python에는 의존성이 없어 "먼저 설치하세요"만 반복하게 된다.
$Python = "python"
$VenvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
    Write-Host "[i] 가상환경 사용: .venv"
}

& $Python -c "import fastapi" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] 의존성이 없습니다. 먼저 실행하세요:"
    Write-Host "    python -m venv .venv"
    Write-Host "    .\.venv\Scripts\Activate.ps1"
    Write-Host "    python -m pip install -r requirements.txt"
    exit 1
}

$GrypeBin = if ($env:GRYPE_BIN) { $env:GRYPE_BIN } else { "grype" }
if (-not (Get-Command $GrypeBin -ErrorAction SilentlyContinue)) {
    Write-Host "[!] grype를 찾을 수 없습니다. scripts\install-tools.ps1 로 설치하거나"
    Write-Host "    GRYPE_BIN 환경변수로 경로를 지정하세요. (설치 전에는 스캔이 실패합니다)"
}

$IsPublic = $BindHost -ne "127.0.0.1" -and $BindHost -ne "localhost"

if ($IsPublic) {
    Write-Host ""
    Write-Host "[!] $BindHost 로 바인딩합니다 — 이 PC 밖에서 접속할 수 있게 됩니다."
    Write-Host "    스캔 결과에는 어떤 서버에 어떤 취약점이 있는지가 그대로 담깁니다."
    Write-Host "    신뢰할 수 있는 내부망에서만 여세요."
    Write-Host ""

    # 바인딩을 열어도 Windows 방화벽이 두 번째 관문이다. 규칙이 없으면
    # 다른 PC에서 접속이 조용히 실패하고, 원인을 찾기 어렵다.
    $RuleName = "SBOMSight ($Port)"
    $Existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-Host "[i] 방화벽 규칙 있음: $RuleName"
    } else {
        Write-Host "[!] 방화벽 인바운드 규칙이 없습니다. 관리자 PowerShell에서 한 번 실행하세요:"
        Write-Host ""
        Write-Host "    New-NetFirewallRule -DisplayName '$RuleName' -Direction Inbound ``"
        Write-Host "      -LocalPort $Port -Protocol TCP -Action Allow -Profile Private"
        Write-Host ""
        Write-Host "    (규칙이 없으면 다른 PC에서 접속이 되지 않습니다)"
        Write-Host ""
    }

    # 접속에 쓸 주소를 알려 준다. 0.0.0.0 은 주소가 아니라 '전부'라는 뜻이라
    # 그대로 브라우저에 칠 수 없다.
    $Addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" }
    foreach ($Address in $Addresses) {
        Write-Host "[i] 접속 주소  http://$($Address.IPAddress):$Port"
    }
}

# AI 상태를 미리 알려 준다 — 결과 화면에서 전송 버튼이 안 보이는 이유를
# 그때 가서 찾게 하지 않기 위한 것이다. 키 값 자체는 출력하지 않는다.
if ($env:SBOMSIGHT_AI_ENABLED -in @("1", "true", "yes", "on")) {
    if ($env:GEMINI_API_KEY) {
        $Model = if ($env:GEMINI_MODEL) { $env:GEMINI_MODEL } else { "gemini-3.5-flash-lite" }
        Write-Host "[i] AI 사용 가능 · 모델 $Model"
    } else {
        Write-Host "[!] SBOMSIGHT_AI_ENABLED=1 이지만 GEMINI_API_KEY 가 없습니다. 룰 기반으로만 동작합니다."
    }
} else {
    Write-Host "[i] AI 미사용 (기본값). 보고서는 룰 기반으로 완결됩니다."
}

Write-Host "[i] http://${BindHost}:${Port}"
& $Python -m uvicorn server.app:app --host $BindHost --port $Port @args
