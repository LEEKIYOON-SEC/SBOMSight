<#
.SYNOPSIS
    SBOMSight 을 띄운다.

.DESCRIPTION
    운영 값(DB 비밀번호·키스토어 비밀번호)은 config\env.ps1 에서 읽는다.
    그 파일은 저장소에 올라가지 않는다(.gitignore).

    -Listen 을 주면 방화벽 인바운드 규칙까지 만든다. 이 스위치를 쓸 때만
    관리자 권한이 필요하다 — 443 으로 여는 것 자체는 관리자가 아니어도 된다
    (윈도우는 낮은 포트를 제한하지 않는다. 그건 리눅스 얘기다).

.EXAMPLE
    .\scripts\run-server.ps1                  # 그냥 띄운다
    .\scripts\run-server.ps1 -Listen          # 방화벽까지 열고 띄운다 (관리자)
    .\scripts\run-server.ps1 -Check           # 띄우지 않고 준비 상태만 본다
#>
[CmdletBinding()]
param(
    [switch] $Listen,
    [switch] $Check,
    [int]    $Port = 0
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

function Test-Line($ok, $label, $detail = '') {
    $mark  = if ($ok) { '  OK  ' } else { ' 안됨 ' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host $mark -ForegroundColor $color -NoNewline
    Write-Host " $label" -NoNewline
    if ($detail) { Write-Host "  $detail" -ForegroundColor DarkGray } else { Write-Host '' }
    return $ok
}

# --- 준비 상태 확인 --------------------------------------------------------
Write-Host ""
Write-Host "SBOMSight 준비 상태" -ForegroundColor Cyan
Write-Host ("-" * 60)

$ready = $true

$java = Get-Command java -ErrorAction SilentlyContinue
if ($java) {
    $ver = (& java -version 2>&1 | Select-Object -First 1)
    # 21 미만이면 Spring Boot 3.3 이 안 뜬다.
    $major = if ($ver -match '"(\d+)') { [int]$Matches[1] } else { 0 }
    $ready = (Test-Line ($major -ge 21) "Java 21 이상" $ver) -and $ready
} else {
    $ready = (Test-Line $false "Java" "PATH 에 java 가 없습니다") -and $ready
}

$jar = Join-Path $root 'target\sbomsight-1.0.0.jar'
$ready = (Test-Line (Test-Path $jar) "빌드된 jar" $jar) -and $ready

# env.ps1 이 있으면 읽는다. 없어도 환경변수로 줄 수 있으므로 막지는 않는다.
$envFile = Join-Path $root 'config\env.ps1'
if (Test-Path $envFile) {
    . $envFile
    Test-Line $true "config\env.ps1" "읽었습니다" | Out-Null
} else {
    Test-Line $true "config\env.ps1" "없음 — 환경변수를 직접 주는 것으로 봅니다" | Out-Null
}

if ($Port -gt 0) { $env:SBOMSIGHT_PORT = "$Port" }
if (-not $env:SBOMSIGHT_PORT) { $env:SBOMSIGHT_PORT = '443' }
$listenPort = [int]$env:SBOMSIGHT_PORT

$keystore = if ($env:SBOMSIGHT_KEYSTORE) {
    $env:SBOMSIGHT_KEYSTORE -replace '^file:', ''
} else { 'config\keystore.p12' }
$ready = (Test-Line (Test-Path $keystore) "인증서" $keystore) -and $ready

$grypeCmd = if ($env:SBOMSIGHT_GRYPE) { $env:SBOMSIGHT_GRYPE } else { 'grype' }
$grype = Get-Command $grypeCmd -ErrorAction SilentlyContinue
$ready = (Test-Line ($null -ne $grype) "grype" $grypeCmd) -and $ready

# --- 포트가 비어 있는가 ----------------------------------------------------
# 윈도우에서 443 이 안 열리는 이유는 권한이 아니라 대개 이 둘이다.
$holder = Get-NetTCPConnection -LocalPort $listenPort -State Listen -ErrorAction SilentlyContinue
if ($holder) {
    $names = $holder | ForEach-Object {
        (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    } | Select-Object -Unique
    Test-Line $false "$listenPort 포트" "이미 쓰는 중: $($names -join ', ')" | Out-Null
    Write-Host "        IIS 나 'World Wide Web Publishing Service' 를 끄거나 다른 포트를 쓰세요." -ForegroundColor DarkGray
    $ready = $false
} else {
    Test-Line $true "$listenPort 포트" "비어 있음" | Out-Null
}

# Hyper-V·WSL 이 잡아 둔 예약 구간에 걸리면 바인딩이 조용히 실패한다.
$excluded = & netsh interface ipv4 show excludedportrange protocol=tcp 2>$null |
    Select-String -Pattern '^\s*(\d+)\s+(\d+)' |
    ForEach-Object {
        [pscustomobject]@{ Start = [int]$_.Matches[0].Groups[1].Value
                           End   = [int]$_.Matches[0].Groups[2].Value }
    } | Where-Object { $listenPort -ge $_.Start -and $listenPort -le $_.End }

if ($excluded) {
    Test-Line $false "$listenPort 예약 구간" "윈도우가 예약해 둔 범위에 들어갑니다" | Out-Null
    Write-Host "        netsh interface ipv4 show excludedportrange protocol=tcp 로 확인하세요." -ForegroundColor DarkGray
    $ready = $false
}

Write-Host ("-" * 60)

if ($Check) {
    Write-Host ""
    if ($ready) { Write-Host "준비되었습니다." -ForegroundColor Green }
    else { Write-Host "위의 '안됨' 항목을 먼저 해결하세요." -ForegroundColor Red }
    exit ($(if ($ready) { 0 } else { 1 }))
}

if (-not $ready) {
    Write-Host ""
    Write-Host "위의 '안됨' 항목을 먼저 해결하세요." -ForegroundColor Red
    exit 1
}

# --- 방화벽 ----------------------------------------------------------------
if ($Listen) {
    $admin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        throw "-Listen 은 방화벽 규칙을 만들므로 관리자 권한 PowerShell 에서 실행해야 합니다."
    }

    $ruleName = "SBOMSight ($listenPort)"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        # Private 프로파일만 연다. Public(카페 와이파이 등)에서까지 열 이유가 없다.
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
            -LocalPort $listenPort -Protocol TCP -Action Allow -Profile Private | Out-Null
        Write-Host "방화벽 규칙을 만들었습니다: $ruleName (Private 프로파일)" -ForegroundColor Green
    } else {
        Write-Host "방화벽 규칙이 이미 있습니다: $ruleName" -ForegroundColor DarkGray
    }
}

# --- 기동 ------------------------------------------------------------------
$ips = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress) -join ', '

Write-Host ""
Write-Host "접속 주소" -ForegroundColor Cyan
Write-Host "  https://localhost:$listenPort"
if ($ips) { $ips -split ', ' | ForEach-Object { Write-Host "  https://$_`:$listenPort" } }
Write-Host ""

& java "-Dfile.encoding=UTF-8" -jar $jar
