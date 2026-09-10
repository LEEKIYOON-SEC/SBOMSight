# ⚠ 이 파일은 반드시 **UTF-8 BOM** 으로 저장한다.
#
#   Windows PowerShell 5.1(= 윈도우 기본 powershell.exe)은 BOM 이 없는 파일을
#   시스템 ANSI 코드페이지(한국어 윈도우면 CP949)로 읽는다. 그러면 한글이
#   깨지는 데서 끝나지 않고 **닫는 따옴표까지 먹혀** 파서가 죽는다:
#
#       식에 닫는 ')' 가 없습니다.
#       ParserError: MissingEndParenthesisInExpression
#
#   BOM 이 있으면 5.1 도 UTF-8 로 읽는다. PowerShell 7(pwsh)은 BOM 없이도
#   UTF-8 로 읽지만, 이 도구는 기본 powershell.exe 로도 돌아야 한다.
#   ScriptEncodingTest 가 매 빌드마다 BOM 을 확인한다.

<#
.SYNOPSIS
    자체 서명 인증서를 만든다 (초기 구축용).

.DESCRIPTION
    정식 인증서를 받으면 이 파일을 바꿔 끼우기만 하면 된다 — 사내 CA 가 내주는
    .pfx 를 config\keystore.p12 자리에 놓고 비밀번호만 맞추면 끝이다.

.EXAMPLE
    .\scripts\make-keystore.ps1 -HostName sbomsight.example.co.kr -Password 'keystore-secret'
#>
[CmdletBinding()]
param(
    # 브라우저 주소창에 칠 이름. 인증서의 CN 과 SAN 에 들어간다.
    [string] $HostName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $true)]
    [string] $Password,

    [string] $Out = "config\keystore.p12"
)

$ErrorActionPreference = 'Stop'

# keytool 은 JDK 에 딸려 온다. 없으면 JRE 만 깔렸거나 PATH 가 안 잡힌 것이다.
$keytool = Get-Command keytool -ErrorAction SilentlyContinue
if (-not $keytool) {
    throw "keytool 을 찾을 수 없습니다. JDK 21 을 설치하고 PATH 에 추가하세요 (JRE 가 아니라 JDK 입니다)."
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

if (Test-Path $Out) {
    Write-Host "이미 있습니다: $Out" -ForegroundColor Yellow
    $answer = Read-Host "덮어쓸까요? 기존 인증서는 사라집니다 (y/N)"
    if ($answer -ne 'y') { Write-Host "그대로 둡니다."; exit 0 }
    Remove-Item $Out
}

# SAN 에 호스트 이름과 이 PC 의 IP 를 모두 넣는다. 요즘 브라우저는 CN 을 보지
# 않으므로 SAN 이 없으면 "이름이 맞지 않는다"며 막는다. 내부망에서는 이름 대신
# IP 로 접속하는 일이 흔해서 IP 도 함께 넣어야 한다.
$addresses = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress -Unique

$sanParts = @("dns:$HostName", 'dns:localhost', 'ip:127.0.0.1')
$sanParts += ($addresses | ForEach-Object { "ip:$_" })
$san = ($sanParts | Select-Object -Unique) -join ','

Write-Host ""
Write-Host "인증서를 만듭니다" -ForegroundColor Cyan
Write-Host "  이름   $HostName"
Write-Host "  SAN    $san"
Write-Host ""

& keytool -genkeypair `
    -alias sbomsight `
    -keyalg RSA -keysize 3072 `
    -validity 825 `
    -storetype PKCS12 `
    -keystore $Out `
    -storepass $Password `
    -dname "CN=$HostName, OU=Security, O=SBOMSight, L=Seoul, C=KR" `
    -ext "SAN=$san" `
    -ext "KeyUsage=digitalSignature,keyEncipherment" `
    -ext "ExtendedKeyUsage=serverAuth"

if ($LASTEXITCODE -ne 0) { throw "keytool 이 실패했습니다." }

Write-Host ""
Write-Host "만들었습니다: $Out" -ForegroundColor Green
Write-Host ""
Write-Host "자체 서명이라 브라우저가 경고를 냅니다. 없애는 방법은 둘입니다:" -ForegroundColor Yellow
Write-Host "  1. 이 인증서를 사내 CA(신뢰할 수 있는 루트 인증 기관)로 등록"
Write-Host "  2. 정식 인증서를 받아 같은 자리에 .p12 로 바꿔 끼우기 (권장)"
