# ⚠ 이 파일은 반드시 **UTF-8 BOM** 으로 저장한다 (ScriptEncodingTest 가 확인한다).

<#
.SYNOPSIS
    SBOMSight 를 재부팅해도 올라오게 등록한다.

.DESCRIPTION
    `run-server.ps1` 은 앞단에서 돈다 — 창을 닫거나 PC 를 재부팅하면 내려간다.
    팀이 함께 쓰는 도구가 그러면 "언제부터 안 됐는지" 를 아무도 모른다.

    **작업 스케줄러에 등록한다.** 윈도우에 들어 있는 것이라 폐쇄망에 따로
    반입할 것이 없다 — NSSM 같은 외부 프로그램을 쓰지 않는 이유가 그것이다.

      트리거   시스템 시작 1분 뒤 (DB 가 먼저 올라와야 한다)
      계정     SYSTEM (로그온하지 않아도 돈다)
      실패 시  1분 뒤 다시 시작, 세 번까지
      기록     logs\service.log (10MB 를 넘으면 .1 로 밀어 둔다)

    **창이 없으니 콘솔에 찍히던 것을 파일로 받는다.** 최초 관리자 비밀번호도,
    기동이 실패한 이유도 그 파일에만 남는다.

.PARAMETER Remove
    등록을 지운다. 돌고 있으면 내리고, 다음 부팅에 올라오지 않는다.

.PARAMETER Start
    지금 띄운다.

.PARAMETER Stop
    지금 내린다. **판올림 전에 반드시 한다** — 도는 동안에는 jar 가 잠겨 있어
    `.\mvnw.cmd clean package` 가 그 파일을 지우지 못하고 빌드가 실패한다.

.EXAMPLE
    관리자 PowerShell 에서:
      .\scripts\install-service.ps1            # 등록하고 띄운다
      .\scripts\install-service.ps1 -Stop      # 내린다 (판올림 전)
      .\scripts\install-service.ps1 -Start     # 다시 띄운다
      .\scripts\install-service.ps1 -Remove    # 등록을 지운다

.NOTES
    **최초 관리자 비밀번호는 계정이 하나도 없는 첫 기동에 한 번만 찍힌다.**
    서비스로 먼저 올리면 그것이 화면이 아니라 `logs\service.log` 에만 남는다.
    docs/windows-setup.md 11단계(첫 로그인)를 먼저 끝내고 등록하는 편이 쉽다.

    **SYSTEM 으로 돌면 사용자 폴더가 달라진다.** grype 는 취약점 DB 를
    사용자 캐시(`%LOCALAPPDATA%\grype`)에 두므로, 로그인 계정으로 받아 둔 DB 를
    SYSTEM 이 못 찾는다. 폐쇄망이면 `config\env.ps1` 에 위치를 못 박아 두라:

      $env:GRYPE_DB_CACHE_DIR = 'C:\work\grype-db'

    자세한 것은 docs/operations.md · docs/offline-operations.md.
#>
[CmdletBinding()]
param(
    [switch] $Remove,
    [switch] $Start,
    [switch] $Stop
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$TaskName = 'SBOMSight'
$Root     = (Get-Location).Path
$Jar      = Join-Path $Root 'target\sbomsight-1.0.0.jar'
$Launcher = Join-Path $Root 'scripts\service-launch.ps1'
$LogFile  = Join-Path $Root 'logs\service.log'

# 관리자인가. 작업 등록·시작·정지 모두 관리자만 된다 — 아니면 무슨 말인지
# 알 수 없는 오류로 끝난다.
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    throw '관리자 PowerShell 에서 실행하세요. (시작 → PowerShell → 마우스 오른쪽 → 관리자 권한으로 실행)'
}

function Get-SbomSightProcess {
    # 이 jar 인 것만 고른다. 이름만 보고 java 를 끝내면 남의 프로그램을 끈다.
    @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" `
        -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -like '*sbomsight-1.0.0.jar*' })
}

function Stop-SbomSight {
    # Stop-ScheduledTask 는 작업이 띄운 powershell 을 끝내지만, 그 자식인 java
    # 까지 반드시 따라 죽지는 않는다. 남으면 포트를 쥔 채 남아 다음 기동이
    # 조용히 실패한다 — 그래서 프로세스까지 확인해 끝낸다.
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        $procs = Get-SbomSightProcess
        if (-not $procs) { return $true }
        $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 1
    }
    return (-not (Get-SbomSightProcess))
}

function Get-SbomSightPort {
    # 메시지에 쓸 포트. env.ps1 을 읽고, 없으면 서비스가 쓰는 기본값과 같은
    # 443 으로 본다.
    if (Test-Path '.\config\env.ps1') { . '.\config\env.ps1' }
    if ($env:SBOMSIGHT_PORT) { $env:SBOMSIGHT_PORT } else { '443' }
}

function Wait-SbomSightUp($port) {
    # 스프링 부트가 올라오는 데 십수 초 걸린다. 포트를 듣기 시작하면 된 것이다.
    Write-Host "올라오기를 기다립니다" -NoNewline
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 2
        Write-Host "." -NoNewline
        $up = Get-NetTCPConnection -LocalPort ([int]$port) -State Listen -ErrorAction SilentlyContinue
        if ($up) { Write-Host ""; return $true }
    }
    Write-Host ""
    return $false
}

function Show-Tail($lines = 20) {
    if (Test-Path $LogFile) {
        Write-Host ""
        Write-Host "logs\service.log 끝 $lines 줄" -ForegroundColor Cyan
        Get-Content $LogFile -Tail $lines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "기록 파일이 아직 없습니다: $LogFile" -ForegroundColor DarkGray
    }
}

# --- 내리기 ----------------------------------------------------------------
if ($Stop) {
    if (Stop-SbomSight) {
        Write-Host "내렸습니다. 다음 부팅에는 다시 올라옵니다 (등록은 남아 있습니다)."
    } else {
        throw '프로세스가 남아 있습니다. 작업 관리자에서 java 를 확인하세요.'
    }
    return
}

# --- 등록 지우기 -----------------------------------------------------------
if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-SbomSight | Out-Null
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "등록을 지웠습니다. 다음 부팅에 올라오지 않습니다."
        Write-Host "다시 띄우려면 .\scripts\run-server.ps1 을 쓰세요."
    } else {
        Write-Host "등록되어 있지 않습니다."
    }
    return
}

# --- 띄우기 ----------------------------------------------------------------
if ($Start) {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        throw "등록되어 있지 않습니다. 먼저 .\scripts\install-service.ps1 을 실행하세요."
    }
    Start-ScheduledTask -TaskName $TaskName
    $port = Get-SbomSightPort
    if (Wait-SbomSightUp $port) {
        Write-Host "올라왔습니다 — https://localhost:$port" -ForegroundColor Green
    } else {
        Write-Host "$port 포트를 듣지 않습니다. 기록을 보세요." -ForegroundColor Red
        Show-Tail
    }
    return
}

# --- 등록 ------------------------------------------------------------------
if (-not (Test-Path $Jar)) {
    throw "$Jar 가 없습니다. .\mvnw.cmd clean package 를 먼저 실행하세요."
}

# 자바를 전체 경로로 못 박는다. SYSTEM 의 PATH 는 로그인 계정의 것과 다르다.
#
# javaw.exe(창 없는 판) 를 쓰지 않는다 — 출력을 파일로 받아야 하고, 어차피
# SYSTEM 의 작업은 보이는 창이 없다. 창을 아끼려다 기동 실패 이유를 잃는다.
$javaCmd = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaCmd) { throw 'PATH 에 java 가 없습니다. JDK 21 을 먼저 설치하세요.' }
$java = $javaCmd.Source

$port = Get-SbomSightPort
if (-not (Test-Path '.\config\env.ps1')) {
    Write-Host "config\env.ps1 이 없습니다 — DB·인증서 비밀번호 없이 기동하면 실패합니다." -ForegroundColor Red
    Write-Host "  Copy-Item scripts\env.example.ps1 config\env.ps1" -ForegroundColor DarkGray
}

# 운영 값은 config\env.ps1 에 있고, 작업 스케줄러는 환경변수를 넘기지 못한다.
# 그래서 그 파일을 읽고 jar 를 띄우는 스크립트를 만들어 두고 그것을 등록한다.
$launcherText = @"
# install-service.ps1 이 만든다. 손으로 고치지 않는다 (.gitignore 대상).
#
# `$ErrorActionPreference 를 'Stop' 으로 두지 않는다. 자바는 정상 출력도 stderr
# 로 내는 것이 있어서(예: java -version), 'Stop' 이면 그 한 줄에 죽는다.
Set-Location '$Root'
if (Test-Path '.\config\env.ps1') { . '.\config\env.ps1' }

# run-server.ps1 과 같은 기본값을 준다. 이것이 없으면 application.yml 의 8443
# 으로 떨어져, 설치 문서가 안내한 주소(https://localhost)가 열리지 않는다.
if (-not `$env:SBOMSIGHT_PORT) { `$env:SBOMSIGHT_PORT = '443' }

`$log = '$LogFile'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent `$log) | Out-Null
if ((Test-Path `$log) -and (Get-Item `$log).Length -gt 10MB) { Move-Item `$log "`$log.1" -Force }

# 한 줄씩 바로 파일에 쓴다(Out-File 은 모아 두었다가 쓴다). 기동 중에 다른
# 창에서 Get-Content -Wait 로 들여다볼 수 있어야 한다.
Add-Content -Path `$log -Value "=== `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') SBOMSight 시작 ===" -Encoding UTF8
& '$java' '-Dfile.encoding=UTF-8' '-jar' '$Jar' 2>&1 |
    ForEach-Object { Add-Content -Path `$log -Value "`$_" -Encoding UTF8 }

# 자바의 끝 코드를 그대로 물려준다. **이 줄이 없으면 powershell.exe 는 0 으로
# 끝난다** — 자바가 DB 접속 실패로 죽어도 작업 스케줄러는 성공으로 보고, 위에
# 걸어 둔 '실패 시 1분 뒤 다시 시작' 이 한 번도 동작하지 않는다.
exit `$LASTEXITCODE
"@

# BOM 을 직접 붙여 쓴다. `Set-Content -Encoding UTF8` 은 PowerShell 5.1 에서는
# BOM 을 붙이지만 7 에서는 붙이지 않는다 — 7 로 등록하면 BOM 없는 파일이
# 만들어지고, 작업이 부르는 powershell.exe(5.1)가 그것을 CP949 로 읽어 한글
# 주석에서 파서가 죽는다. 부팅 때 조용히 실패하는, 가장 찾기 어려운 고장이다.
[IO.File]::WriteAllText($Launcher, $launcherText, (New-Object Text.UTF8Encoding $true))

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`"" `
    -WorkingDirectory $Root
$trigger   = New-ScheduledTaskTrigger -AtStartup
# 부팅 뒤 1분 기다린다. DB 가 먼저 올라와 있어야 하고, 시스템 시작 트리거는
# 서비스들과 거의 동시에 뜬다 — 기다리지 않으면 첫 기동이 접속 실패로 죽고
# 다시 시작을 한 바퀴 돌려 쓸데없이 몇 분을 잡아먹는다.
$trigger.Delay = 'PT1M'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# MultipleInstances 를 못 박는다. 둘이 뜨면 뒤엣것이 포트를 못 잡고 죽으면서
# 앞엣것이 멀쩡한데도 실패로 기록된다.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew `
    -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3 `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host ""
Write-Host "등록했습니다 — 작업 이름 '$TaskName'" -ForegroundColor Green
Write-Host "  트리거   시스템 시작 1분 뒤 (DB 가 먼저 올라와야 합니다)"
Write-Host "  계정     SYSTEM (로그온하지 않아도 돕니다)"
Write-Host "  실패 시  1분 뒤 다시 시작, 세 번까지"
Write-Host "  기록     logs\service.log"
Write-Host ""

Start-ScheduledTask -TaskName $TaskName
if (Wait-SbomSightUp $port) {
    Write-Host "올라왔습니다 — https://localhost:$port" -ForegroundColor Green
    $ips = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -ExpandProperty IPAddress)
    $ips | ForEach-Object { Write-Host "                https://$_`:$port" }
} else {
    Write-Host "$port 포트를 듣지 않습니다. 아래 기록에서 이유를 찾으세요." -ForegroundColor Red
    Write-Host "  (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult  # 0 이어야 합니다" -ForegroundColor DarkGray
    Show-Tail
}

Write-Host ""
Write-Host "판올림 전에는 먼저 내리세요 — 도는 동안 jar 가 잠겨 빌드가 실패합니다:" -ForegroundColor Yellow
Write-Host "  .\scripts\install-service.ps1 -Stop"
Write-Host ""
Write-Host "폐쇄망이면 config\env.ps1 에 GRYPE_DB_CACHE_DIR 을 못 박으세요 —"
Write-Host "SYSTEM 은 로그인 계정의 grype DB 캐시를 못 찾습니다."
