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

# SBOMSight 운영 값 — config\env.ps1 로 복사해서 채운다.
#
# **이 파일을 채운 것은 저장소에 올리지 않는다** (.gitignore 에 있다).
# run-server.ps1 이 시작할 때 읽는다.

# --- 포트 ---
# 금융권 지침상 https 로만 연다. 443 이 이미 쓰이면 8443 등으로 바꾼다.
$env:SBOMSIGHT_PORT = '443'

# --- 인증서 ---
# 정식 인증서를 받으면 이 파일만 바꿔 끼운다. .pfx 도 PKCS12 라 그대로 된다.
$env:SBOMSIGHT_KEYSTORE          = 'file:./config/keystore.p12'
$env:SBOMSIGHT_KEYSTORE_PASSWORD = '여기에-키스토어-비밀번호'

# --- 데이터베이스 ---
#
# allowPublicKeyRetrieval=true 를 빼지 마라. MySQL 8 은 한 번 인증한 계정을
# 메모리에 캐시해 두고 그동안은 간단한 경로로 받아 주는데, 그 캐시는 **DB 서버가
# 다시 뜨면 비워진다.** 그 뒤 첫 접속은 전체 인증을 해야 하고, 전체 인증은 TLS
# 이거나 서버의 RSA 공개키가 있어야 한다. 둘 다 없으면 드라이버가
# "RSA public key is not available client side" 로 멈춘다 — DB 는 멀쩡하고
# 비밀번호도 맞는데 재부팅한 다음 날 아침에 안 뜨는 모양이 된다.
#
# DB 를 다른 PC 에 두었다면 이 옵션 대신 sslMode=trust 를 쓴다 — 암호화된 연결
# 위에서는 공개키를 따로 받지 않는다.
$env:SBOMSIGHT_DB_URL      = 'jdbc:mariadb://localhost:3306/sbomsight?sslMode=disable&rewriteBatchedStatements=true&allowPublicKeyRetrieval=true'
$env:SBOMSIGHT_DB_USER     = 'sbomsight'
$env:SBOMSIGHT_DB_PASSWORD = '여기에-DB-비밀번호'

# --- 도구 ---
# PATH 에 있으면 이름만으로 충분하다. 아니면 전체 경로를 적는다.
$env:SBOMSIGHT_GRYPE = 'grype'

# --- 보관 ---
# SBOM 원본과 grype 결과가 여기 쌓인다. 백업 대상이다.
$env:SBOMSIGHT_DATA_DIR = 'C:\work\SBOMSight\data'

# --- 세션 ---
# 마지막 요청으로부터 이만큼 놀면 로그아웃된다.
$env:SBOMSIGHT_SESSION_TIMEOUT = '10m'

# --- 접근 IP (선택) ---
# 부트스트랩 값이다. 웹의 [설정 → 접근 IP] 에서 한 번이라도 저장하면
# 그때부터 DB 값이 쓰인다. 비워 두면 제한 없음(로그인은 여전히 필요).
# $env:SBOMSIGHT_ALLOWED_IPS = '192.168.10.0/24'
