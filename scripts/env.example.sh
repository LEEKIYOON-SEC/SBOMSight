# SBOMSight 운영 값 (Linux) — config/env 로 복사해서 채운다.
#
#   cp scripts/env.example.sh config/env && chmod 600 config/env
#
# **채운 것은 저장소에 올리지 않는다** (.gitignore 에 있다). 비밀번호가 들어
# 있으므로 띄우는 계정만 읽게 둔다(600). scripts/run-server.sh 가 시작할 때
# 셸로 읽는다 — 윈도우의 config\env.ps1 과 같은 자리다.
#
# **값은 작은따옴표로 감싼다.** 셸로 읽으므로 따옴표가 없으면 DB 주소의 `&` 가
# 명령을 뒤로 돌리고, 비밀번호의 `$` 가 변수로 풀린다. 값 안에 작은따옴표가
# 있으면 '\'' 로 적는다.

# --- 포트 ---
# 금융권 지침상 https 로만 연다. 1024 미만(443)은 권한이 필요하다 — 서비스로
# 돌리면 systemd 가 준다(docs/linux-setup.md). 손으로 띄울 때는 8443 이 편하다.
SBOMSIGHT_PORT='443'

# --- 인증서 ---
# 정식 인증서를 받으면 이 파일만 바꿔 끼운다. .pfx 도 PKCS12 라 그대로 된다.
SBOMSIGHT_KEYSTORE='file:./config/keystore.p12'
SBOMSIGHT_KEYSTORE_PASSWORD='여기에-키스토어-비밀번호'

# --- 데이터베이스 ---
# 주소를 **반드시** 적는다. 비워 두면 개발용 기본값(127.0.0.1:13306)으로 붙는다.
# allowPublicKeyRetrieval=true 를 빼지 마라 — MySQL 8 은 DB 서버가 다시 뜬 뒤 첫
# 접속에서 그것이 없으면 "RSA public key is not available" 로 멈춘다
# (scripts/env.example.ps1 의 설명과 같다). DB 를 다른 PC 에 두었다면 이 옵션
# 대신 sslMode=trust.
SBOMSIGHT_DB_URL='jdbc:mariadb://localhost:3306/sbomsight?sslMode=disable&rewriteBatchedStatements=true&allowPublicKeyRetrieval=true'
SBOMSIGHT_DB_USER='sbomsight'
SBOMSIGHT_DB_PASSWORD='여기에-DB-비밀번호'

# --- 도구 ---
# 서비스 계정의 PATH 는 로그인 셸과 다르다. 전체 경로로 적는다.
SBOMSIGHT_GRYPE='/usr/local/bin/grype'
# grype 가 취약점 DB 를 찾는 자리. 적지 않으면 띄우는 계정의 ~/.cache/grype 다.
GRYPE_DB_CACHE_DIR='/var/lib/sbomsight/grype-db'
# 폐쇄망이면 false — grype 가 검사 중에 DB 를 받으러 나가지 않는다.
# GRYPE_DB_AUTO_UPDATE='false'

# --- 보관 ---
# SBOM 원본과 grype 결과가 여기 쌓인다. 백업 대상이다.
SBOMSIGHT_DATA_DIR='/var/lib/sbomsight/data'

# --- 세션 ---
# 마지막 요청으로부터 이만큼 놀면 로그아웃된다.
SBOMSIGHT_SESSION_TIMEOUT='10m'

# --- 접근 IP (선택) ---
# 부트스트랩 값이다. 웹의 [설정 → 접근 IP] 에서 한 번이라도 저장하면
# 그때부터 DB 값이 쓰인다. 비워 두면 제한 없음(로그인은 여전히 필요).
# SBOMSIGHT_ALLOWED_IPS='192.168.10.0/24'
