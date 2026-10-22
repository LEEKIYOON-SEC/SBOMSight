-- 패키지 유형을 purl 의 이름으로 — purl 이 없어 syft 의 이름이 담긴 행만.
--
-- 패키지 화면의 한 줄이 (이름, 유형)이 됐다. 유형은 purl 에서 따는데, purl 이 없는 원소는
-- syft 가 적은 유형(java-archive · python …)이 그대로 담겼다. 같은 jackson-databind 가
-- purl 이 있으면 maven, 없으면 java-archive 로 담겨 두 줄로 갈리고, 탐지(grype 의 유형을
-- 같은 표로 옮긴다)와도 이어지지 않는다. 새로 담는 행은 ComponentReader 가 purl 의 이름으로
-- 옮긴다 — 이미 담긴 행을 같은 표(PackageTypes)로 옮긴다.
--
-- 건드리지 않는 것:
--   purl 이 있는 행 — 유형이 이미 purl 의 것이다(앱과 같은 판단: `pkg:` 다음에 `/` 앞의
--     한 글자 이상).
--   이름이 같은 유형(rpm · deb · npm …)과 표에 없는 유형(binary …) — 받은 그대로.
--   CycloneDX 로 담긴 purl 없는 행 — 앞서 빈 값으로 담겼다. 옮길 값이 없다(다음 검사부터
--     syft 의 속성으로 찬다).
-- UnknownPackage 는 빈 값으로 — purl 도 유형도 없는 원소를 syft 가 그렇게 부른다.
--
-- 글자를 그대로 견준다(utf8mb4_bin) — 앱의 표가 대소문자를 가린다.

UPDATE component
SET type = CASE type COLLATE utf8mb4_bin
        WHEN 'pod'                    THEN 'cocoapods'
        WHEN 'conda'                  THEN 'generic'
        WHEN 'dart-pub'               THEN 'pub'
        WHEN 'dotnet'                 THEN 'nuget'
        WHEN 'erlang-otp'             THEN 'otp'
        WHEN 'github-action'          THEN 'github'
        WHEN 'github-action-workflow' THEN 'github'
        WHEN 'go-module'              THEN 'golang'
        WHEN 'java-archive'           THEN 'maven'
        WHEN 'jenkins-plugin'         THEN 'maven'
        WHEN 'linux-kernel'           THEN 'generic'
        WHEN 'linux-kernel-module'    THEN 'generic'
        WHEN 'php-composer'           THEN 'composer'
        WHEN 'php-pear'               THEN 'pear'
        WHEN 'php-pecl'               THEN 'pear'
        WHEN 'python'                 THEN 'pypi'
        WHEN 'lua-rocks'              THEN 'luarocks'
        WHEN 'R-package'              THEN 'cran'
        WHEN 'rust-crate'             THEN 'cargo'
        WHEN 'UnknownPackage'         THEN ''
    END
WHERE type COLLATE utf8mb4_bin IN ('pod', 'conda', 'dart-pub', 'dotnet', 'erlang-otp',
                                   'github-action', 'github-action-workflow', 'go-module',
                                   'java-archive', 'jenkins-plugin', 'linux-kernel',
                                   'linux-kernel-module', 'php-composer', 'php-pear', 'php-pecl',
                                   'python', 'lua-rocks', 'R-package', 'rust-crate',
                                   'UnknownPackage')
  AND NOT (purl COLLATE utf8mb4_bin LIKE 'pkg:%/%'
           AND purl COLLATE utf8mb4_bin NOT LIKE 'pkg:/%');
