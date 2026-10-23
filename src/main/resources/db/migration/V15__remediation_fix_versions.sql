-- 조치의 목표 버전 — 하나로 고르지 않고 수정 버전 전부를 적는다.
--
-- 앞서 조치는 CVSS 가 가장 높은 건의 수정 버전 하나를 적었다. 보고서는
-- 글자로 가장 큰 것 하나를 적었다. 같은 curl 조치의 목표가 조치 화면은
-- deb10u4(그리로 올려도 10건이 남는다), 보고서는 deb10u9 였다. 글자로 가장
-- 큰 것은 `9.0.90` 을 `9.0.107` 보다 크다고 본다.
--
-- 버전끼리 견주려면 배포판·언어마다 다른 규칙을 짜 넣어야 하고, 그것은 검사
-- 결과가 준 것을 다시 판정하는 일이다. **여럿이면 여럿을 적는다**(사용자
-- 결정). 조치 화면 · 보고서 · CSV 가 같은 규칙을 쓴다(FixVersions).
--
-- 저장하는 꼴: 수정 버전을 글자 순으로 빈칸 하나씩 띄워 잇는다. 버전 문자열에는
-- 빈칸이 없다. 버전 하나만 적힌 옛 행도 그대로 읽힌다.

-- 1) 넓힌다. 스물다섯 가지(openjdk)가 237자였다 — 255 에 거의 닿는다.
ALTER TABLE remediations
    MODIFY COLUMN to_version VARCHAR(4000) NOT NULL DEFAULT '';

-- 2) 이미 등록된 조치는 **등록한 검사에서 다시 모은다** — 스냅샷의 뜻(등록
--    당시)은 그대로 두고, 고른 하나를 전부로 바꾼다. 보고서 3장과 같은 건에서
--    모은다: 수정 상태가 fixed 이고, 그 자산의 검토 결과가 해당 없음 · 오탐인
--    건은 뺀다(주 식별자로 적은 것이 먼저, 없으면 함께 온 CVE 번호로 적은 것).
--
--    등록한 검사가 지워졌으면 **그대로 둔다** — 다시 모을 데가 없는데 비우면
--    적혀 있던 것이 사라진다.
SET SESSION group_concat_max_len = 1048576;

UPDATE remediations r
SET r.to_version = COALESCE((
        SELECT GROUP_CONCAT(DISTINCT f.fixed_version
                            ORDER BY f.fixed_version COLLATE utf8mb4_bin SEPARATOR ' ')
        FROM findings f
        WHERE f.scan_id = r.opened_scan_id
          AND f.package_name = r.package_name
          AND f.fix_state = 'fixed'
          AND f.fixed_version <> ''
          AND NOT EXISTS (
                SELECT 1 FROM finding_analysis fa
                WHERE fa.asset_id = r.asset_id
                  AND fa.package_name = f.package_name
                  AND fa.state IN ('NOT_AFFECTED', 'FALSE_POSITIVE')
                  AND (fa.cve = f.cve
                       OR (fa.cve = f.related_cve
                           AND NOT EXISTS (SELECT 1 FROM finding_analysis fd
                                           WHERE fd.asset_id = r.asset_id
                                             AND fd.package_name = f.package_name
                                             AND fd.cve = f.cve))))
    ), '')
WHERE r.opened_scan_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM scans s WHERE s.id = r.opened_scan_id);
