package kr.sbomsight.service;

import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.domain.FindingAnalysis;
import kr.sbomsight.domain.Finding;
import kr.sbomsight.domain.FixVersions;
import kr.sbomsight.domain.Remediation;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * CSV 내보내기.
 *
 * <p>결재와 공유는 엑셀로 돈다. 한글이 깨지지 않게 <b>UTF-8 BOM</b> 을 붙인다 —
 * 없으면 엑셀이 파일을 EUC-KR 로 짐작해 전부 깨진 글자로 연다.
 *
 * <p>줄 구분은 CRLF 다. 엑셀이 LF 만 있는 파일을 한 줄로 읽는 경우가 있다.
 */
public final class CsvWriter {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private CsvWriter() {
    }

    public static void writeRemediations(OutputStream out, List<Remediation> list)
            throws IOException {
        try (Writer writer = start(out)) {
            row(writer, "자산", "패키지", "현재 버전", "목표 버전", "조치 상태", "담당", "기한",
                        "등록 당시 건수", "설명", "등록", "최종 변경");
            for (Remediation r : list) {
                row(writer,
                    r.getAsset().getName(),
                    r.getPackageName(),
                    r.getFromVersion(),
                    // 하나로 고르지 않는다 — 여럿이면 `수정 버전 N가지: a · b` (화면과 같은 규칙)
                    FixVersions.describe(r.getToVersions()),
                    r.getStatus().label(),
                    r.getOwner(),
                    r.getDueDate() == null ? "" : r.getDueDate().format(DAY),
                    String.valueOf(r.getOpenedCount()),
                    r.getNote(),
                    WHEN.format(r.getCreatedAt()),
                    WHEN.format(r.getUpdatedAt()));
            }
        }
    }

    /**
     * 검토 결과.
     *
     * <p>자산과 구역이 앞에 온다. 이 파일로 답해야 하는 질문이 "어느 서버의
     * 무엇을 어떻게 하기로 했나" 이기 때문이다.
     *
     * <p><b>고르는 값은 화면 말로 적는다.</b> 표준값({@code NOT_AFFECTED})을
     * 그대로 내보내면 결재 서류에 붙였을 때 아무도 못 읽는다. 표준 이름이
     * 필요한 자리는 VEX 내보내기이지 이 파일이 아니다.
     */
    public static void writeAnalyses(OutputStream out, List<FindingAnalysis> rows)
            throws IOException {
        try (Writer writer = start(out)) {
            row(writer, "자산", "구역", "취약점", "패키지", "검토 상태", "근거", "대응 방안",
                        "설명", "추가 보안 통제", "결재 문서 번호", "재검토일",
                        "기록한 사람", "기록한 때");
            for (FindingAnalysis a : rows) {
                row(writer,
                    a.getAsset().getName(),
                    a.getAsset().getZone().getName(),
                    a.getCve(),
                    a.getPackageName(),
                    a.getState().label(),
                    a.getJustification() == null ? "" : a.getJustification().label(),
                    a.getResponse() == null ? "" : a.getResponse().label(),
                    a.getNote(),
                    a.getOtherControl(),
                    a.getApprovalDoc(),
                    a.getReviewBy() == null ? "" : a.getReviewBy().format(DAY),
                    a.getUpdatedBy(),
                    WHEN.format(a.getUpdatedAt()));
            }
        }
    }

    /**
     * 감사 로그.
     *
     * <p>시각은 <b>초까지</b> 적는다. 같은 분 안에 여러 일이 일어나는 것이
     * 흔하고, 점검에서 순서를 묻는다.
     */
    public static void writeAuditLog(OutputStream out, List<AuditLog> rows) throws IOException {
        try (Writer writer = start(out)) {
            row(writer, "시각", "계정", "행위", "대상", "내용", "접속 IP");
            for (AuditLog a : rows) {
                row(writer,
                    SECONDS.format(a.getAt()),
                    a.getActor(),
                    a.getAction().label(),
                    a.getTarget(),
                    a.getDetail(),
                    a.getClientIp());
            }
        }
    }

    /**
     * 전사 조회 결과.
     *
     * <p>자산과 구역이 앞에 온다. 이 파일로 답해야 하는 질문이 "어느 서버냐"
     * 이기 때문이다.
     */
    public static void writeLookup(OutputStream out, List<Finding> findings) throws IOException {
        try (Writer writer = start(out)) {
            row(writer, "자산", "구역", "CVE", "grype 식별자", "심각도", "CVSS",
                        "패키지", "설치 버전", "수정 버전", "수정 상태", "검사 시각");
            for (Finding f : findings) {
                var asset = f.getScan().getAsset();
                row(writer,
                    asset.getName(),
                    asset.getZone().getName(),
                    f.getDisplayId(),
                    f.getSecondaryId(),
                    f.getSeverity(),
                    f.getCvssScore() == null ? "" : f.getCvssScore().toPlainString(),
                    f.getPackageName(),
                    f.getPackageVersion(),
                    f.getFixedVersion(),
                    f.getFixState(),
                    WHEN.format(f.getScan().getCreatedAt()));
            }
        }
    }

    /**
     * 패키지 인벤토리.
     *
     * <p>한 줄이 {@code (패키지, 버전)} 하나다 — 화면의 버전 조각 하나. 버전
     * 분포를 한 칸에 몰아 넣으면 엑셀에서 거르지도 정렬하지도 못한다.
     *
     * <p><b>등급은 grype 이 낸 것 중 가장 높은 것</b>이고, 걸린 것이 없으면
     * 빈 칸이다 — {@code 없음} 이라고 적으면 아무도 내리지 않은 판정이 된다.
     * 건수 0 은 값이다(최신 검사에서 매치가 없었다).
     */
    public static void writePackages(OutputStream out, List<PackageService.ExportRow> rows)
            throws IOException {
        try (Writer writer = start(out)) {
            row(writer, "패키지", "유형", "버전", "자산 수", "취약점", "최고 등급");
            for (PackageService.ExportRow r : rows) {
                var version = r.version();
                row(writer,
                    r.name(),
                    r.type(),
                    version.version(),
                    String.valueOf(version.assetCount()),
                    String.valueOf(version.total()),
                    version.worst() == null ? "" : version.worst().label());
            }
        }
    }

    private static Writer start(OutputStream out) throws IOException {
        Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
        writer.write('﻿');   // BOM — 엑셀이 UTF-8 로 읽게 하는 유일한 방법
        return writer;
    }

    private static void row(Writer writer, String... cells) throws IOException {
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) {
                writer.write(',');
            }
            writer.write(quote(cells[i]));
        }
        writer.write("\r\n");
    }

    /**
     * 값 하나를 CSV 칸으로.
     *
     * <p>{@code =} 나 {@code +} 로 시작하는 값은 엑셀이 <b>수식으로 실행한다.</b>
     * 패키지 이름이나 메모에 그런 글자가 들어올 수 있으므로 앞에 작은따옴표를
     * 붙여 글자로 남긴다.
     */
    private static String quote(String value) {
        String text = value == null ? "" : value;
        if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        return '"' + text.replace("\"", "\"\"") + '"';
    }
}
