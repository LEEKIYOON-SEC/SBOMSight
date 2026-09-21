package kr.sbomsight;

import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ZoneRepository;
import kr.sbomsight.service.AssetImportService;
import kr.sbomsight.service.AssetImportService.RowState;
import kr.sbomsight.service.CsvReader;
import kr.sbomsight.service.ZoneService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 자산 일괄 등록.
 *
 * <p><b>인코딩이 이 기능의 가장 큰 위험이다.</b> 한국어 윈도우의 엑셀에서
 * "CSV (쉼표로 분리)" 로 저장하면 UTF-8 이 아니라 CP949 로 나온다. 그것을
 * UTF-8 로 읽으면 한글이 전부 깨지고, <b>깨진 이름으로 자산이 등록된다</b> —
 * 그 뒤로는 어느 서버인지 아무도 모른다. 이 도구는 같은 함정에 이미 한 번
 * 걸렸다(PowerShell 스크립트의 BOM).
 */
@SpringBootTest
@Transactional
class AssetImportTest {

    private static final Charset CP949 = Charset.forName("x-windows-949");

    @Autowired AssetImportService imports;
    @Autowired AssetRepository assets;
    @Autowired ZoneRepository zones;
    @Autowired ZoneService zoneService;

    private byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] utf8Bom(String s) {
        byte[] body = utf8(s);
        byte[] out = new byte[body.length + 3];
        out[0] = (byte) 0xEF; out[1] = (byte) 0xBB; out[2] = (byte) 0xBF;
        System.arraycopy(body, 0, out, 3, body.length);
        return out;
    }

    private byte[] cp949(String s) {
        return s.getBytes(CP949);
    }

    private String uniq(String base) {
        return base + "-" + System.nanoTime();
    }

    /**
     * 파일이 쓰는 구역을 먼저 만들어 둔다. 없으면 판정이 {@code NEW} 가 아니라
     * {@code NEW_ZONE} 이 되어, 구역과 무관한 시험이 구역 때문에 깨진다.
     */
    private void ensureZone(String name) {
        if (zones.findByName(name).isEmpty()) {
            zoneService.create(name, "", "");
        }
    }

    // --- 인코딩 -------------------------------------------------------------

    @Test
    @DisplayName("엑셀이 저장한 CP949 파일의 한글을 그대로 읽는다")
    void readsCp949FromExcel() {
        String name = uniq("web");
        byte[] csv = cp949("서버 이름,구역,운영체제,비고\n"
                           + name + ",내부업무,Rocky Linux 9.3,원장 디비\n");

        AssetImportService.Preview preview = imports.preview(csv);

        assertThat(preview.charsetName()).isEqualTo("CP949");
        assertThat(preview.rows()).singleElement().satisfies(row -> {
            // 깨진 이름으로 등록되면 그 뒤로는 어느 서버인지 아무도 모른다.
            assertThat(row.zone()).isEqualTo("내부업무");
            assertThat(row.note()).isEqualTo("원장 디비");
            assertThat(row.name()).isEqualTo(name);
        });
    }

    @Test
    @DisplayName("UTF-8 도 BOM 이 있든 없든 읽는다")
    void readsUtf8WithAndWithoutBom() {
        String body = "서버 이름,구역\n" + uniq("web") + ",내부업무\n";

        assertThat(imports.preview(utf8(body)).charsetName()).isEqualTo("UTF-8");
        assertThat(imports.preview(utf8Bom(body)).charsetName()).isEqualTo("UTF-8 (BOM)");
        // BOM 이 첫 칸에 섞여 들어가면 제목 판정이 어긋난다.
        assertThat(imports.preview(utf8Bom(body)).headerSkipped()).isTrue();
    }

    @Test
    @DisplayName("BOM 이 첫 값에 붙어 들어가지 않는다")
    void stripsTheBomFromTheFirstValue() {
        String name = uniq("web");
        // 제목 없이 바로 데이터. BOM 이 남으면 이름이 "﻿web-…" 이 된다.
        AssetImportService.Preview preview = imports.preview(utf8Bom(name + ",DMZ\n"));

        assertThat(preview.rows()).singleElement()
                .extracting(AssetImportService.Row::name).isEqualTo(name);
    }

    // --- 파싱 ---------------------------------------------------------------

    @Test
    @DisplayName("따옴표 안의 쉼표를 지킨다")
    void keepsCommasInsideQuotes() {
        String name = uniq("web");
        byte[] csv = utf8(name + ",DMZ,Rocky 9.3,\"대외 웹, 인프라운영팀\"\n");

        // 쪼개면 자산 이름이 밀린다.
        assertThat(imports.preview(csv).rows()).singleElement()
                .extracting(AssetImportService.Row::note)
                .isEqualTo("대외 웹, 인프라운영팀");
    }

    @Test
    @DisplayName("따옴표 안의 두 겹 따옴표는 한 개다")
    void unescapesDoubledQuotes() {
        List<List<String>> rows = CsvReader.parse("a,\"그는 \"\"안녕\"\" 이라 했다\"\n");
        assertThat(rows).singleElement().satisfies(r ->
                assertThat(r.get(1)).isEqualTo("그는 \"안녕\" 이라 했다"));
    }

    @Test
    @DisplayName("빈 줄과 마지막 줄바꿈 없음을 견딘다")
    void toleratesBlankLinesAndNoTrailingNewline() {
        String a = uniq("web");
        String b = uniq("api");
        byte[] csv = utf8(a + ",DMZ\n\n\n" + b + ",DMZ");

        assertThat(imports.preview(csv).rows()).hasSize(2);
    }

    // --- 판정 ---------------------------------------------------------------

    @Test
    @DisplayName("제목 줄은 건너뛰되 자산 이름 같은 첫 줄은 살린다")
    void detectsTheHeaderWithoutEatingData() {
        // 제목을 등록하면 "이름" 이라는 서버가 생긴다.
        assertThat(imports.preview(utf8("서버 이름,구역\nweb-a,DMZ\n")).headerSkipped()).isTrue();
        // 반대로 제목 없는 파일의 첫 줄을 버리면 서버 하나가 조용히 빠진다.
        AssetImportService.Preview noHeader = imports.preview(utf8("web-b,DMZ\nweb-c,DMZ\n"));
        assertThat(noHeader.headerSkipped()).isFalse();
        assertThat(noHeader.rows()).hasSize(2);

        // 제목을 부분 일치로 잡으면 "웹서버" 가 "서버" 를 포함한다는 이유로
        // 제목이 되어 그 줄이 사라진다. 실제로 그렇게 만들었다가 잡혔다.
        AssetImportService.Preview looksLikeOne = imports.preview(utf8("웹서버,DMZ\nweb-d,DMZ\n"));
        assertThat(looksLikeOne.headerSkipped()).isFalse();
        assertThat(looksLikeOne.rows()).hasSize(2);
    }

    @Test
    @DisplayName("이름 규칙을 어긴 줄은 사유와 함께 건너뛴다")
    void flagsBadNames() {
        ensureZone("DMZ");
        byte[] csv = utf8("웹서버,DMZ\n-web,DMZ\n,DMZ\n" + uniq("ok") + ",DMZ\n");
        List<AssetImportService.Row> rows = imports.preview(csv).rows();

        assertThat(rows).extracting(AssetImportService.Row::state)
                .containsExactly(RowState.BAD_NAME, RowState.BAD_NAME,
                                 RowState.EMPTY_NAME, RowState.NEW);
        // 줄 번호가 남아야 파일에서 찾을 수 있다.
        assertThat(rows.get(0).line()).isEqualTo(1);
    }

    @Test
    @DisplayName("파일 안에서 겹치는 이름과 이미 있는 이름을 가려 낸다")
    void detectsDuplicates() {
        ensureZone("DMZ");
        String existing = uniq("web");
        var asset = new kr.sbomsight.domain.Asset();
        asset.setName(existing);
        asset.setZone(zoneService.unassigned());
        assets.saveAndFlush(asset);

        String dup = uniq("api");
        byte[] csv = utf8(existing + ",DMZ\n" + dup + ",DMZ\n" + dup + ",DMZ\n");

        assertThat(imports.preview(csv).rows()).extracting(AssetImportService.Row::state)
                .containsExactly(RowState.DUPLICATE_IN_DB, RowState.NEW,
                                 RowState.DUPLICATE_IN_FILE);
    }

    @Test
    @DisplayName("없는 구역은 '새로 만듭니다' 로 미리 보여 준다")
    void warnsAboutNewZones() {
        String zone = uniq("새구역");
        AssetImportService.Preview preview =
                imports.preview(utf8(uniq("web") + "," + zone + "\n"));

        // 오타 하나가 조용히 새 구역이 되는 것을 막아야 한다.
        assertThat(preview.rows()).singleElement()
                .extracting(AssetImportService.Row::state).isEqualTo(RowState.NEW_ZONE);
        assertThat(preview.newZones()).contains(zone);
    }

    // --- 적용 ---------------------------------------------------------------

    @Test
    @DisplayName("통과한 줄만 등록되고 나머지는 들어가지 않는다")
    void importsOnlyValidRows() {
        String ok = uniq("web");
        byte[] csv = utf8("서버 이름,구역,운영체제,비고\n"
                          + ok + ",DMZ,Rocky 9.3,대외 웹\n"
                          + "나쁜이름,DMZ,,\n");

        int created = imports.apply(csv, "tester");

        assertThat(created).isEqualTo(1);
        assertThat(assets.findByName(ok)).isPresent();
        assertThat(assets.findByName("나쁜이름")).isEmpty();
    }

    @Test
    @DisplayName("CP949 파일을 등록하면 한글 구역이 그대로 만들어진다")
    void importsKoreanZonesFromCp949() {
        String name = uniq("db");
        String zone = uniq("내부업무");
        imports.apply(cp949(name + "," + zone + ",Rocky 8.9,원장\n"), "tester");

        var saved = assets.findByName(name).orElseThrow();
        assertThat(zones.findByName(zone)).isPresent();
        assertThat(saved.getNote()).isEqualTo("원장");
    }

    @Test
    @DisplayName("구역을 비우면 미분류로 간다")
    void emptyZoneGoesToUnassigned() {
        String name = uniq("web");
        imports.apply(utf8(name + ",,Rocky 9.3,\n"), "tester");

        assertThat(assets.findWithZone(assets.findByName(name).orElseThrow().getId())
                         .orElseThrow().getZone().getName())
                .isEqualTo(kr.sbomsight.domain.Zone.UNASSIGNED);
    }
}
