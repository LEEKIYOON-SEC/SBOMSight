package kr.sbomsight.service;

import kr.sbomsight.domain.Asset;
import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.Zone;
import kr.sbomsight.repo.AssetRepository;
import kr.sbomsight.repo.ZoneRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 자산 일괄 등록 — CSV 한 장으로 서버 수십 대.
 *
 * <p><b>미리 보고 나서 넣는다.</b> 바로 밀어 넣으면 무엇이 들어갔고 무엇이
 * 걸러졌는지 나중에야 알게 되고, 그때는 이미 절반쯤 등록된 상태다. 먼저
 * 줄마다 판정을 붙여 보여 주고, 확인을 받은 뒤에 넣는다.
 *
 * <p><b>걸러진 줄을 조용히 버리지 않는다.</b> "30줄 중 24줄 등록" 만 말하면
 * 나머지 여섯이 무엇이었는지 알 수 없다. 줄 번호와 사유를 그대로 돌려준다.
 */
@Service
public class AssetImportService {

    /** {@link Asset} 의 이름 규칙과 같아야 한다 — 여기서만 느슨하면 저장에서 터진다. */
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]*$");

    /**
     * 한 파일의 줄 수 한도 — 제목 줄은 세지 않는다. <b>넘으면 파일을 받지 않는다.</b>
     *
     * <p>앞서는 앞 5,000줄만 남기고 나머지를 말없이 버렸다. 미리보기는 5,000줄을
     * 보여 주고 등록 단추를 달았고, 파일이 그보다 길었다는 것은 화면 어디에도
     * 없었다 — 등록하면 뒤의 줄이 빠진 채 끝났다. 잘라서 받으면 나머지를 따로 떼어
     * 다시 업로드해야 하는데, 어디서 잘렸는지는 미리보기에 없다.
     */
    private static final int MAX_ROWS = 5000;

    private final AssetRepository assets;
    private final ZoneRepository zones;
    private final ZoneService zoneService;
    private final AuditService audit;

    public AssetImportService(AssetRepository assets, ZoneRepository zones,
                              ZoneService zoneService, AuditService audit) {
        this.assets = assets;
        this.zones = zones;
        this.zoneService = zoneService;
        this.audit = audit;
    }

    /** 줄 하나의 판정. */
    public enum RowState {
        NEW("등록"),
        NEW_ZONE("등록 (구역도 새로 만듭니다)"),
        DUPLICATE_IN_DB("건너뜀 — 같은 이름이 이미 있습니다"),
        DUPLICATE_IN_FILE("건너뜀 — 파일 안에서 이름이 겹칩니다"),
        BAD_NAME("건너뜀 — 이름은 영문·숫자로 시작하고 . _ - 만 쓸 수 있습니다"),
        EMPTY_NAME("건너뜀 — 이름이 비어 있습니다"),
        TOO_LONG("건너뜀 — 값이 너무 깁니다");

        private final String label;

        RowState(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        public boolean importable() {
            return this == NEW || this == NEW_ZONE;
        }
    }

    public record Row(int line, String name, String zone, String os, String note, RowState state) {
    }

    public record Preview(List<Row> rows, String charsetName, boolean headerSkipped) {

        public long importable() {
            return rows.stream().filter(r -> r.state().importable()).count();
        }

        public long skipped() {
            return rows.size() - importable();
        }

        public List<String> newZones() {
            return rows.stream().filter(r -> r.state() == RowState.NEW_ZONE)
                       .map(Row::zone).distinct().sorted().toList();
        }

        public boolean isEmpty() {
            return rows.isEmpty();
        }
    }

    /**
     * 읽어서 줄마다 판정을 붙인다. 아무것도 저장하지 않는다.
     *
     * @throws IllegalArgumentException 줄 수가 한도({@link #MAX_ROWS})를 넘을 때 — 화면에
     *                                  그대로 띄울 사유를 담는다
     */
    @Transactional(readOnly = true)
    public Preview preview(byte[] csv) {
        CsvReader.Decoded decoded = CsvReader.decode(csv);
        List<List<String>> raw = CsvReader.parse(decoded.text());

        boolean headerSkipped = false;
        if (!raw.isEmpty() && looksLikeHeader(raw.get(0))) {
            raw = raw.subList(1, raw.size());
            headerSkipped = true;
        }
        if (raw.size() > MAX_ROWS) {
            throw new IllegalArgumentException(String.format(
                    "줄이 너무 많습니다 (최대 %,d줄 · 이 파일 %,d줄%s). 나눠서 업로드해 주세요.",
                    MAX_ROWS, raw.size(), headerSkipped ? " — 제목 줄 제외" : ""));
        }

        Set<String> existing = new HashSet<>();
        assets.findAll().forEach(a -> existing.add(a.getName().toLowerCase(Locale.ROOT)));
        Set<String> zoneNames = new HashSet<>();
        zones.findAll().forEach(z -> zoneNames.add(z.getName()));

        Set<String> seenInFile = new HashSet<>();
        List<Row> rows = new ArrayList<>();
        int line = headerSkipped ? 2 : 1;

        for (List<String> cells : raw) {
            String name = cell(cells, 0);
            String zone = cell(cells, 1);
            String os = cell(cells, 2);
            String note = cell(cells, 3);

            RowState state;
            if (name.isEmpty()) {
                state = RowState.EMPTY_NAME;
            } else if (name.length() > 128 || zone.length() > 64
                       || os.length() > 128 || note.length() > 500) {
                state = RowState.TOO_LONG;
            } else if (!NAME.matcher(name).matches()) {
                state = RowState.BAD_NAME;
            } else if (existing.contains(name.toLowerCase(Locale.ROOT))) {
                state = RowState.DUPLICATE_IN_DB;
            } else if (!seenInFile.add(name.toLowerCase(Locale.ROOT))) {
                state = RowState.DUPLICATE_IN_FILE;
            } else if (!zone.isEmpty() && !zoneNames.contains(zone)) {
                // 없는 구역은 만들어 준다. 다만 미리보기에 그렇게 적어 둔다 —
                // 오타 하나가 조용히 새 구역이 되는 것을 막아야 한다.
                state = RowState.NEW_ZONE;
            } else {
                state = RowState.NEW;
            }

            rows.add(new Row(line++, name, zone, os, note, state));
        }

        return new Preview(rows, decoded.charsetName(), headerSkipped);
    }

    /**
     * 미리보기에서 통과한 줄만 등록한다. 미리보기가 받지 않는 파일은 여기서도 받지
     * 않는다 — 같은 {@link #preview} 를 지나므로 한 줄도 넣기 전에 멈춘다.
     *
     * @return 실제로 등록된 수
     */
    @Transactional
    public int apply(byte[] csv, String actor) {
        Preview preview = preview(csv);
        int created = 0;

        for (Row row : preview.rows()) {
            if (!row.state().importable()) {
                continue;
            }
            Zone zone = row.zone().isEmpty()
                    ? zoneService.unassigned()
                    : zones.findByName(row.zone())
                           .orElseGet(() -> zoneService.create(row.zone(), "", ""));

            Asset asset = new Asset();
            asset.setName(row.name());
            asset.setZone(zone);
            asset.setOsName(row.os());
            asset.setNote(row.note());
            assets.save(asset);
            created++;
        }

        if (created > 0) {
            audit.record(AuditEvent.ASSET_CREATED, "일괄 등록",
                         created + "대 등록 · " + preview.skipped() + "줄 건너뜀 ("
                         + preview.charsetName() + ")");
        }
        return created;
    }

    /**
     * 제목 줄로 인정하는 첫 칸의 값. <b>정확히 일치할 때만</b> 제목이다.
     *
     * <p>부분 일치로 잡으면 "웹서버" 라는 자산이 "서버" 를 포함한다는 이유로
     * 제목이 되어 <b>그 줄이 조용히 사라진다.</b> 실제로 그렇게 만들었다가
     * 시험에서 잡혔다 — 30줄을 올렸는데 29대만 등록되고, 무엇이 빠졌는지는
     * 아무 데도 나오지 않는 종류의 버그다.
     */
    private static final Set<String> HEADER_FIRST_CELL = Set.of(
            "서버 이름", "서버이름", "서버명", "서버", "이름",
            "자산", "자산 이름", "자산명", "호스트명", "호스트 이름",
            "name", "hostname", "host", "server", "asset", "asset name");

    /**
     * 첫 줄이 제목 줄인가.
     *
     * <p>제목을 자산으로 등록하면 "이름" 이라는 서버가 생긴다. 반대로 제목이
     * 없는 파일의 첫 줄을 버리면 서버 하나가 조용히 빠진다. 둘 다 나쁘지만
     * <b>조용히 빠지는 쪽이 더 나쁘다</b> — 잘못 등록된 것은 목록에서 보이고
     * 지우면 되지만, 빠진 것은 없다는 사실 자체가 보이지 않는다.
     *
     * <p>그래서 아는 제목과 정확히 같을 때만 제목으로 본다. 모르는 제목
     * ("서버 이름(필수)" 같은 것)은 한 줄로 들어와 이름 규칙에 걸리고,
     * 줄 번호와 사유가 미리보기에 그대로 뜬다 — 보이는 실패다.
     */
    private boolean looksLikeHeader(List<String> cells) {
        String first = cell(cells, 0);
        return !first.isEmpty() && HEADER_FIRST_CELL.contains(first.toLowerCase(Locale.ROOT));
    }

    private String cell(List<String> cells, int index) {
        return index < cells.size() && cells.get(index) != null ? cells.get(index).trim() : "";
    }
}
