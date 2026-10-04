package kr.sbomsight.service;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.Entity;
import kr.sbomsight.domain.*;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 발행본의 <b>계산 결과</b>(JSON) — 그때의 보고서 계산을 그대로 적는다(D6).
 *
 * <p>보고서의 모양(record)은 그대로 쓰되, 그 안에 든 엔티티(자산 · 구역 · 검사 · 조치 ·
 * 검토 결과)는 <b>정해 둔 칸만</b> 적는다. 엔티티를 통째로 적으면 연관을 따라 DB 를 끝없이
 * 읽거나(지연 로딩) 같은 것을 되풀이해 적는다.
 *
 * <p><b>칸을 정하지 않은 엔티티가 끼면 멈춘다.</b> 보고서에 새 엔티티를 넣고 여기를
 * 잊으면, 조용히 연관을 따라가는 대신 발행이 실패한다 — 시험(PublicationTest)이 잡는다.
 *
 * <p>해시는 이것이 아니라 그린 문서(HTML)에 건다 — 같은 계산이라도 칸 순서가 달라질 수 있다.
 */
final class PublicationJson {

    private static final ObjectMapper JSON = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .addModule(entities())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
            // `isNew()` 같은 판정 메서드를 칸으로 적지 않는다 — 보고서가 센 값만.
            .disable(MapperFeature.AUTO_DETECT_IS_GETTERS)
            .build();

    private PublicationJson() {
    }

    /**
     * @param basis 발행본이 가리키는 검사 번호
     * @param report 계산한 보고서 — {@link ReportService.Report} 또는
     *               {@link ZoneReportService.ZoneReport}
     */
    static String write(PublicationKind kind, PublicationService.Head head, List<Long> basis,
                        Object report) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("kind", kind.name());
        doc.put("number", head.number());
        doc.put("publishedAt", head.publishedAt());
        doc.put("publishedBy", head.publisher());
        doc.put("basisScans", basis);
        doc.put("report", report);
        try {
            return JSON.writeValueAsString(doc);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("발행본의 계산 결과를 적지 못했습니다: " + e.getOriginalMessage(), e);
        }
    }

    // --- 엔티티는 정해 둔 칸만 ------------------------------------------------

    private static SimpleModule entities() {
        SimpleModule module = new SimpleModule("publication-entities");
        module.addSerializer(Zone.class, new Fields<>((z, out) -> {
            out.put("id", z.getId());
            out.put("name", z.getName());
        }));
        module.addSerializer(Asset.class, new Fields<>((a, out) -> {
            out.put("id", a.getId());
            out.put("name", a.getName());
            out.put("zoneId", a.getZone().getId());
            out.put("zoneName", a.getZone().getName());
            out.put("osName", a.getOsName());
            out.put("archivedAt", a.getArchivedAt());
        }));
        module.addSerializer(Scan.class, new Fields<>((s, out) -> {
            out.put("id", s.getId());
            out.put("assetId", s.getAsset().getId());
            out.put("status", s.getStatus());
            out.put("createdAt", s.getCreatedAt());
            out.put("sbomCreatedAt", s.getSbomCreatedAt());
            out.put("sbomTime", s.getSbomTime());
            out.put("sbomFilename", s.getSbomFilename());
            out.put("sbomSha256", s.getSbomSha256());
            out.put("sbomTool", s.getSbomTool());
            out.put("sbomTarget", s.getSbomTarget());
            out.put("grypeVersion", s.getGrypeVersion());
            out.put("grypeDbBuilt", s.getGrypeDbBuilt());
            out.put("componentCount", s.getComponentCount());
            out.put("matchCount", s.getMatchCount());
            out.put("findingCount", s.getFindingCount());
            out.put("mergedCount", s.getMergedCount());
            out.put("droppedCount", s.getDroppedCount());
            out.put("rescanOf", s.getRescanOf());
        }));
        module.addSerializer(Remediation.class, new Fields<>((r, out) -> {
            out.put("id", r.getId());
            out.put("assetId", r.getAsset().getId());
            out.put("packageName", r.getPackageName());
            out.put("roundNo", r.getRoundNo());
            out.put("previousId", r.getPreviousId());
            out.put("status", r.getStatus());
            out.put("owner", r.getOwner());
            out.put("dueDate", r.getDueDate());
            out.put("openedScanId", r.getOpenedScanId());
            out.put("openedCount", r.getOpenedCount());
            out.put("closedAt", r.getClosedAt());
        }));
        module.addSerializer(FindingAnalysis.class, new Fields<>((a, out) -> {
            out.put("id", a.getId());
            out.put("assetId", a.getAsset().getId());
            out.put("cve", a.getCve());
            out.put("packageName", a.getPackageName());
            out.put("state", a.getState());
            out.put("justification", a.getJustification());
            out.put("response", a.getResponse());
            out.put("reviewBy", a.getReviewBy());
            out.put("approvalDoc", a.getApprovalDoc());
        }));
        module.setSerializerModifier(new BeanSerializerModifier() {
            @Override
            public JsonSerializer<?> modifySerializer(SerializationConfig config, BeanDescription bean,
                                                      JsonSerializer<?> serializer) {
                // 위에서 칸을 정한 것도 여기를 지난다 — 그것은 그대로 둔다.
                if (serializer instanceof Fields) {
                    return serializer;
                }
                Class<?> type = bean.getBeanClass();
                for (Class<?> c = type; c != null; c = c.getSuperclass()) {
                    if (c.isAnnotationPresent(Entity.class)) {
                        return new Refuse(type);
                    }
                }
                return serializer;
            }
        });
        return module;
    }

    /** 엔티티 하나를 정해 둔 칸만으로 — 칸은 순서대로 담는다. */
    private static final class Fields<T> extends JsonSerializer<T> {

        interface Pick<T> {
            void into(T value, Map<String, Object> out);
        }

        private final Pick<T> pick;

        Fields(Pick<T> pick) {
            this.pick = pick;
        }

        @Override
        public void serialize(T value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            Map<String, Object> out = new LinkedHashMap<>();
            pick.into(value, out);
            provider.defaultSerializeValue(out, gen);
        }
    }

    /** 칸을 정하지 않은 엔티티 — 적지 않고 멈춘다. */
    private static final class Refuse extends JsonSerializer<Object> {

        private final Class<?> type;

        Refuse(Class<?> type) {
            this.type = type;
        }

        @Override
        public void serialize(Object value, JsonGenerator gen, SerializerProvider provider) {
            throw new IllegalStateException("발행본의 계산 결과에 칸을 정하지 않은 엔티티가 있습니다: "
                                            + type.getName() + " (PublicationJson)");
        }
    }
}
