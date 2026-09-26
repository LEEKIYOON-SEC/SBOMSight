package kr.sbomsight;

import kr.sbomsight.repo.ComponentRepository;
import kr.sbomsight.repo.FindingAnalysisRepository;
import kr.sbomsight.repo.FindingRepository;
import kr.sbomsight.service.VulnQuery;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Query;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <b>쪽을 나눠 보는 목록은 정렬의 끝이 줄 하나를 가리킨다.</b>
 *
 * <p>앞의 축이 같은 줄 — 같은 CVE 가 여러 자산에, 같은 패키지 · 같은 버전이 두
 * 경로에 — 은 DB 가 아무 순서로 내도 된다. 쪽마다 따로 묻는 목록은 그 순서가
 * 요청마다 달라질 수 있고, 그러면 쪽 경계에서 줄이 빠지거나 두 번 나온다.
 * 심각도 순 목록은 이미 끝에 id 를 두었다(FindingRepository 의 BY_SEVERITY).
 * 나머지 정렬(CVSS · 악용 확률 · 패키지 · CVE)과 목록 둘이 빠져 있었다.
 *
 * <p>H2 는 같은 값의 줄을 넣은 순서대로 내 줘서 행동으로는 재현되지 않는다.
 * 그래서 정렬 자체를 본다.
 */
class ListOrderTest {

    @Test
    @DisplayName("취약점 목록의 정렬은 어느 축 · 어느 방향이든 끝이 id 다")
    void everyVulnSortEndsWithTheId() {
        for (String sort : List.of("severity", "cvss", "epss", "package", "cve")) {
            for (String dir : List.of("asc", "desc")) {
                List<Sort.Order> orders = VulnQuery.order(sort, dir).toList();
                assertThat(orders.get(orders.size() - 1).getProperty())
                        .as("%s %s 정렬의 끝", sort, dir)
                        .isEqualTo("id");
            }
        }
    }

    /**
     * 자산의 패키지 탭은 SQL 로 쪽을 나눈다 — 같은 패키지 · 같은 버전이 두 경로에
     * 깔리면(component 에는 유일 키가 없다) 두 줄의 순서가 정해지지 않는다.
     * 대응 화면의 검토 결과 목록은 요청마다 전부 읽어 쪽을 자른다 — 같은 자산의
     * 같은 CVE 가 패키지 둘에 걸리면 마찬가지다. 자산 이름은 유일하고
     * (uk_assets_name), 검토 결과는 (자산, CVE, 패키지) 에 하나다(ux_analysis_key).
     */
    @Test
    @DisplayName("자산의 패키지 탭 · 대응 화면의 검토 결과 목록도 정렬의 끝이 줄 하나를 가리킨다")
    void listQueriesEndOnAUniqueColumn() {
        assertThat(orderBy(ComponentRepository.class, "findByAsset"))
                .endsWith("c.name ASC, c.version ASC, c.id ASC");
        assertThat(orderBy(FindingAnalysisRepository.class, "findForList"))
                .endsWith("a.name ASC, f.cve ASC, f.packageName ASC");
        // CVE 상세도 요청마다 전부 읽어 쪽을 자른다.
        assertThat(orderBy(FindingRepository.class, "findByCveIn"))
                .endsWith("ax.name ASC, f.packageName ASC, f.id ASC");
    }

    private static String orderBy(Class<?> repository, String name) {
        Method method = Arrays.stream(repository.getMethods())
                .filter(m -> m.getName().equals(name)).findFirst().orElseThrow();
        String query = method.getAnnotation(Query.class).value();
        return query.substring(query.lastIndexOf("ORDER BY")).replaceAll("\\s+", " ").strip();
    }
}
