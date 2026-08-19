/**
 * AI 프롬프트 조립 — core/prompt.py 의 동형 구현.
 *
 * 프롬프트에 담기는 것은 VulnFact 목록뿐이다. 자산 정보도, 우리 판정도
 * 들어가지 않는다. 그래서 이 문자열 전체를 화면에 그대로 보여 줄 수 있다 —
 * "AI에게 전송될 내용 전체 보기"가 가능한 이유다.
 *
 * 이 파일의 문자열은 core/prompt.py 와 한 글자도 달라서는 안 된다.
 * 파리티 테스트(tests/js/parity.test.mjs)가 두 벌을 대조한다.
 */

export const SYSTEM_INSTRUCTION = "당신은 공개된 취약점 데이터를 근거로 보안 담당자가 읽을 설명을 작성합니다.\n\n[당신이 받는 것]\n공개 취약점 데이터만 받습니다: CVE ID, CVSS 점수와 벡터, CWE, EPSS,\nCISA KEV 등재 여부, 공개 exploit 존재 여부와 출처, 공개 advisory가 지목한\n패키지명과 영향 버전범위, 수정 버전, OS 계열.\n\n[당신이 받지 못하는 것]\n요청자의 자산 정보는 일절 포함되어 있지 않습니다. 어떤 서버에 무엇이 설치되어\n있는지, 실제 설치 버전이 무엇인지, 몇 대나 영향을 받는지, 내부적으로 어떤\n대응 우선순위가 매겨졌는지 알 수 없습니다.\n\n[따라서 지켜야 할 것]\n1. 요청자의 조직이나 자산을 지칭하지 마십시오. \"귀사\", \"우리 조직\", \"해당 서버\",\n   \"사내\" 같은 표현을 쓰지 마십시오.\n2. 특정 환경의 위험도를 단정하지 마십시오. \"매우 위험합니다\", \"치명적입니다\"가\n   아니라 \"공개 데이터를 기준으로 ~한 특성이 관측됩니다\"라고 쓰십시오.\n3. 최종 조치 여부를 명령하지 마십시오. \"반드시 패치해야 합니다\"가 아니라\n   \"우선적인 대응을 검토할 필요가 있습니다\", \"높은 우선순위로 조치하는 것을\n   권고합니다\"라고 쓰십시오.\n4. 대응 우선순위 등급(P0~P3)을 말하지 마십시오. 등급은 요청자 측 정책 룰이\n   결정하며 당신은 그 결과를 알지 못합니다.\n5. 패치 명령어(dnf, apt, npm, pip 등)를 작성하지 마십시오. 실행 절차는 요청자\n   측에서 결정론적으로 생성합니다.\n6. 주어진 데이터에 없는 사실을 지어내지 마십시오. 모르는 것은 \"공개된 정보만으로는\n   확인되지 않습니다\"라고 쓰십시오. 특히 CVSS 벡터나 CWE가 비어 있으면 그것을\n   근거로 한 서술을 하지 마십시오.\n\n[작성 언어]\n한국어. 보안 담당자가 결재 문서에 그대로 옮길 수 있는 문어체로 씁니다.\n";

export const NARRATIVE_FIELDS = [
  'technical_risk',
  'exploitability_note',
  'response_rationale',
  'recommendation_note',
];

/**
 * Python의 json.dumps 와 같은 숫자 표기로 직렬화한다.
 *
 * JavaScript는 정수와 실수를 구분하지 않아 10.0 을 "10" 으로 쓴다. 값의 의미는
 * 같지만 "AI에게 전송될 내용 전체 보기"가 실 운영과 데모에서 다르게 보이면
 * 그 화면의 신뢰도가 떨어진다. 실수 필드는 소수점을 유지한다.
 */
const FLOAT_FIELDS = new Set(['cvss_score', 'epss', 'epss_percentile']);
// JSON.stringify 가 이스케이프하지 않는 표식이어야 한다. 제어문자는
// \u0000 형태로 escape되어 정규식이 잡지 못한다.
const FLOAT_MARK = '__SBOMSIGHT_FLOAT__';

export function stringifyPayload(value, indent = 2) {
  const marked = JSON.stringify(value, function replacer(key, val) {
    if (FLOAT_FIELDS.has(key) && typeof val === 'number') {
      return FLOAT_MARK + (Number.isInteger(val) ? `${val}.0` : String(val));
    }
    return val;
  }, indent);
  // 표식이 붙은 문자열의 따옴표를 벗겨 다시 숫자로 만든다.
  return marked.replaceAll(new RegExp(`"${FLOAT_MARK}([0-9.eE+-]*)"`, 'g'), '$1');
}

/** VulnFact 목록으로 사용자 프롬프트를 만든다. facts 외의 어떤 것도 들어가지 않는다. */
export function buildPrompt(facts) {
  const payload = stringifyPayload({ vulnerabilities: facts }, 2);
  return `아래는 공개 취약점 데이터입니다. 각 항목에 대해 지정된 스키마로 분석을 작성하십시오.

값이 "unknown"이거나 null인 항목은 **확인되지 않은 것**이지 "없음"이 아닙니다.
예를 들어 exploit_available이 "unknown"이면 "공개 exploit이 없다"가 아니라
"공개 exploit 존재 여부가 확인되지 않았다"입니다. 이 구분을 서술에 반영하십시오.

affected_version_range와 fixed_version은 공개 advisory가 공표한 값이며,
요청자의 실제 설치 버전이 아닙니다.

${payload}

각 CVE에 대해 하나의 분석 객체를 만들고, cve 필드에 위 데이터의 cve 값을
그대로 넣으십시오.
`;
}

/** 화면의 "AI에게 전송될 내용 전체 보기"에 그대로 실리는 문자열. */
export function buildFullText(facts) {
  return `=== 시스템 지시 ===\n${SYSTEM_INSTRUCTION}\n\n=== 요청 ===\n${buildPrompt(facts)}`;
}
