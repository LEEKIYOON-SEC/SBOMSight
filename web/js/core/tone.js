/**
 * AI 서술 표현 가드 (브라우저 구현) — core/tone.py 의 동형.
 *
 * rules/tone-policy.json 을 Python 구현과 **같은 파일**로 읽는다.
 *
 * AI는 우리 환경의 정보를 받지 않으므로 "우리 조직에서 이 취약점의 위험도가
 * 높다"고 판단할 수 없다. 그런데 생성 모델은 관성적으로 단정형 문장을 쓴다.
 * 프롬프트 제약만으로는 부족하므로 생성 후 여기서 다시 점검한다.
 */

let cached = null;

export async function loadTonePolicy(url = 'rules/tone-policy.json') {
  if (cached) return cached;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`표현 정책을 읽지 못했습니다 (${response.status})`);
  cached = await response.json();
  return cached;
}

export class ToneGuard {
  constructor(policy) {
    this.policy = policy;
    this.rules = (policy.forbidden || []).map((spec) => ({
      name: spec.name,
      re: new RegExp(spec.pattern, spec.flags || ''),
      reason: spec.reason || '',
    }));
  }

  static async load(url) {
    return new ToneGuard(await loadTonePolicy(url));
  }

  /** 필드명 → 서술 매핑을 검사한다. */
  inspect(texts) {
    const violations = [];
    for (const [field, text] of Object.entries(texts)) {
      if (!text) continue;
      for (const { name, re, reason } of this.rules) {
        const match = re.exec(text);
        if (match) {
          violations.push({ rule: name, field, reason, sample: match[0].trim().slice(0, 60) });
        }
      }
    }
    return violations;
  }

  get preferred() {
    return this.policy.preferred_phrasing || [];
  }
}
