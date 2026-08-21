/**
 * Google AI Studio (Gemini) 브라우저 클라이언트 — 데모 전용.
 *
 * GitHub Pages에는 서버가 없으므로 방문자가 **자기 API 키**로 직접 호출한다.
 * 우리 키는 배포물에 포함되지 않는다. 방문자의 키는 sessionStorage에만 남고
 * (탭을 닫으면 사라진다) 우리 쪽 어디로도 전송되지 않는다.
 *
 * 전송 직전 이그레스 가드를 다시 통과시킨다. 서버가 없는 이 경로에서는
 * 브라우저 가드가 유일한 방어이므로, 여기를 통과하지 못하면 네트워크 호출이
 * 일어나지 않는다.
 */

import { RESPONSE_SCHEMA, SYSTEM_INSTRUCTION, buildPrompt } from './prompt.js';

const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models';
const KEY_STORAGE = 'sbomsight.demo.aikey';

// AI 응답에서 절대 받아들이지 않는 키. 모델이 넣어도 무시한다.
const IGNORED_KEYS = [
  'priority', 'priority_reasons', 'priority_label', 'severity_rating',
  'risk_level', 'verdict', 'is_vulnerable', 'update_available',
];

export const apiKey = {
  get() {
    try { return sessionStorage.getItem(KEY_STORAGE) || ''; } catch { return ''; }
  },
  set(value) {
    try {
      if (value) sessionStorage.setItem(KEY_STORAGE, value);
      else sessionStorage.removeItem(KEY_STORAGE);
    } catch { /* 저장 실패해도 이번 세션에서는 인자로 넘겨 쓸 수 있다 */ }
  },
  clear() { this.set(''); },
};

function extractJson(text) {
  const candidates = [text, String(text || '').replace(/^```(?:json)?\s*|\s*```$/gm, '').trim()];
  for (const candidate of candidates) {
    try { return JSON.parse(candidate); } catch { /* 다음 후보 */ }
  }
  const match = /\{[\s\S]*\}/.exec(text || '');
  if (match) {
    try { return JSON.parse(match[0]); } catch { /* 실패 */ }
  }
  throw new Error('모델 응답에서 JSON을 읽지 못했습니다.');
}

/**
 * VulnFact 목록에 대한 서술을 받아온다.
 *
 * guard: EgressGuard — 전송 직전 마지막 관문. 통과하지 못하면 호출하지 않는다.
 */
export async function analyze(facts, {
  key = apiKey.get(),
  model = 'gemini-3.6-flash',
  fallbackModel = 'gemini-3.5-flash-lite',
  guard = null,
  signal = null,
} = {}) {
  if (!key) throw new Error('API 키가 없습니다.');

  // --- 마지막 관문 ---------------------------------------------------------
  if (guard) guard.enforce(facts);

  const body = {
    systemInstruction: { parts: [{ text: SYSTEM_INSTRUCTION }] },
    contents: [{ role: 'user', parts: [{ text: buildPrompt(facts) }] }],
    generationConfig: {
      temperature: 0.2,
      topP: 0.9,
      responseMimeType: 'application/json',
      responseSchema: RESPONSE_SCHEMA,
    },
  };

  let lastError = null;
  for (const candidate of [model, fallbackModel].filter(Boolean)) {
    try {
      const response = await fetch(`${ENDPOINT}/${candidate}:generateContent`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-goog-api-key': key },
        body: JSON.stringify(body),
        signal,
      });

      if (!response.ok) {
        const detail = await response.text();
        if (response.status === 400 && /API key/i.test(detail)) {
          throw new Error('API 키가 올바르지 않습니다.');
        }
        lastError = new Error(`${candidate}: ${response.status} ${detail.slice(0, 200)}`);
        continue;   // 다음 모델로
      }

      const payload = await response.json();
      const text = payload?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('') || '';
      const parsed = extractJson(text);
      if (!Array.isArray(parsed.analyses)) throw new Error('응답에 analyses 배열이 없습니다.');
      return { analyses: parsed.analyses, model: candidate };
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      lastError = error;
    }
  }
  throw lastError || new Error('모델 호출에 실패했습니다.');
}

/**
 * 모델 응답을 Narrative 형태로 옮긴다.
 *
 * 우선순위성 필드는 여기서 버려진다 — 등급은 로컬 룰 엔진의 산출물이며
 * 모델이 바꿀 수 없다.
 */
export function toNarrative(analysis) {
  const copy = { ...analysis };
  for (const key of IGNORED_KEYS) delete copy[key];
  return {
    technical_risk: String(copy.technical_risk || ''),
    attack_preconditions: (copy.attack_preconditions || []).map(String),
    impact_types: (copy.impact_types || []).map(String),
    exploitability_note: String(copy.exploitability_note || ''),
    response_rationale: String(copy.response_rationale || ''),
    recommendation_note: String(copy.recommendation_note || ''),
    source: 'ai',
  };
}

export function narrativeTexts(narrative) {
  return {
    technical_risk: narrative.technical_risk,
    exploitability_note: narrative.exploitability_note,
    response_rationale: narrative.response_rationale,
    recommendation_note: narrative.recommendation_note,
  };
}
