/**
 * 패치 플레이북 — core/playbooks.py 의 동형 구현.
 *
 * 패치 명령은 AI가 아니라 여기서 나온다. rules/playbooks/*.json 을 Python
 * 구현과 **같은 파일**로 읽으므로 두 환경의 권고 절차가 갈라지지 않는다.
 */

const PLAYBOOK_FOR = {
  rpm: 'rpm', rhel: 'rpm', redhat: 'rpm', centos: 'rpm', rocky: 'rpm',
  almalinux: 'rpm', amazonlinux: 'rpm', sles: 'rpm', opensuse: 'rpm',
  deb: 'deb', dpkg: 'deb', debian: 'deb', ubuntu: 'deb',
  npm: 'npm', javascript: 'npm', node: 'npm',
  python: 'pip', pypi: 'pip', 'python-pkg': 'pip', wheel: 'pip', egg: 'pip',
  'java-archive': 'maven', maven: 'maven', java: 'maven', jar: 'maven',
};

const NAMES = ['rpm', 'deb', 'npm', 'pip', 'maven', 'generic'];

export class PlaybookLibrary {
  constructor(books) {
    this.books = books;   // { rpm: {...}, deb: {...}, ... }
  }

  static async load(base = 'rules/playbooks') {
    const entries = await Promise.all(NAMES.map(async (name) => {
      const response = await fetch(`${base}/${name}.json`);
      if (!response.ok) throw new Error(`플레이북을 읽지 못했습니다: ${name} (${response.status})`);
      return [name, await response.json()];
    }));
    return new PlaybookLibrary(Object.fromEntries(entries));
  }

  forEcosystem(ecosystem) {
    const key = PLAYBOOK_FOR[String(ecosystem || '').trim().toLowerCase()] || 'generic';
    return this.books[key] || this.books.generic;
  }

  build({ ecosystem, packageName, installedVersion, fixedVersion, cve, osFamily = '' }) {
    const book = this.forEcosystem(ecosystem);
    const hasFix = Boolean(fixedVersion);

    const values = {
      package: packageName || '해당 패키지',
      installed_version: installedVersion || '(확인 필요)',
      fixed_version: fixedVersion || '(공개된 수정 버전 없음)',
      cve: cve || '',
      os_family: osFamily,
    };
    const fill = (template) => String(template ?? '').replace(
      /\{(package|installed_version|fixed_version|cve|os_family)\}/g,
      (_, key) => values[key],
    );
    const fillAll = (items) => (items || []).map(fill);

    const online = book.online || {};
    const airgapped = book.airgapped || {};

    return {
      ecosystem: book.ecosystem || 'generic',
      label: book.label || '일반',
      action: fill(hasFix ? book.recommended_action : book.recommended_action_no_fix),
      has_fix: hasFix,
      precheck: fillAll(book.precheck),
      online_title: online.title || '',
      online_steps: hasFix ? fillAll(online.steps) : [],
      airgapped_title: airgapped.title || '',
      airgapped_note: fill(airgapped.note || ''),
      airgapped_steps: hasFix ? fillAll(airgapped.steps) : [],
      verification: hasFix ? fillAll(book.verification) : [],
      // 수정 버전이 없을 때만 완화 방안을 전면에 낸다. 패치가 가능한데 완화책을
      // 나란히 놓으면 "패치 안 해도 된다"로 읽힐 수 있다.
      mitigations: hasFix ? [] : fillAll(book.mitigation_when_no_fix),
    };
  }
}
