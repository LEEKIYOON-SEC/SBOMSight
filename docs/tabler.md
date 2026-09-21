# Tabler 1.5.1 — 여기 있는 것과 없는 것

> 이 문서는 `static/vendor/tabler/` 에 있었다. 그 아래는 **로그인 없이 밖에서
> 열리는 자리**라, 개발용 문서가 `/vendor/tabler/README.md` 로 그대로
> 내려받아졌다. 문서는 `docs/` 에 둔다 — 그 자리에 남는 것은 CSS 와
> 라이선스뿐이고, 라이선스는 MIT 가 배포물과 함께 가기를 요구한다.

화면의 바탕이 되는 CSS 다. 폐쇄망이라 CDN 을 부르지 않고 **파일을 저장소에
담는다.**

| 파일 | 무엇 |
|---|---|
| `tabler.min.css` | Tabler 1.5.1 의 배포본 CSS (694KB) |
| `LICENSE` | MIT — 원문 그대로 |

## 가져오지 않은 것

**`dist/libs/` 는 통째로 뺐다.** Tabler 가 함께 배포하는 제3자 라이브러리
모음인데, 그 안의 **ApexCharts 는 5판부터 MIT 가 아니다**(이중 라이선스 ·
재배포는 별도 OEM 라이선스). 우리는 차트를 쓰지 않으므로 반입할 이유가 없다 —
안 가져오면 따져 볼 일도 없다.

**JS 도 가져오지 않았다.** 메뉴는 `<details>`, 팝업은 `<dialog>` 로 되어 있어
자바스크립트 없이 열리고 `Esc` 가 듣는다. 프레임워크의 JS 를 들이면 그것 없이는
안 열리는 화면이 생긴다.

그래서 여기 있는 것은 **CSS 한 장과 라이선스 한 장**이다.

## 판을 올릴 때

```bash
curl -O https://registry.npmjs.org/@tabler/core/-/core-<판>.tgz
tar xzf core-<판>.tgz
cp package/dist/css/tabler.min.css src/main/resources/static/vendor/tabler/
```

올린 뒤에는 **띄워서 화면을 한 바퀴 본다.** Tabler 는 판이 올라가며 변수
이름과 기본값이 바뀐다 — `css/app.css` 가 `--tblr-*` 를 덮어쓰고 있으므로
그 이름이 바뀌면 조용히 안 먹는다.

```bash
python3 tests/check-uniform.py     # 단추·입력칸이 한 모양인가
python3 tests/check-contrast.py    # 글자 대비
python3 tests/check-table-width.py 1280
```
