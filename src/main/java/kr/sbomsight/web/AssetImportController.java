package kr.sbomsight.web;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import kr.sbomsight.service.AssetImportService;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;

/**
 * 자산 일괄 등록 — CSV 한 장으로 서버 수십 대.
 *
 * <p>미리보기와 실행이 두 요청이라 그 사이에 파일을 들고 있어야 한다.
 * 세션에 둔다 — 다시 올리게 하면 "미리 본 것" 과 "넣은 것" 이 다른 파일일 수
 * 있고, 걸러진 줄 목록을 폼에 실어 보내면 그 값을 고쳐 보낼 수 있다.
 */
@Controller
@RequestMapping("/assets/import")
@PreAuthorize("hasRole('ADMIN')")
public class AssetImportController {

    /** 세션에 담아 둘 수 있는 크기. 자산 목록은 몇만 줄이어도 수백 KB 다. */
    private static final int MAX_BYTES = 2 * 1024 * 1024;

    private static final String SESSION_KEY = "assetImportCsv";

    private final AssetImportService imports;

    public AssetImportController(AssetImportService imports) {
        this.imports = imports;
    }

    @GetMapping
    public String form() {
        return "asset-import";
    }

    @PostMapping("preview")
    public String preview(@RequestParam("file") MultipartFile file,
                          HttpSession session, Model model, RedirectAttributes flash)
            throws IOException {
        if (file.isEmpty()) {
            flash.addFlashAttribute("error", "파일을 선택하세요.");
            return "redirect:/assets/import";
        }
        if (file.getSize() > MAX_BYTES) {
            flash.addFlashAttribute("error", "파일이 너무 큽니다 (최대 2MB).");
            return "redirect:/assets/import";
        }

        byte[] bytes = file.getBytes();
        session.setAttribute(SESSION_KEY, bytes);

        model.addAttribute("preview", imports.preview(bytes));
        model.addAttribute("filename", file.getOriginalFilename());
        return "asset-import";
    }

    @PostMapping("apply")
    public String apply(HttpSession session, Principal principal, RedirectAttributes flash) {
        byte[] bytes = (byte[]) session.getAttribute(SESSION_KEY);
        if (bytes == null) {
            // 세션이 끊겼거나 새로고침으로 두 번 눌렀다. 말없이 0건을
            // 등록하면 "왜 안 들어갔지" 가 된다.
            flash.addFlashAttribute("error", "올린 파일이 남아 있지 않습니다. 다시 올려 주세요.");
            return "redirect:/assets/import";
        }
        session.removeAttribute(SESSION_KEY);

        int created = imports.apply(bytes, principal.getName());
        flash.addFlashAttribute("message", created + "대를 등록했습니다.");
        return "redirect:/";
    }

    /** 서식 내려받기 — 무엇을 어떤 순서로 적어야 하는지 파일로 준다. */
    @GetMapping("template.csv")
    public void template(HttpServletResponse response) throws IOException {
        response.setContentType(MediaType.TEXT_PLAIN_VALUE + "; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"assets-template.csv\"");
        // BOM 을 붙여야 엑셀이 UTF-8 로 연다. 없으면 한글 제목이 깨진 채로 뜬다.
        response.getOutputStream().write(new byte[] { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF });
        response.getOutputStream().write("""
                서버 이름,구역,운영체제,비고
                web-01,DMZ,Rocky Linux 9.3,대외 웹
                api-02,DMZ,Rocky Linux 9.3,API 게이트웨이
                db-01,내부업무,Rocky Linux 8.9,원장 DB
                """.getBytes(StandardCharsets.UTF_8));
    }
}
