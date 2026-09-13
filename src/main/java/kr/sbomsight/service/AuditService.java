package kr.sbomsight.service;

import kr.sbomsight.domain.AuditEvent;
import kr.sbomsight.domain.AuditLog;
import kr.sbomsight.repo.AuditLogRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 감사 로그 기록.
 *
 * <p><b>어느 트랜잭션에 기록하는가.</b> 기본은 {@link Propagation#REQUIRED} —
 * 돌고 있는 트랜잭션에 함께 올라탄다. 자산 삭제가 롤백되면 "자산을 지웠다"는
 * 기록도 함께 사라져야 한다. 별도 트랜잭션으로 빼 두면 일어나지 않은 일이
 * 기록에 남고, 그 기록을 근거로 점검에 답하면 틀린 말을 하게 된다.
 *
 * <p>반대로 <b>로그인 실패</b>는 업무 트랜잭션 밖에서 일어나므로 이 규칙에
 * 걸리지 않는다 — 알아서 새 트랜잭션이 열린다.
 *
 * <p><b>IP 는 소켓 주소만 본다.</b> {@code X-Forwarded-For} 는 누구든 채워
 * 보낼 수 있어서, 그것을 기록하면 "어디서 접속했는지" 를 접속한 사람이 정하게
 * 된다. 접근 통제({@link IpAllowlist})와 같은 기준이다.
 *
 * <p><b>비밀번호는 담지 않는다.</b> {@code detail} 에 무엇을 넣든 그것은
 * 평문으로 DB 에 남고 CSV 로 내려간다.
 */
@Service
public class AuditService {

    private final AuditLogRepository logs;

    public AuditService(AuditLogRepository logs) {
        this.logs = logs;
    }

    /** 지금 로그인한 계정의 행위. */
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(AuditEvent action, String target, String detail) {
        logs.save(new AuditLog(action, currentActor(), target, detail, clientIp()));
    }

    /** 사람을 직접 지정한다 — 로그인 실패처럼 아직 인증되지 않은 경우. */
    @Transactional(propagation = Propagation.REQUIRED)
    public void recordAs(String actor, AuditEvent action, String target, String detail) {
        logs.save(new AuditLog(action, actor, target, detail, clientIp()));
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return "";
        }
        return auth.getName();
    }

    /**
     * 소켓 주소. 요청 밖에서 불린 경우(기동 시 작업 등)는 빈 값이다 —
     * 그때 '알 수 없음' 같은 문자열을 넣으면 그것이 IP 처럼 보인다.
     */
    private String clientIp() {
        var attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            return servlet.getRequest().getRemoteAddr();
        }
        return "";
    }
}
