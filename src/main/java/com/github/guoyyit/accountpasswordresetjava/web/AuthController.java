package com.github.guoyyit.accountpasswordresetjava.web;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.guoyyit.accountpasswordresetjava.account.AccountService;
import com.github.guoyyit.accountpasswordresetjava.account.PasswordAccount;
import com.github.guoyyit.accountpasswordresetjava.audit.AuditService;
import com.github.guoyyit.accountpasswordresetjava.reset.ResetService;
import com.github.guoyyit.accountpasswordresetjava.session.LoginSession;
import com.github.guoyyit.accountpasswordresetjava.session.SessionRepository;
import com.github.guoyyit.accountpasswordresetjava.session.SessionService;

@RestController
@RequestMapping("/api")
public class AuthController {

    public record RegisterRequest(String username, String password) {
    }

    public record RegisterResponse(Long accountId, String username) {
    }

    public record LoginRequest(String username, String password) {
    }

    public record LoginResponse(String sessionToken, String sessionId, Instant expiresAt) {
    }

    public record SessionResponse(Long accountId, String username, String sessionId) {
    }

    public record ResetRequestBody(String username) {
    }

    public record ResetVerifyBody(String token) {
    }

    public record ResetConfirmBody(String token, String newPassword) {
    }

    private final AccountService accountService;
    private final SessionService sessionService;
    private final ResetService resetService;
    private final SessionRepository sessionRepository;
    private final AuditService auditService;

    public AuthController(AccountService accountService,
                          SessionService sessionService,
                          ResetService resetService,
                          SessionRepository sessionRepository,
                          AuditService auditService) {
        this.accountService = accountService;
        this.sessionService = sessionService;
        this.resetService = resetService;
        this.sessionRepository = sessionRepository;
        this.auditService = auditService;
    }

    @PostMapping("/accounts/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request) {
        PasswordAccount account = accountService.register(request.username(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterResponse(account.getId(), account.getUsername()));
    }

    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        PasswordAccount account = accountService
                .authenticate(request.username(), request.password())
                .orElseThrow(() -> new UnauthorizedException("invalid_credentials"));
        SessionService.IssuedSession session = sessionService.issue(account);
        return ResponseEntity.ok(new LoginResponse(session.token(), session.sessionId(),
                session.expiresAt()));
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorization) {
        LoginSession session = requireSession(authorization, "logout");
        sessionService.revoke(session);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/auth/session")
    public ResponseEntity<SessionResponse> currentSession(@RequestHeader("Authorization") String authorization) {
        LoginSession session = requireSession(authorization, "current_session");
        PasswordAccount account = accountService.findById(session.getAccountId())
                .orElseThrow(() -> new UnauthorizedException("invalid_session"));
        return ResponseEntity.ok(new SessionResponse(account.getId(), account.getUsername(),
                session.getSessionPublicId()));
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> revokeSession(@RequestHeader("Authorization") String authorization,
                                              @PathVariable String sessionId) {
        LoginSession caller = requireSession(authorization, "revoke_session");
        LoginSession target = sessionRepository.findBySessionPublicId(sessionId)
                .orElseThrow(() -> new AccessDeniedException("forbidden"));
        if (!target.getAccountId().equals(caller.getAccountId())) {
            auditService.record("ACCESS_DENIED", caller.getAccountId(),
                    "action=revoke_session targetSessionId=" + sessionId);
            throw new AccessDeniedException("forbidden");
        }
        sessionService.revoke(target);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password-reset/request")
    public ResponseEntity<Void> requestReset(@RequestBody ResetRequestBody request) {
        resetService.requestReset(request.username());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/password-reset/verify")
    public ResponseEntity<Void> verifyReset(@RequestBody ResetVerifyBody request) {
        resetService.verify(request.token());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<Void> confirmReset(@RequestBody ResetConfirmBody request) {
        resetService.confirmReset(request.token(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    private LoginSession requireSession(String authorization, String action) {
        String token = null;
        if (authorization != null && authorization.startsWith("Bearer ")) {
            token = authorization.substring("Bearer ".length()).trim();
        }
        return sessionService.authenticate(token)
                .orElseThrow(() -> {
                    auditService.record("UNAUTHORIZED_ACCESS", null, "action=" + action);
                    return new UnauthorizedException("invalid_session");
                });
    }
}
