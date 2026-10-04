package com.github.guoyyit.accountpasswordresetjava.web;

import com.github.guoyyit.accountpasswordresetjava.model.AuditEventType;
import com.github.guoyyit.accountpasswordresetjava.model.Session;
import com.github.guoyyit.accountpasswordresetjava.service.AccountService;
import com.github.guoyyit.accountpasswordresetjava.service.AuditService;
import com.github.guoyyit.accountpasswordresetjava.service.SessionService;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.LoginResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MeResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RegisterRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AccountService accountService;
    private final SessionService sessionService;
    private final AuditService auditService;

    public AuthController(AccountService accountService,
                          SessionService sessionService,
                          AuditService auditService) {
        this.accountService = accountService;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@RequestBody RegisterRequest request) {
        accountService.register(request.username(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED).body(new MessageResponse("registered"));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        SessionService.IssuedSession session = accountService.login(request.username(), request.password());
        return ResponseEntity.ok(new LoginResponse(session.token(), session.expiresAt()));
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = requireBearerToken(authorization);
        Session session = sessionService.resolve(token)
                .orElseThrow(() -> ApiException.unauthorized("session is invalid or expired"));
        sessionService.revoke(token);
        auditService.record(AuditEventType.LOGOUT, session.getAccount().getId(),
                session.getAccount().getUsername(), "logout");
        return ResponseEntity.ok(new MessageResponse("logged out"));
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(@RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = requireBearerToken(authorization);
        Session session = sessionService.resolve(token)
                .orElseThrow(() -> ApiException.unauthorized("session is invalid or expired"));
        return ResponseEntity.ok(new MeResponse(session.getAccount().getUsername()));
    }

    private static String requireBearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw ApiException.unauthorized("missing bearer token");
        }
        String token = authorization.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            throw ApiException.unauthorized("missing bearer token");
        }
        return token;
    }
}
