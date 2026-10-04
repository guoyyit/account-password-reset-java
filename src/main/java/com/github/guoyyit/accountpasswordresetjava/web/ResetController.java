package com.github.guoyyit.accountpasswordresetjava.web;

import com.github.guoyyit.accountpasswordresetjava.service.ResetService;
import com.github.guoyyit.accountpasswordresetjava.web.dto.ConfirmResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.MessageResponse;
import com.github.guoyyit.accountpasswordresetjava.web.dto.RequestResetRequest;
import com.github.guoyyit.accountpasswordresetjava.web.dto.VerifyResetRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reset")
public class ResetController {

    /** 统一文案：无论账户是否存在都返回相同响应，防止账户枚举 */
    static final String REQUEST_RESPONSE_MESSAGE =
            "if the account exists, a reset credential has been sent";

    private final ResetService resetService;

    public ResetController(ResetService resetService) {
        this.resetService = resetService;
    }

    @PostMapping("/request")
    public ResponseEntity<MessageResponse> request(@RequestBody RequestResetRequest request) {
        resetService.requestReset(request.username());
        return ResponseEntity.ok(new MessageResponse(REQUEST_RESPONSE_MESSAGE));
    }

    @PostMapping("/verify")
    public ResponseEntity<MessageResponse> verify(@RequestBody VerifyResetRequest request) {
        resetService.verify(request.username(), request.code());
        return ResponseEntity.ok(new MessageResponse("credential valid"));
    }

    @PostMapping("/confirm")
    public ResponseEntity<MessageResponse> confirm(@RequestBody ConfirmResetRequest request) {
        resetService.confirm(request.username(), request.code(), request.newPassword());
        return ResponseEntity.ok(new MessageResponse("password reset completed"));
    }
}
