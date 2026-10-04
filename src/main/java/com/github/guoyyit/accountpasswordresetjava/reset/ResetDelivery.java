package com.github.guoyyit.accountpasswordresetjava.reset;

public interface ResetDelivery {

    void deliver(String username, String rawToken);
}
