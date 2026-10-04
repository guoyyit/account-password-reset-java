package com.github.guoyyit.accountpasswordresetjava.delivery;

import java.util.List;

public interface LocalDeliveryService {

    void deliver(String recipient, String message);

    List<String> outboxFor(String recipient);
}
