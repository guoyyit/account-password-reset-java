package com.github.guoyyit.accountpasswordresetjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:contextload;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
