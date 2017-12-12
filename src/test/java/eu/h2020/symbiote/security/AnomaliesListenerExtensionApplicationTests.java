package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.repositories.BlockedActionsRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public abstract class AnomaliesListenerExtensionApplicationTests {

    @Autowired
    protected BlockedActionsRepository blockedActionsRepository;
    protected String username = "username";
    protected String username2 = "username2";
    protected String clientId = "clientId";
    protected String jti = "jti";
    protected EventType eventType = EventType.VALIDATION_FAILED;
    protected long timestamp = 1234;
    protected long duration = 4;
    protected long duration2 = 10;
    protected long duration3 = 1;

    @Before
    public void setUp() throws Exception {
        blockedActionsRepository.deleteAll();
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}
