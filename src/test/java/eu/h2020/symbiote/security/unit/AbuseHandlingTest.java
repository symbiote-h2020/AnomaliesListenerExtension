package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AnomaliesListenerExtensionApplicationTests;
import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import eu.h2020.symbiote.security.services.DetectedAnomaliesService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Objects;
import java.util.Optional;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AbuseHandlingTest extends AnomaliesListenerExtensionApplicationTests {


    protected String serverAddress;
    protected HandleAnomalyRequest handleAnomalyRequest;
    @LocalServerPort
    private int port;

    @Autowired
    public DetectedAnomaliesService detectedAnomaliesService;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        serverAddress = "http://localhost:" + port;
        timestamp = System.currentTimeMillis();
        handleAnomalyRequest = new HandleAnomalyRequest(jti, eventType, timestamp, duration);
    }

    @Test
    public void recordInsertingTest() {
        assert blockedActionsRepository.findByIdentifier(jti).size() == 0;

        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);

        assert blockedActionsRepository.findByIdentifier(jti).size() == 1;
        assert blockedActionsRepository.findBlockedActionByIdentifierAndEventType(jti, EventType.VALIDATION_FAILED) != null;

        BlockedAction blockedAction = blockedActionsRepository.findByIdentifier(jti).get(0);

        assert Objects.equals(blockedAction.getIdentifier(), jti);
        assert blockedAction.getEventType() == eventType;
        assert blockedAction.getDuration() == duration;
        assert blockedAction.getTimeout() == timestamp + duration;

        handleAnomalyRequest.setDuration(duration2);
        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);

        assert blockedActionsRepository.findByIdentifier(jti).size() == 1;
        blockedAction = blockedActionsRepository.findByIdentifier(jti).get(0);

        assert blockedAction.getTimeout() == timestamp + duration2;

        handleAnomalyRequest.setDuration(duration3);
        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);
        assert blockedActionsRepository.findByIdentifier(jti).size() == 1;

        blockedAction = blockedActionsRepository.findByIdentifier(jti).get(0);

        assert blockedAction.getTimeout() == timestamp + duration2;

        handleAnomalyRequest.setEventType(EventType.LOGIN_FAILED);

        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);

        assert blockedActionsRepository.findByIdentifier(jti).size() == 2;

    }

    @Test
    public void blockCheckingTest() {

        assert blockedActionsRepository.findByIdentifier(jti).size() == 0;
        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);
        assert blockedActionsRepository.findByIdentifier(jti).size() == 1;

        assert !detectedAnomaliesService.isBlocked(Optional.empty(), Optional.empty(), Optional.of(jti), Optional.empty(), Optional.empty(), EventType.VALIDATION_FAILED);

        handleAnomalyRequest.setDuration(1000000);
        detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest);

        assert detectedAnomaliesService.isBlocked(Optional.of(username), Optional.of(clientId), Optional.of(jti), Optional.empty(), Optional.empty(), EventType.VALIDATION_FAILED);
        assert !detectedAnomaliesService.isBlocked(Optional.of(username), Optional.of(clientId), Optional.of(jti), Optional.empty(), Optional.empty(), EventType.LOGIN_FAILED);
        assert detectedAnomaliesService.getVerbosityLevel() == AnomalyDetectionVerbosityLevel.FULL;

    }

}
