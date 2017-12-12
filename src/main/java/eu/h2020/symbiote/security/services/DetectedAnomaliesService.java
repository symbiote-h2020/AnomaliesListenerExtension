
package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.communication.payloads.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.repositories.BlockedActionsRepository;
import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import eu.h2020.symbiote.security.services.helpers.IAnomaliesHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide support for detected anomalies handling.
 *
 * @author Piotr Jakubowski (PSNC)
 */

@Service
public class DetectedAnomaliesService implements IAnomaliesHelper {
    private static Log log = LogFactory.getLog(DetectedAnomaliesService.class);

    private final BlockedActionsRepository blockedActionsRepository;

    @Value("${anomaly.verbosity.username}")
    private Boolean usernameEnabled;
    @Value("${anomaly.verbosity.clientIdentifier}")
    private Boolean clientIdentifierEnabled;
    @Value("${anomaly.verbosity.jti}")
    private Boolean jtiEnabled;
    @Value("${anomaly.verbosity.platformId}")
    private Boolean platformIdEnabled;
    @Value("${anomaly.verbosity.eventType}")
    private Boolean eventTypeEnabled;
    @Value("${anomaly.verbosity.timestamp}")
    private Boolean timestampEnabled;
    @Value("${anomaly.verbosity.tokenString}")
    private Boolean tokenStringEnabled;
    @Value("${anomaly.verbosity.reason}")
    private Boolean reasonEnabled;


    public AnomalyDetectionVerbosityLevel anomalyDetectionVerbosityLevel;

    @Autowired
    public DetectedAnomaliesService(BlockedActionsRepository blockedActionsRepository) {
        this.blockedActionsRepository = blockedActionsRepository;
        anomalyDetectionVerbosityLevel = new AnomalyDetectionVerbosityLevel(usernameEnabled, clientIdentifierEnabled,
                jtiEnabled, platformIdEnabled, eventTypeEnabled, timestampEnabled, tokenStringEnabled, reasonEnabled);
    }

    public Boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest) {

        long timeout = handleAnomalyRequest.getTimestamp() + handleAnomalyRequest.getDuration();
        String username = handleAnomalyRequest.getUsername();
        EventType eventType = handleAnomalyRequest.getEventType();
        BlockedAction blockedAction = blockedActionsRepository.findBlockedActionByUsernameAndEventType(username, eventType);
        if (blockedAction != null) {
            if (timeout > blockedAction.getTimeout())
                blockedActionsRepository.deleteBlockedActionByUsernameAndEventType(username, eventType);
            else
                return true;
        }
        return blockedActionsRepository.insert(new BlockedAction(username, eventType, timeout, handleAnomalyRequest.getDuration())) != null;
    }

    public Boolean isBlocked(String username, EventType eventType) {

        BlockedAction blockedAction = blockedActionsRepository.findBlockedActionByUsernameAndEventType(username, eventType);
        return blockedAction != null && blockedAction.getTimeout() > System.currentTimeMillis();
    }

    public AnomalyDetectionVerbosityLevel getVerbosityLevel() {
        return this.anomalyDetectionVerbosityLevel;
    }

    public EventLogRequest prepareEventLogRequest(EventLogRequest eventLogRequest) throws IllegalAccessException {

        if (!this.anomalyDetectionVerbosityLevel.getUsername())
            eventLogRequest.setUsername(null);
        if (!this.anomalyDetectionVerbosityLevel.getClientIdentifier())
            eventLogRequest.setClientIdentifier(null);
        if (!this.anomalyDetectionVerbosityLevel.getJti())
            eventLogRequest.setJti(null);
        if (!this.anomalyDetectionVerbosityLevel.getEventType())
            eventLogRequest.setEventType(null);
        if (!this.anomalyDetectionVerbosityLevel.getPlatformId())
            eventLogRequest.setPlatformId(null);
        if (!this.anomalyDetectionVerbosityLevel.getTimestamp())
            eventLogRequest.setTimestamp(0);
        if (!this.anomalyDetectionVerbosityLevel.getTokenString())
            eventLogRequest.setTokenString(null);
        if (!this.anomalyDetectionVerbosityLevel.getReason())
            eventLogRequest.setReason(null);

        return eventLogRequest;
    }

}