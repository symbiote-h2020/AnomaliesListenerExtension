
package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
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

    @Value("${anomaly.verbosity.level}")
    private AnomalyDetectionVerbosityLevel anomalyDetectionVerbosityLevel;

    @Autowired
    public DetectedAnomaliesService(BlockedActionsRepository blockedActionsRepository) {
        this.blockedActionsRepository = blockedActionsRepository;
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

        switch (this.anomalyDetectionVerbosityLevel) {
            case FULL:
                break;
            case LIMITED:
                eventLogRequest.setTokenString(null);
                eventLogRequest.setReason(null);
                break;
            case DISABLED:
                return new EventLogRequest();
            default:
                break;
        }
        return eventLogRequest;
    }

}