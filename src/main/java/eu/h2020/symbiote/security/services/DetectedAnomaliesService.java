
package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.handler.IAnomalyListenerSecurity;
import eu.h2020.symbiote.security.repositories.BlockedActionsRepository;
import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Spring service used to provide support for detected anomalies handling.
 *
 * @author Piotr Jakubowski (PSNC)
 */

@Service
public class DetectedAnomaliesService implements IAnomalyListenerSecurity {

    private final BlockedActionsRepository blockedActionsRepository;

    @Value("${anomaly.verbosity.level}")
    private AnomalyDetectionVerbosityLevel anomalyDetectionVerbosityLevel;

    @Autowired
    public DetectedAnomaliesService(BlockedActionsRepository blockedActionsRepository) {
        this.blockedActionsRepository = blockedActionsRepository;
    }

    public boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest) {

        long timeout = handleAnomalyRequest.getTimestamp() + handleAnomalyRequest.getDuration();
        String anomalyIdentifier = handleAnomalyRequest.getAnomalyIdentifier();
        EventType eventType = handleAnomalyRequest.getEventType();
        BlockedAction blockedAction = blockedActionsRepository.findBlockedActionByIdentifierAndEventType(anomalyIdentifier, eventType);
        if (blockedAction != null) {
            if (timeout > blockedAction.getTimeout())
                blockedActionsRepository.deleteBlockedActionByIdentifierAndEventType(anomalyIdentifier, eventType);
            else
                return true;
        }
        return blockedActionsRepository.insert(new BlockedAction(anomalyIdentifier, eventType, timeout, handleAnomalyRequest.getDuration())) != null;
    }

    public boolean isBlocked(Optional<String> username, Optional<String> clientId, Optional<String> jti, Optional<String> componentId, Optional<String> platformId, EventType eventType) {

        String identifier = "";
        switch (eventType) {
            case VALIDATION_FAILED:
                if (!jti.isPresent()) {
                    throw new IllegalArgumentException();
                }
                identifier = jti.get();
                break;
            case LOGIN_FAILED:
                if (!username.isPresent()) {
                    throw new IllegalArgumentException();
                }
                identifier = username.get();
                break;
            case ACQUISITION_FAILED:
                if (username.isPresent() &&
                        clientId.isPresent()) {
                    identifier = username.get() + illegalSign + clientId.get();
                    break;
                }
                if (componentId.isPresent() &&
                        platformId.isPresent()) {
                    identifier = platformId.get() + illegalSign + componentId.get();
                    break;
                }
                throw new IllegalArgumentException();
            case NULL:
                throw new IllegalArgumentException();
        }
        BlockedAction blockedAction = blockedActionsRepository.findBlockedActionByIdentifierAndEventType(identifier, eventType);
        return blockedAction != null && blockedAction.getTimeout() > System.currentTimeMillis();
    }

    public AnomalyDetectionVerbosityLevel getVerbosityLevel() {
        return this.anomalyDetectionVerbosityLevel;
    }

    public EventLogRequest prepareEventLogRequest(EventLogRequest eventLogRequest) {

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

    public boolean clearBlockedActions() {
        try {
            blockedActionsRepository.deleteAll();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}