
package eu.h2020.symbiote.security.services;

import com.sun.org.apache.xpath.internal.operations.Bool;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.util.List;

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
        return blockedActionsRepository.insert(new BlockedAction(handleAnomalyRequest.getUsername(), handleAnomalyRequest.getEventType(), timeout, handleAnomalyRequest.getDuration())) != null;
    }

    public Boolean isBlocked(String username, EventType eventType) {
        List<BlockedAction> actionEntries = blockedActionsRepository.findByUsername(username);

        if (actionEntries.isEmpty())
            return false;

        for (BlockedAction blockedAction : actionEntries) {
            long currentTime = System.currentTimeMillis();
            long timeout = blockedAction.getTimeout();
            if (blockedAction.getEventType() == eventType && timeout >= currentTime)
                return true;
        }
        return false;

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