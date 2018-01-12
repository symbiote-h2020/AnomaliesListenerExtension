package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.enums.EventType;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class BlockedAction {

    private final String identifier;
    private final EventType eventType;
    private final long timeout;
    private final long duration;


    public BlockedAction(String identifier, EventType eventType, long timeout, long duration) {
        this.identifier = identifier;
        this.eventType = eventType;
        this.timeout = timeout;
        this.duration = duration;
    }

    public String getIdentifier() {
        return identifier;
    }

    public long getTimeout() {
        return timeout;
    }

    public long getDuration() {
        return duration;
    }

    public EventType getEventType() {
        return eventType;
    }

}