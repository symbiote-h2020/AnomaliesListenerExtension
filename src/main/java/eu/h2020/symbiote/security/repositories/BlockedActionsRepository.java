package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface BlockedActionsRepository extends MongoRepository<BlockedAction, String> {

    /**
     * Used to find repository entries for specific user.
     *
     * @param identifier identifier
     * @return true/false
     */
    List<BlockedAction> findByIdentifier(String identifier);

    /**
     * Used to delete repository entries for specific user.
     *
     * @param identifier identifier
     * @return number of removed entries
     */
    Long deleteBlockedActionByIdentifier(String identifier);

    /**
     * Used to delete repository entries for specific user and event type.
     *
     * @param identifier identifier
     * @return number of removed entries
     */
    Long deleteBlockedActionByIdentifierAndEventType(String identifier, EventType eventType);
    /**
     * Used to find repository entry for specific user and event type.
     *
     * @param identifier identifier
     * @return number of removed entries
     */
    BlockedAction findBlockedActionByIdentifierAndEventType(String identifier, EventType eventType);
}