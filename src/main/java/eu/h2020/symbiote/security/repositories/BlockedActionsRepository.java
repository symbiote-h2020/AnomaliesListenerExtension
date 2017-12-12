package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface BlockedActionsRepository extends MongoRepository<BlockedAction, String> {

    /**
     * Used to find repository entries for specific user.
     *
     * @param username user
     * @return true/false
     */
    List<BlockedAction> findByUsername(String username);

    /**
     * Used to delete repository entries for specific user.
     *
     * @param username user
     * @return number of removed entries
     */
    Long deleteBlockedActionByUsername(String username);

    /**
     * Used to delete repository entries for specific user and event type.
     *
     * @param username user
     * @return number of removed entries
     */
    Long deleteBlockedActionByUsernameAndEventType(String username, EventType eventType);
    /**
     * Used to find repository entry for specific user and event type.
     *
     * @param username user
     * @return number of removed entries
     */
    BlockedAction findBlockedActionByUsernameAndEventType(String username, EventType eventType);
}