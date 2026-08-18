package com.example;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A classic unbounded static cache. SESSIONS is only ever put into and never
 * evicted, so it grows for the life of the JVM.
 */
public class SessionRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(SessionRegistry.class);

    public static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();

    public static void register(String id, Session s) {
        SESSIONS.put(id, s);
        LOG.debug("registered {}", id);
    }
}
