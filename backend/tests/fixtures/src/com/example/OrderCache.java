package com.example;

import java.util.HashMap;
import java.util.Map;

/**
 * An *instance* field holding an unbounded map — the retention tracer should
 * climb from Order back to OrderCache.entries (not a static field).
 */
public class OrderCache {

    // Instance-field leak: grows without bound, never cleared.
    private final Map<Long, Order> entries = new HashMap<>();

    public void put(Order o) {
        entries.put(o.getId(), o);
    }

    public Order get(long id) {
        return entries.get(id);
    }
}
