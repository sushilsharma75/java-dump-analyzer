package com.example;

import java.util.HashMap;
import java.util.Map;

/**
 * An *instance* field holding an unbounded map. The retention tracer climbs from
 * Order, through the HashMap's internal Node[] table, back to this field.
 */
public class OrderCache {

    private final Map<Long, Order> entries = new HashMap<>();   // leak anchor: unbounded

    public void put(Order o) {
        entries.put(o.getId(), o);
    }

    public Order get(long id) {
        return entries.get(id);
    }
}
