package com.example;

import java.util.ArrayList;
import java.util.List;

/**
 * loadAll() constructs an Order per row with no pagination — the allocator that
 * the thread×heap correlation should bridge to from a heap dominated by Order.
 */
public class OrderService {

    private final OrderRepository repo;

    public OrderService(OrderRepository repo) {
        this.repo = repo;
    }

    public List<Order> loadAll() {
        List<Order> all = new ArrayList<>();
        for (Row r : repo.scanEntireTable()) {
            all.add(new Order(r.id(), r.customer()));
        }
        return all;
    }
}
