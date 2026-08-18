package com.example;

import java.util.ArrayList;
import java.util.List;

/**
 * loadAll() constructs an Order per row with no pagination. Under load, many
 * worker threads sit in this method allocating Orders — which is exactly what
 * the thread x heap correlation bridges to from a heap dominated by Order.
 */
public class OrderService {

    private final OrderRepository repo;

    public OrderService(OrderRepository repo) {
        this.repo = repo;
    }

    public List<Order> loadAll() {
        List<Order> all = new ArrayList<>();
        for (Row r : repo.scanEntireTable()) {
            all.add(new Order(r.id(), r.customer()));   // line 21: the allocator
        }
        return all;
    }
}
