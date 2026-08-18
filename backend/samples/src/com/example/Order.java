package com.example;

public class Order {
    private final long id;
    private final String customer;

    public Order(long id, String customer) {
        this.id = id;
        this.customer = customer;
    }

    public long getId() {
        return id;
    }
}
