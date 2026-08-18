package com.example;

import java.util.ArrayList;
import java.util.List;

public class InMemoryOrderRepository implements OrderRepository {

    @Override
    public List<Row> scanEntireTable() {
        List<Row> rows = new ArrayList<>();
        for (long i = 0; i < 2000; i++) {
            rows.add(new Row(i, "customer-" + i));
        }
        return rows;
    }
}
