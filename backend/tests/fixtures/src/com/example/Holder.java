package com.example;

import java.util.ArrayList;
import java.util.List;

public class Holder {

    // Instance field that anchors a growing list of Leaf objects.
    private final List<Leaf> leaves = new ArrayList<>();

    public void add(Leaf l) {
        leaves.add(l);
    }
}
