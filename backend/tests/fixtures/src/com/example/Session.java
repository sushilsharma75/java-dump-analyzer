package com.example;

public class Session {
    private final String id;
    private final byte[] payload;

    public Session(String id, byte[] payload) {
        this.id = id;
        this.payload = payload;
    }

    public String getId() {
        return id;
    }
}
