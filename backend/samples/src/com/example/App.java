package com.example;

/**
 * Entry point. The OrderCache is a process-lifetime object held on the running
 * worker thread's stack (a GC root) — NOT a static field. That's deliberate: it
 * lets the retention tracer climb back to the *instance* field OrderCache.entries
 * and report it as the leak anchor, instead of collapsing the path onto a static
 * holder. (The static-field finder is exercised separately by SessionRegistry.)
 */
public class App {

    public static void main(String[] args) throws InterruptedException {
        OrderCache cache = new OrderCache();
        OrderService service = new OrderService(new InMemoryOrderRepository());
        for (Order o : service.loadAll()) {
            cache.put(o);                 // accumulates without bound
        }
        // The cache stays reachable from this live thread for the life of the
        // process, so nothing it holds is ever collected.
        Thread.currentThread().join();
    }
}
