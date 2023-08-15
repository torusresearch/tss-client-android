package com.web3auth.tss_client_android.client;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class EventQueue {
    // Singleton instance
    private static final EventQueue shared = new EventQueue();

    //private final List<Event> events = new CopyOnWriteArrayList<>();
    private final ConcurrentLinkedQueue<Event> events = new ConcurrentLinkedQueue<>();
    private final ExecutorService queueExecutor = Executors.newCachedThreadPool();
    private Date lastFocus = new Date();

    // Private constructor to prevent external instantiation
    private EventQueue() {
    }

    // Static method to access the singleton instance
    public static EventQueue shared() {
        return shared;
    }

    // Method to add an event to the queue
    public void addEvent(Event event) {
        queueExecutor.submit(() -> {
            boolean found = events.stream()
                    .anyMatch(e -> e.getParty() == event.getParty() &&
                            e.getSession().equals(event.getSession()) &&
                            e.getType() == event.getType() &&
                            e.getOccurred().after(lastFocus));
            if (!found) {
                events.add(event);
            }
        });
    }

    // Method to find events for a specific session and event type
    public List<Event> findEvent(String session, EventType eventType) throws ExecutionException, InterruptedException {
        return queueExecutor.submit(() -> {
            List<Event> filteredEvents = new ArrayList<>();
            for (Event event : events) {
                if (event.getOccurred().after(lastFocus) && event.getSession().equals(session) && event.getType() == eventType) {
                    filteredEvents.add(event);
                }
            }
            return filteredEvents;
        }).get();
    }

    // Method to count events for each event type in a specific session
    public Map<EventType, Integer> countEvents(String session) throws ExecutionException, InterruptedException {
        return queueExecutor.submit(() -> {
            Map<EventType, Integer> counts = new HashMap<>();
            for (Event event : events) {
                if (event.getOccurred().after(lastFocus) && event.getSession().equals(session)) {
                    counts.put(event.getType(), counts.getOrDefault(event.getType(), 0) + 1);
                }
            }
            return counts;
        }).get();
    }

    // Method to update the last focus time and remove events occurred before the new focus time
    public void updateFocus(Date time) {
        queueExecutor.submit(() -> {
            lastFocus = time;
            events.removeIf(event -> event.getOccurred().before(time));
        });
    }

    // Method to remove events for a specific session
    public void removeEvents(String session) {
        queueExecutor.submit(() -> {
            events.removeIf(event -> event.getSession().equals(session));
        });
    }

    // Method to shut down the executor when no longer needed
    public void shutdown() {
        queueExecutor.shutdown();
    }
}

