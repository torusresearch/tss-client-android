package com.web3auth.tss_client_android.client;

import java.util.Date;

public class Event {
    private final String message;
    private final String session;
    private final int party;
    private final Date occurred;
    private final EventType type;

    public Event(String message, String session, int party, Date occurred, EventType type) {
        this.message = message;
        this.session = session;
        this.party = party;
        this.occurred = occurred;
        this.type = type;
    }

    // Getters and setters (if needed)
    public String getMessage() {
        return message;
    }

    public String getSession() {
        return session;
    }

    public int getParty() {
        return party;
    }

    public Date getOccurred() {
        return occurred;
    }

    public EventType getType() {
        return type;
    }
}

