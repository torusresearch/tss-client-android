package com.web3auth.tss_client_android.client;

import java.util.Date;

public class Event {
    private String message;
    private String session;
    private int party;
    private Date occurred;
    private EventType type;

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

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public int getParty() {
        return party;
    }

    public void setParty(int party) {
        this.party = party;
    }

    public Date getOccurred() {
        return occurred;
    }

    public void setOccurred(Date occurred) {
        this.occurred = occurred;
    }

    public EventType getType() {
        return type;
    }

    public void setType(EventType type) {
        this.type = type;
    }
}

