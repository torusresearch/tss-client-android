package com.web3auth.tss_client_android.client;

import org.json.JSONObject;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.emitter.Emitter;
import io.socket.engineio.client.transports.WebSocket;

public class TSSSocket {
    private final String session;
    private final int party;
    private final String socketURL;
    private Socket socket;
    private Map<String, String> headers;

    public TSSSocket(String session, int party, String socketURL) {
        this.session = session;
        this.party = party;
        this.socketURL = socketURL;
        this.headers = new HashMap<>();

        try {
            IO.Options options = IO.Options.builder()
                    //.setPath("/tss/socket.io")
                    .setQuery(session.split("default0")[1])
                    .setTransports(new String[]{WebSocket.NAME})
                    //.setSecure(true)
                    .setReconnectionDelayMax(10000)
                    .setReconnectionAttempts(3)
                    .setForceNew(true)
                    .build();
            socket = IO.socket(URI.create(socketURL), options);
        } catch (Exception e) {
            e.printStackTrace();
        }

        setupSocketEventHandlers();
    }

    public String getSession() {
        return session;
    }

    public int getParty() {
        return party;
    }

    public Socket getSocket() {
        return socket;
    }

    private void setupSocketEventHandlers() {
        socket.on(Socket.EVENT_CONNECT_ERROR, (Emitter.Listener) args -> System.out.println("socket error, party: " + party));

        socket.on(Socket.EVENT_CONNECT, args -> System.out.println("connected, party: " + party));

        socket.on(Socket.EVENT_DISCONNECT, args -> System.out.println("disconnected, party: " + party));

        socket.on("precompute_complete", args -> {
            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            JSONObject jsonData = (JSONObject) args[0];
            String session = jsonData.optString("session");
            int party = jsonData.optInt("party");
            EventQueue.shared().addEvent(new Event(
                    String.valueOf(party),
                    session,
                    party,
                    new Date(),
                    EventType.PRECOMPUTE_COMPLETE
            ));

        });

        socket.on("precompute_failed", args -> {
            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            JSONObject jsonData = (JSONObject) args[0];
            String session = jsonData.optString("session");
            int party = jsonData.optInt("party");
            EventQueue.shared().addEvent(new Event(
                    String.valueOf(party),
                    session,
                    party,
                    new Date(),
                    EventType.PRECOMPUTE_ERROR
            ));
        });

        socket.on("send", args -> {
            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            JSONObject data = (JSONObject) args[0];
            String session = data.optString("session");
            int sender = data.optInt("sender");
            int recipient = data.optInt("recipient");
            String msg_type = data.optString("msg_type");
            String msg_data = data.optString("msg_data");
            MessageQueue.shared().addMessage(new Message(
                    session,
                    sender,
                    recipient,
                    msg_type,
                    msg_data
            ));

        });
        socket.connect();
    }

    public void disconnect() {
        socket.disconnect();
    }

}

