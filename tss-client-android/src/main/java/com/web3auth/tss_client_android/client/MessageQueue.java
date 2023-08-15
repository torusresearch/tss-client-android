package com.web3auth.tss_client_android.client;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MessageQueue {
    // Singleton instance
    private static final MessageQueue shared = new MessageQueue();

    private final ConcurrentLinkedQueue<Message> messages = new ConcurrentLinkedQueue<>();
    private final ExecutorService queueExecutor = Executors.newCachedThreadPool();

    // Private constructor to prevent external instantiation
    private MessageQueue() {
    }

    // Static method to access the singleton instance
    public static MessageQueue shared() {
        return shared;
    }

    // Method to add a message to the queue
    public void addMessage(Message msg) {
        queueExecutor.submit(() -> messages.add(msg));
    }

    public Message findMessage(String session, long sender, long recipient, String messageType) throws ExecutionException, InterruptedException {
        return queueExecutor.submit(() -> {
            for (Message msg : messages) {
                if (msg.getSession().equals(session) && msg.getSender() == sender && msg.getRecipient() == recipient && msg.getMsgType().equals(messageType)) {
                    return msg;
                }
            }
            return null;
        }).get();
    }

    // Method to get all messages for a specific session
    public List<Message> allMessages(String session) throws ExecutionException, InterruptedException {
        return queueExecutor.submit(() -> {
            List<Message> sessionMessages = new ArrayList<>();
            for (Message msg : messages) {
                if (msg.getSession().equals(session)) {
                    sessionMessages.add(msg);
                }
            }
            return sessionMessages;
        }).get();
    }

    public void removeMessage(String session, long sender, long recipient, String messageType) {
        queueExecutor.submit(() -> messages.removeIf(msg -> msg.getSession().equals(session) && msg.getSender() == sender && msg.getRecipient() == recipient && msg.getMsgType().equals(messageType)));
    }

    public void removeMessages(String session) {
        queueExecutor.submit(() -> messages.removeIf(msg -> msg.getSession().equals(session)));
    }

    public void shutdown() {
        queueExecutor.shutdown();
    }
}


