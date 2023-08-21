package com.web3auth.tss_client_android.client.util;

public class Triple<T, T1, T2> {
    private final T first;
    private final T1 second;
    private final T2 third;

    public Triple(T first, T1 second, T2 third) {
        this.first = first;
        this.second = second;
        this.third = third;
    }

    public T getFirst() { return first; }
    public T1 getSecond() { return second; }
    public T2 getThird() { return third; }
}
