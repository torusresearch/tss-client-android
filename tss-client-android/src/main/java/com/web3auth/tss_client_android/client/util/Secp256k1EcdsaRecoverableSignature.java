package com.web3auth.tss_client_android.client.util;

public class Secp256k1EcdsaRecoverableSignature {

  private byte[] data = new byte[65];

  public Secp256k1EcdsaRecoverableSignature() {
  }

  public Secp256k1EcdsaRecoverableSignature(byte[] data) {
    if (data.length != 65) {
      throw new IllegalArgumentException("Data length must be 65 bytes.");
    }
    this.data = data;
  }

  public byte[] getData() {
    return data;
  }
}

