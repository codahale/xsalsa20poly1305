/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.codahale.xsalsa20poly1305;

import java.util.Arrays;
import java.util.Optional;

/**
 * Convenience functions for encryption without requiring nonce management.
 *
 * <p>Compatible with RbNaCl's SimpleBox construction, but generates misuse-resistant nonces.
 */
public class SimpleBox {

  private final SecretBox box;

  /**
   * Create a new {@link SimpleBox} instance with the given secret key.
   *
   * @param secretKey a 32-byte secret key
   */
  public SimpleBox(byte[] secretKey) {
    this.box = new SecretBox(secretKey);
  }

  /**
   * Create a new {@link SecretBox} instance given a Curve25519 public key and a Curve25519 private
   * key.
   *
   * @param publicKey a Curve25519 public key
   * @param privateKey a Curve25519 private key
   */
  public SimpleBox(byte[] publicKey, byte[] privateKey) {
    this.box = new SecretBox(publicKey, privateKey);
  }

  /**
   * Encrypt the plaintext with the given key.
   *
   * @param plaintext any arbitrary bytes
   * @return the ciphertext
   */
  public byte[] seal(byte[] plaintext) {
    final byte[] nonce = box.nonce(plaintext);
    final byte[] ciphertext = box.seal(nonce, plaintext);
    final byte[] combined = new byte[nonce.length + ciphertext.length];
    System.arraycopy(nonce, 0, combined, 0, nonce.length);
    System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
    return combined;
  }

  /**
   * Decrypt the ciphertext with the given key.
   *
   * @param ciphertext an encrypted message
   * @return an {@link Optional} of the original plaintext, or if either the key, nonce, or
   *     ciphertext was modified, an empty {@link Optional}
   */
  public Optional<byte[]> open(byte[] ciphertext) {
    if (ciphertext.length < SecretBox.NONCE_SIZE) {
      return Optional.empty();
    }
    final byte[] nonce = Arrays.copyOfRange(ciphertext, 0, SecretBox.NONCE_SIZE);
    final byte[] x = Arrays.copyOfRange(ciphertext, SecretBox.NONCE_SIZE, ciphertext.length);
    return box.open(nonce, x);
  }
}
