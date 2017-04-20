/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.xsalsa20poly1305;

/**
 * Convenience functions for encryption without requiring nonce management.
 * <p>
 * Compatible with RbNaCl's SimpleBox construction, but generates misuse-resistant nonces.
 */
public class SimpleBox {

  private final SecretBox box;

  /**
   * Create a new {@link SimpleBox} instance with the given key.
   *
   * @param key a 32-byte key
   */
  public SimpleBox(byte[] key) {
    this.box = new SecretBox(key);
  }

  /**
   * Encrypt the plaintext with the given key.
   *
   * @param plaintext any arbitrary bytes
   * @return the ciphertext
   */
  public byte[] seal(byte[] plaintext) {
    final byte[] nonce = Nonces.misuseResistant(box.key, plaintext);
    final byte[] ciphertext = box.seal(nonce, plaintext);
    final byte[] out = new byte[nonce.length + ciphertext.length];
    System.arraycopy(nonce, 0, out, 0, nonce.length);
    System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
    return out;
  }

  /**
   * Decrypt the ciphertext with the given key.
   *
   * @param ciphertext an encrypted message
   * @return the plaintext
   * @throws InvalidCiphertextException if the ciphertext cannot be decrypted
   */
  public byte[] open(byte[] ciphertext) throws InvalidCiphertextException {
    final byte[] nonce = new byte[Nonces.NONCE_SIZE];
    final int len = Math.min(ciphertext.length, nonce.length);
    System.arraycopy(ciphertext, 0, nonce, 0, len);
    final byte[] out = new byte[Math.max(0, ciphertext.length - nonce.length)];
    System.arraycopy(ciphertext, len, out, 0, out.length);
    return box.open(nonce, out);
  }
}
