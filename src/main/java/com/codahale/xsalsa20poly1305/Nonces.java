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

import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.Blake2bDigest;

/**
 * This class contains {@code static} utility methods for generating
 * XSalsa20Poly1305 nonces.
 */
public final class Nonces {

  /**
   * The size, in bytes, of an XSalsa20Poly1305 nonce.
   */
  static final int NONCE_SIZE = 24;

  private Nonces() {
    throw new AssertionError("No Nonces instances for you!");
  }

  /**
   * Generates a random nonce.
   * <p>
   * <b>N.B.:</b> Use of this method is probably fine, but because an entropy-exhausted or
   * compromised {@link SecureRandom} provider might generate duplicate nonces (which would allow an
   * attacker to potentially decrypt and even forge messages), {@link #misuseResistant(byte[],
   * byte[])} is recommended instead.
   *
   * @return a 24-byte nonce
   */
  public static byte[] random() {
    final byte[] nonce = new byte[NONCE_SIZE];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(nonce);
    return nonce;
  }

  /**
   * Generates a random nonce which is guaranteed to be unique even if the process's PRNG is
   * exhausted or compromised.
   * <p>
   * Internally, this creates a Blake2b instance with the given key, a random 16-byte salt, and a
   * random 16-byte personalization tag. It then hashes the message and returns the resulting
   * 24-byte digest as the nonce.
   * <p>
   * In the event of a broken or entropy-exhausted {@link SecureRandom} provider, the nonce is
   * essentially equivalent to a synthetic IV and should be unique for any given key/message pair.
   * The result will be deterministic, which will allow attackers to detect duplicate messages.
   * <p>
   * In the event of a compromised {@link SecureRandom} provider, the attacker would need a complete
   * second-preimage attack against Blake2b in order to produce colliding nonces.
   *
   * @param key the key which will be used to encrypt the message
   * @param message the message to be encrypted
   * @return a 24-byte nonce
   */
  public static byte[] misuseResistant(byte[] key, byte[] message) {
    final byte[] n1 = new byte[16];
    final byte[] n2 = new byte[16];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(n1);
    random.nextBytes(n2);

    final Blake2bDigest blake2b = new Blake2bDigest(key, NONCE_SIZE, n1, n2);
    blake2b.update(message, message.length, 0);

    final byte[] nonce = new byte[NONCE_SIZE];
    blake2b.doFinal(nonce, 0);
    return nonce;
  }
}
