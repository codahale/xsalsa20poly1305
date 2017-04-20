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

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Encryption and decryption using XSalsa20Poly1305.
 * <p>
 * Compatible with NaCl's SecretBox construction.
 */
public class SecretBox {

  final byte[] key;

  /**
   * Creates a new {@link SecretBox} instance with the given key.
   *
   * @param key a 32-byte key
   */
  public SecretBox(byte[] key) {
    if (Objects.requireNonNull(key).length != 32) {
      throw new IllegalArgumentException("key must be 32 bytes long");
    }
    this.key = Arrays.copyOf(key, key.length);
  }

  /**
   * Encrypt a plaintext using the given key and nonce.
   *
   * @param nonce a 24-byte nonce (cf. {@link Nonces#misuseResistant(byte[], byte[])}, {@link
   * Nonces#random()})
   * @param plaintext an arbitrary message
   * @return the ciphertext
   */
  public byte[] seal(byte[] nonce, byte[] plaintext) {
    // initialize XSalsa20
    final XSalsa20Engine xsalsa20 = new XSalsa20Engine();
    xsalsa20.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

    // generate Poly1305 subkey
    final byte[] sk = new byte[32];
    xsalsa20.processBytes(sk, 0, 32, sk, 0);

    // encrypt plaintext
    final byte[] out = new byte[plaintext.length + 16];
    xsalsa20.processBytes(plaintext, 0, plaintext.length, out, 16);

    // hash ciphertext and prepend mac to ciphertext
    final Poly1305 poly1305 = new Poly1305();
    poly1305.init(new KeyParameter(sk));
    poly1305.update(out, 16, plaintext.length);
    poly1305.doFinal(out, 0);
    return out;
  }

  /**
   * Decrypt a ciphertext using the given key and nonce.
   *
   * @param nonce a 24-byte nonce
   * @param ciphertext the encrypted message
   * @return an {@link Optional} of the original plaintext, or if either the key, nonce, or
   * ciphertext was modified, an empty {@link Optional}
   * @see Nonces#misuseResistant(byte[], byte[])
   * @see Nonces#random()
   */
  public Optional<byte[]> open(byte[] nonce, byte[] ciphertext) {
    final XSalsa20Engine xsalsa20 = new XSalsa20Engine();
    final Poly1305 poly1305 = new Poly1305();

    // initialize XSalsa20
    xsalsa20.init(false, new ParametersWithIV(new KeyParameter(key), nonce));

    // generate mac subkey
    final byte[] sk = new byte[32];
    xsalsa20.processBytes(sk, 0, sk.length, sk, 0);

    // hash ciphertext
    poly1305.init(new KeyParameter(sk));
    final int len = Math.max(ciphertext.length - 16, 0);
    poly1305.update(ciphertext, 16, len);
    final byte[] calculatedMAC = new byte[16];
    poly1305.doFinal(calculatedMAC, 0);

    // extract mac
    final byte[] presentedMAC = new byte[16];
    System.arraycopy(ciphertext, 0, presentedMAC, 0, Math.min(ciphertext.length, 16));

    // compare macs
    if (!MessageDigest.isEqual(calculatedMAC, presentedMAC)) {
      return Optional.empty();
    }

    // decrypt ciphertext
    final byte[] plaintext = new byte[len];
    xsalsa20.processBytes(ciphertext, 16, plaintext.length, plaintext, 0);
    return Optional.of(plaintext);
  }
}
