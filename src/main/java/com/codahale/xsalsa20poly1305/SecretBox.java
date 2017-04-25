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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.java.curve_sigs;

/**
 * Encryption and decryption using XSalsa20Poly1305.
 * <p>
 * Compatible with NaCl's SecretBox construction.
 */
@Immutable
public class SecretBox {

  static final int NONCE_SIZE = 24;
  private final byte[] key;

  /**
   * Create a new {@link SecretBox} instance with the given secret key.
   *
   * @param secetKey a 32-byte secret key
   */
  public SecretBox(@Nonnull byte[] secetKey) {
    if (secetKey.length != 32) {
      throw new IllegalArgumentException("key must be 32 bytes long");
    }
    this.key = Arrays.copyOf(secetKey, secetKey.length);
  }

  /**
   * Create a new {@link SecretBox} instance given a Curve25519 public key and a Curve25519 private
   * key.
   *
   * @param publicKey a Curve25519 public key
   * @param privateKey a Curve25519 private key
   */
  public SecretBox(@Nonnull byte[] publicKey, @Nonnull byte[] privateKey) {
    this(sharedSecret(publicKey, privateKey));
  }

  private static byte[] sharedSecret(@Nonnull byte[] publicKey, @Nonnull byte[] privateKey) {
    final byte[] s = Curve25519.getInstance(Curve25519.BEST)
                               .calculateAgreement(publicKey, privateKey);
    final byte[] k = new byte[32];
    HSalsa20.hsalsa20(k, new byte[16], s, HSalsa20.SIGMA);
    return k;
  }

  /**
   * Generates a Curve25519 public key given a Curve25519 private key.
   *
   * @param privateKey a Curve25519 private key
   * @return the public key matching {@code privateKey}
   */
  public static byte[] generatePublicKey(byte[] privateKey) {
    final byte[] publicKey = new byte[32];
    curve_sigs.curve25519_keygen(publicKey, privateKey);
    return publicKey;
  }

  /**
   * generates a Curve25519 private key.
   *
   * @return a Curve25519 private key
   */
  public static byte[] generatePrivateKey() {
    final byte[] k = generateSecretKey();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return k;
  }

  /**
   * Generates a 32-byte secret key.
   *
   * @return a 32-byte secret key
   */
  public static byte[] generateSecretKey() {
    final byte[] k = new byte[32];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(k);
    return k;
  }

  /**
   * Encrypt a plaintext using the given key and nonce.
   *
   * @param nonce a 24-byte nonce (cf. {@link #nonce(byte[])}, {@link #nonce()})
   * @param plaintext an arbitrary message
   * @return the ciphertext
   */
  public byte[] seal(@Nonnull byte[] nonce, @Nonnull byte[] plaintext) {
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
   * @see #nonce(byte[])
   * @see #nonce()
   */
  public Optional<byte[]> open(@Nonnull byte[] nonce, @Nonnull byte[] ciphertext) {
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

  /**
   * Generates a random nonce.
   * <p>
   * <b>N.B.:</b> Use of this method is probably fine, but because an entropy-exhausted or
   * compromised {@link SecureRandom} provider might generate duplicate nonces (which would allow an
   * attacker to potentially decrypt and even forge messages), {@link #nonce(byte[])}
   * is recommended instead.
   *
   * @return a 24-byte nonce
   */
  public byte[] nonce() {
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
   * @param message the message to be encrypted
   * @return a 24-byte nonce
   */
  public byte[] nonce(byte[] message) {
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
