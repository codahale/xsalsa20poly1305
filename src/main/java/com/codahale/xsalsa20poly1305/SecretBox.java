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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import okio.ByteString;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.rfc7748.X25519;

/**
 * Encryption and decryption using XSalsa20Poly1305.
 *
 * <p>Compatible with NaCl's {@code box} and {@code secretbox} constructions.
 */
@Immutable
public class SecretBox {

  static final int NONCE_SIZE = 24;
  private final byte[] key;

  /**
   * Create a new {@link SecretBox} instance with the given secret key.
   *
   * @param secretKey a 32-byte secret key
   */
  public SecretBox(ByteString secretKey) {
    if (secretKey.size() != 32) {
      throw new IllegalArgumentException("secretKey must be 32 bytes long");
    }
    this.key = secretKey.toByteArray();
  }

  /**
   * Create a new {@link SecretBox} instance given a Curve25519 public key and a Curve25519 private
   * key.
   *
   * @param publicKey a Curve25519 public key
   * @param privateKey a Curve25519 private key
   * @see #sharedSecret(ByteString, ByteString)
   */
  public SecretBox(ByteString publicKey, ByteString privateKey) {
    this(sharedSecret(publicKey, privateKey));
  }

  /**
   * Calculate the X25519/HSalsa20 shared secret for the given public key and private key.
   *
   * @param publicKey the recipient's public key
   * @param privateKey the sender's private key
   * @return a 32-byte secret key only re-calculable by the sender and recipient
   * @see #SecretBox(ByteString, ByteString)
   */
  public static ByteString sharedSecret(ByteString publicKey, ByteString privateKey) {
    final byte[] s = new byte[32];
    X25519.scalarMult(privateKey.toByteArray(), 0, publicKey.toByteArray(), 0, s, 0);
    final byte[] k = new byte[32];
    HSalsa20.hsalsa20(k, new byte[16], s);
    return ByteString.of(k);
  }

  /**
   * Generates a Curve25519 public key given a Curve25519 private key.
   *
   * @param privateKey a Curve25519 private key
   * @return the public key matching {@code privateKey}
   */
  public static ByteString generatePublicKey(ByteString privateKey) {
    final byte[] publicKey = new byte[32];
    X25519.scalarMultBase(privateKey.toByteArray(), 0, publicKey, 0);
    return ByteString.of(publicKey);
  }

  /**
   * generates a Curve25519 private key.
   *
   * @return a Curve25519 private key
   */
  public static ByteString generatePrivateKey() {
    final byte[] k = generateSecretKey().toByteArray();
    k[0] &= (byte) 248;
    k[31] &= (byte) 127;
    k[31] |= (byte) 64;
    return ByteString.of(k);
  }

  /**
   * Generates a 32-byte secret key.
   *
   * @return a 32-byte secret key
   */
  public static ByteString generateSecretKey() {
    final byte[] k = new byte[32];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(k);
    return ByteString.of(k);
  }

  /**
   * Encrypt a plaintext using the given key and nonce.
   *
   * @param nonce a 24-byte nonce (cf. {@link #nonce(ByteString)}, {@link #nonce()})
   * @param plaintext an arbitrary message
   * @return the ciphertext
   */
  public ByteString seal(@Nonnull ByteString nonce, @Nonnull ByteString plaintext) {
    // initialize XSalsa20
    final XSalsa20Engine xsalsa20 = new XSalsa20Engine();
    xsalsa20.init(true, new ParametersWithIV(new KeyParameter(key), nonce.toByteArray()));

    // generate Poly1305 subkey
    final byte[] sk = new byte[32];
    xsalsa20.processBytes(sk, 0, 32, sk, 0);

    // encrypt plaintext
    final byte[] out = new byte[plaintext.size() + 16];
    xsalsa20.processBytes(plaintext.toByteArray(), 0, plaintext.size(), out, 16);

    // hash ciphertext and prepend mac to ciphertext
    final Poly1305 poly1305 = new Poly1305();
    poly1305.init(new KeyParameter(sk));
    poly1305.update(out, 16, plaintext.size());
    poly1305.doFinal(out, 0);
    return ByteString.of(out);
  }

  /**
   * Decrypt a ciphertext using the given key and nonce.
   *
   * @param nonce a 24-byte nonce
   * @param ciphertext the encrypted message
   * @return an {@link Optional} of the original plaintext, or if either the key, nonce, or
   *     ciphertext was modified, an empty {@link Optional}
   * @see #nonce(ByteString)
   * @see #nonce()
   */
  public Optional<ByteString> open(@Nonnull ByteString nonce, @Nonnull ByteString ciphertext) {
    final byte[] in = ciphertext.toByteArray();
    final XSalsa20Engine xsalsa20 = new XSalsa20Engine();
    final Poly1305 poly1305 = new Poly1305();

    // initialize XSalsa20
    xsalsa20.init(false, new ParametersWithIV(new KeyParameter(key), nonce.toByteArray()));

    // generate mac subkey
    final byte[] sk = new byte[32];
    xsalsa20.processBytes(sk, 0, sk.length, sk, 0);

    // hash ciphertext
    poly1305.init(new KeyParameter(sk));
    final int len = Math.max(ciphertext.size() - 16, 0);
    poly1305.update(in, 16, len);
    final byte[] calculatedMAC = new byte[16];
    poly1305.doFinal(calculatedMAC, 0);

    // extract mac
    final byte[] presentedMAC = new byte[16];
    System.arraycopy(in, 0, presentedMAC, 0, Math.min(ciphertext.size(), 16));

    // compare macs
    if (!MessageDigest.isEqual(calculatedMAC, presentedMAC)) {
      return Optional.empty();
    }

    // decrypt ciphertext
    final byte[] plaintext = new byte[len];
    xsalsa20.processBytes(in, 16, plaintext.length, plaintext, 0);
    return Optional.of(ByteString.of(plaintext));
  }

  /**
   * Generates a random nonce.
   *
   * <p><b>N.B.:</b> Use of this method is probably fine, but because an entropy-exhausted or
   * compromised {@link SecureRandom} provider might generate duplicate nonces (which would allow an
   * attacker to potentially decrypt and even forge messages), {@link #nonce(ByteString)} is
   * recommended instead.
   *
   * @return a 24-byte nonce
   */
  public ByteString nonce() {
    final byte[] nonce = new byte[NONCE_SIZE];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(nonce);
    return ByteString.of(nonce);
  }

  /**
   * Generates a random nonce which is guaranteed to be unique even if the process's PRNG is
   * exhausted or compromised.
   *
   * <p>Internally, this creates a Blake2b instance with the given key, a random 16-byte salt, and a
   * random 16-byte personalization tag. It then hashes the message and returns the resulting
   * 24-byte digest as the nonce.
   *
   * <p>In the event of a broken or entropy-exhausted {@link SecureRandom} provider, the nonce is
   * essentially equivalent to a synthetic IV and should be unique for any given key/message pair.
   * The result will be deterministic, which will allow attackers to detect duplicate messages.
   *
   * <p>In the event of a compromised {@link SecureRandom} provider, the attacker would need a
   * complete second-preimage attack against Blake2b in order to produce colliding nonces.
   *
   * @param message the message to be encrypted
   * @return a 24-byte nonce
   */
  public ByteString nonce(ByteString message) {
    final byte[] n1 = new byte[16];
    final byte[] n2 = new byte[16];
    final SecureRandom random = new SecureRandom();
    random.nextBytes(n1);
    random.nextBytes(n2);

    final Blake2bDigest blake2b = new Blake2bDigest(key, NONCE_SIZE, n1, n2);
    blake2b.update(message.toByteArray(), message.size(), 0);

    final byte[] nonce = new byte[NONCE_SIZE];
    blake2b.doFinal(nonce, 0);
    return ByteString.of(nonce);
  }
}
