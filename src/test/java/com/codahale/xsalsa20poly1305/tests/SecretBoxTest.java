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
package com.codahale.xsalsa20poly1305.tests;

import static com.codahale.xsalsa20poly1305.tests.Generators.byteStrings;
import static com.codahale.xsalsa20poly1305.tests.Generators.privateKeys;
import static org.junit.Assert.assertEquals;

import com.codahale.xsalsa20poly1305.SecretBox;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import okio.ByteString;
import org.abstractj.kalium.crypto.Box;
import org.apache.commons.math3.exception.NullArgumentException;
import org.junit.Test;
import org.quicktheories.WithQuickTheories;

public class SecretBoxTest implements WithQuickTheories {

  @Test
  public void shortKey() {
    qt().forAll(byteStrings(1, 31))
        .check(
            key -> {
              try {
                new SecretBox(key);
                return false;
              } catch (IllegalArgumentException e) {
                return true;
              }
            });
  }

  @Test
  public void generateSecretKey() {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString key = SecretBox.generateSecretKey();
    final SecretBox box = new SecretBox(key);
    final ByteString n = box.nonce(message);
    final ByteString c = box.seal(n, message);
    final Optional<ByteString> p = box.open(n, c);
    assertEquals(message, p.orElseThrow(NullArgumentException::new));
  }

  @Test
  public void generateKeyPair() {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString privateKeyA = SecretBox.generatePrivateKey();
    final ByteString publicKeyA = SecretBox.generatePublicKey(privateKeyA);
    final ByteString privateKeyB = SecretBox.generatePrivateKey();
    final ByteString publicKeyB = SecretBox.generatePublicKey(privateKeyB);
    final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
    final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
    final ByteString n = boxA.nonce(message);
    final ByteString c = boxA.seal(n, message);
    final Optional<ByteString> p = boxB.open(n, c);
    assertEquals(message, p.orElseThrow(NullArgumentException::new));
  }

  @Test
  public void roundTrip() {
    qt().withExamples(1)
        .withShrinkCycles(1)
        .forAll(byteStrings(32, 32), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (key, nonce, message) -> {
              final SecretBox box = new SecretBox(key);
              return box.open(nonce, box.seal(nonce, message)).map(message::equals).orElse(false);
            });
  }

  @Test
  public void pkRoundTrip() {
    qt().forAll(privateKeys(), privateKeys(), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final ByteString publicKeyA = SecretBox.generatePublicKey(privateKeyA);
              final ByteString publicKeyB = SecretBox.generatePublicKey(privateKeyB);
              final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
              final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
              return boxB.open(nonce, boxA.seal(nonce, message)).map(message::equals).orElse(false);
            });
  }

  @Test
  public void badKey() {
    qt().forAll(byteStrings(32, 32), byteStrings(24, 24), byteStrings(1, 4096), byteStrings(32, 32))
        .assuming((keyA, nonce, message, keyB) -> !keyA.equals(keyB))
        .check(
            (keyA, nonce, message, keyB) -> {
              final ByteString ciphertext = new SecretBox(keyA).seal(nonce, message);
              final Optional<ByteString> plaintext = new SecretBox(keyB).open(nonce, ciphertext);
              return !plaintext.isPresent();
            });
  }

  @Test
  public void badNonce() {
    qt().forAll(byteStrings(32, 32), byteStrings(24, 24), byteStrings(1, 4096), byteStrings(24, 24))
        .assuming((key, nonceA, message, nonceB) -> !nonceA.equals(nonceB))
        .check(
            (key, nonceA, message, nonceB) -> {
              final SecretBox box = new SecretBox(key);
              return !box.open(nonceB, box.seal(nonceA, message)).isPresent();
            });
  }

  @Test
  public void badCiphertext() {
    qt().forAll(
            byteStrings(32, 32),
            byteStrings(24, 24),
            byteStrings(1, 4096),
            integers().allPositive())
        .check(
            (key, nonce, message, v) -> {
              final SecretBox box = new SecretBox(key);
              final byte[] ciphertext = box.seal(nonce, message).toByteArray();
              // flip a single random bit of plaintext
              byte mask = (byte) (1 << (v % 8));
              if (mask == 0) {
                mask = 1;
              }
              ciphertext[v % ciphertext.length] ^= mask;
              return !box.open(nonce, ByteString.of(ciphertext)).isPresent();
            });
  }

  @Test
  public void randomNonce() {
    final SecretBox box = new SecretBox(ByteString.of(new byte[32]));
    final List<ByteString> nonces =
        IntStream.range(0, 1000).mapToObj(i -> box.nonce()).collect(Collectors.toList());
    qt().forAll(integers().between(1, 1000), integers().between(1, 1000))
        .assuming((x, y) -> !Objects.equals(x, y))
        .check((x, y) -> !nonces.get(x - 1).equals(nonces.get(y - 1)));
    qt().forAll(integers().all()).check(i -> box.nonce().size() == 24);
  }

  @Test
  public void misuseResistantNonce() {
    qt().forAll(byteStrings(32, 32), byteStrings(1, 4096))
        .check(
            (key, message) -> {
              final SecretBox box = new SecretBox(key);
              return box.nonce(message).size() == 24;
            });
  }

  @Test
  public void fromUsToLibSodium() {
    qt().forAll(byteStrings(32, 32), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (key, nonce, message) -> {
              final ByteString c = new SecretBox(key).seal(nonce, message);
              final org.abstractj.kalium.crypto.SecretBox theirBox =
                  new org.abstractj.kalium.crypto.SecretBox(key.toByteArray());
              final Optional<byte[]> p =
                  tryTo(() -> theirBox.decrypt(nonce.toByteArray(), c.toByteArray()));
              return p.map(ByteString::of).map(message::equals).orElse(false);
            });
  }

  @Test
  public void fromLibSodiumToUs() {
    qt().forAll(byteStrings(32, 32), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (key, nonce, message) -> {
              final byte[] c =
                  new org.abstractj.kalium.crypto.SecretBox(key.toByteArray())
                      .encrypt(nonce.toByteArray(), message.toByteArray());
              final Optional<ByteString> p = new SecretBox(key).open(nonce, ByteString.of(c));
              return p.map(message::equals).orElse(false);
            });
  }

  @Test
  public void pkFromUsToLibSodium() {
    qt().forAll(privateKeys(), privateKeys(), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final ByteString publicKeyA = SecretBox.generatePublicKey(privateKeyA);
              final ByteString publicKeyB = SecretBox.generatePublicKey(privateKeyB);
              final SecretBox ourBox = new SecretBox(publicKeyB, privateKeyA);
              final ByteString c = ourBox.seal(nonce, message);
              final Box theirBox = new Box(publicKeyA.toByteArray(), privateKeyB.toByteArray());
              final Optional<byte[]> p =
                  tryTo(() -> theirBox.decrypt(nonce.toByteArray(), c.toByteArray()));
              return p.map(ByteString::of).map(message::equals).orElse(false);
            });
  }

  @Test
  public void pkFromLibSodiumToUs() {
    qt().forAll(privateKeys(), privateKeys(), byteStrings(24, 24), byteStrings(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final ByteString publicKeyA = SecretBox.generatePublicKey(privateKeyA);
              final ByteString publicKeyB = SecretBox.generatePublicKey(privateKeyB);
              final Box theirBox = new Box(publicKeyB.toByteArray(), privateKeyA.toByteArray());
              final byte[] c = theirBox.encrypt(nonce.toByteArray(), message.toByteArray());
              final SecretBox ourBox = new SecretBox(publicKeyA, privateKeyB);
              return ourBox.open(nonce, ByteString.of(c)).map(message::equals).orElse(false);
            });
  }

  private <T> Optional<T> tryTo(Supplier<T> f) {
    try {
      return Optional.ofNullable(f.get());
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }
}
