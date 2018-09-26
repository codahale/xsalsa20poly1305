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

import static com.codahale.xsalsa20poly1305.tests.Generators.byteArrays;
import static com.codahale.xsalsa20poly1305.tests.Generators.privateKeys;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codahale.xsalsa20poly1305.Keys;
import com.codahale.xsalsa20poly1305.SecretBox;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.abstractj.kalium.crypto.Box;
import org.junit.jupiter.api.Test;
import org.quicktheories.WithQuickTheories;

class SecretBoxTest implements WithQuickTheories {

  @Test
  void shortKey() {
    qt().forAll(byteArrays(1, 31))
        .checkAssert(
            key ->
                assertThatThrownBy(() -> new SecretBox(key))
                    .isInstanceOf(IllegalArgumentException.class));
  }

  @Test
  void roundTrip() {
    qt().withExamples(1)
        .withShrinkCycles(1)
        .forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (key, nonce, message) -> {
              final SecretBox box = new SecretBox(key);
              return box.open(nonce, box.seal(nonce, message))
                  .map(a -> Arrays.equals(message, a))
                  .orElse(false);
            });
  }

  @Test
  void pkRoundTrip() {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final byte[] publicKeyA = Keys.generatePublicKey(privateKeyA);
              final byte[] publicKeyB = Keys.generatePublicKey(privateKeyB);
              final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
              final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
              return boxB.open(nonce, boxA.seal(nonce, message))
                  .map(b -> Arrays.equals(message, b))
                  .orElse(false);
            });
  }

  @Test
  void badKey() {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(32, 32))
        .assuming((keyA, nonce, message, keyB) -> !Arrays.equals(keyA, keyB))
        .check(
            (keyA, nonce, message, keyB) -> {
              final byte[] ciphertext = new SecretBox(keyA).seal(nonce, message);
              final Optional<byte[]> plaintext = new SecretBox(keyB).open(nonce, ciphertext);
              return !plaintext.isPresent();
            });
  }

  @Test
  void badNonce() {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(24, 24))
        .assuming((key, nonceA, message, nonceB) -> !Arrays.equals(nonceA, nonceB))
        .check(
            (key, nonceA, message, nonceB) -> {
              final SecretBox box = new SecretBox(key);
              return !box.open(nonceB, box.seal(nonceA, message)).isPresent();
            });
  }

  @Test
  void badCiphertext() {
    qt().forAll(
            byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), integers().allPositive())
        .check(
            (key, nonce, message, v) -> {
              final SecretBox box = new SecretBox(key);
              final byte[] ciphertext = box.seal(nonce, message);
              // flip a single random bit of plaintext
              byte mask = (byte) (1 << (v % 8));
              if (mask == 0) {
                mask = 1;
              }
              ciphertext[v % ciphertext.length] ^= mask;
              return !box.open(nonce, ciphertext).isPresent();
            });
  }

  @Test
  void randomNonce() {
    final SecretBox box = new SecretBox(new byte[32]);
    final List<byte[]> nonces =
        IntStream.range(0, 1000).mapToObj(i -> box.nonce()).collect(Collectors.toList());
    qt().forAll(integers().between(1, 1000), integers().between(1, 1000))
        .assuming((x, y) -> !Objects.equals(x, y))
        .check((x, y) -> !Arrays.equals(nonces.get(x - 1), nonces.get(y - 1)));
    qt().forAll(integers().all()).check(i -> box.nonce().length == 24);
  }

  @Test
  void misuseResistantNonce() {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check(
            (key, message) -> {
              final SecretBox box = new SecretBox(key);
              return box.nonce(message).length == 24;
            });
  }

  @Test
  void fromUsToLibSodium() {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (key, nonce, message) -> {
              final byte[] c = new SecretBox(key).seal(nonce, message);
              final org.abstractj.kalium.crypto.SecretBox theirBox =
                  new org.abstractj.kalium.crypto.SecretBox(key);
              final Optional<byte[]> p = tryTo(() -> theirBox.decrypt(nonce, c));
              return p.map(a -> Arrays.equals(message, a)).orElse(false);
            });
  }

  @Test
  void fromLibSodiumToUs() {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (key, nonce, message) -> {
              final byte[] c =
                  new org.abstractj.kalium.crypto.SecretBox(key).encrypt(nonce, message);
              final Optional<byte[]> p = new SecretBox(key).open(nonce, c);
              return p.map(a -> Arrays.equals(message, a)).orElse(false);
            });
  }

  @Test
  void pkFromUsToLibSodium() {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final byte[] publicKeyA = Keys.generatePublicKey(privateKeyA);
              final byte[] publicKeyB = Keys.generatePublicKey(privateKeyB);
              final SecretBox ourBox = new SecretBox(publicKeyB, privateKeyA);
              final byte[] c = ourBox.seal(nonce, message);
              final Box theirBox = new Box(publicKeyA, privateKeyB);
              final Optional<byte[]> p = tryTo(() -> theirBox.decrypt(nonce, c));
              return p.map(a -> Arrays.equals(message, a)).orElse(false);
            });
  }

  @Test
  void pkFromLibSodiumToUs() {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check(
            (privateKeyA, privateKeyB, nonce, message) -> {
              final byte[] publicKeyA = Keys.generatePublicKey(privateKeyA);
              final byte[] publicKeyB = Keys.generatePublicKey(privateKeyB);
              final Box theirBox = new Box(publicKeyB, privateKeyA);
              final byte[] c = theirBox.encrypt(nonce, message);
              final SecretBox ourBox = new SecretBox(publicKeyA, privateKeyB);
              return ourBox.open(nonce, c).map(a -> Arrays.equals(message, a)).orElse(false);
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
