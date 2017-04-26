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

package com.codahale.xsalsa20poly1305.tests;

import static com.codahale.xsalsa20poly1305.tests.Generators.byteArrays;
import static com.codahale.xsalsa20poly1305.tests.Generators.privateKeys;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.quicktheories.quicktheories.QuickTheory.qt;
import static org.quicktheories.quicktheories.generators.SourceDSL.integers;

import com.codahale.xsalsa20poly1305.SecretBox;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.abstractj.kalium.crypto.Box;
import org.junit.jupiter.api.Test;

class SecretBoxTest {

  @Test
  void shortKey() throws Exception {
    assertThatThrownBy(() -> new SecretBox(new byte[12]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("secretKey must be 32 bytes long");
  }

  @Test
  void generateSecretKey() throws Exception {
    final byte[] message = "this is a test".getBytes(StandardCharsets.UTF_8);
    final byte[] key = SecretBox.generateSecretKey();
    final SecretBox box = new SecretBox(key);
    final byte[] n = box.nonce(message);
    final byte[] c = box.seal(n, message);
    final Optional<byte[]> p = box.open(n, c);
    assertThat(p)
        .isNotEmpty()
        .contains(message);
  }

  @Test
  void generateKeyPair() throws Exception {
    final byte[] message = "this is a test".getBytes(StandardCharsets.UTF_8);
    final byte[] privateKeyA = SecretBox.generatePrivateKey();
    final byte[] publicKeyA = SecretBox.generatePublicKey(privateKeyA);
    final byte[] privateKeyB = SecretBox.generatePrivateKey();
    final byte[] publicKeyB = SecretBox.generatePublicKey(privateKeyB);
    final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
    final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
    final byte[] n = boxA.nonce(message);
    final byte[] c = boxA.seal(n, message);
    final Optional<byte[]> p = boxB.open(n, c);
    assertThat(p)
        .isNotEmpty()
        .contains(message);
  }

  @Test
  void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final SecretBox box = new SecretBox(key);
          return box.open(nonce, box.seal(nonce, message))
                    .map(p -> Arrays.equals(p, message))
                    .orElse(false);
        });
  }

  @Test
  void pkRoundTrip() throws Exception {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((privateKeyA, privateKeyB, nonce, message) -> {
          final byte[] publicKeyA = SecretBox.generatePublicKey(privateKeyA);
          final byte[] publicKeyB = SecretBox.generatePublicKey(privateKeyB);
          final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
          final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
          return boxB.open(nonce, boxA.seal(nonce, message))
                     .map(p -> Arrays.equals(p, message))
                     .orElse(false);
        });
  }

  @Test
  void badKey() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(32, 32))
        .assuming((keyA, nonce, message, keyB) -> !Arrays.equals(keyA, keyB))
        .check((keyA, nonce, message, keyB) -> {
          final byte[] ciphertext = new SecretBox(keyA).seal(nonce, message);
          final Optional<byte[]> plaintext = new SecretBox(keyB).open(nonce, ciphertext);
          return !plaintext.isPresent();
        });
  }

  @Test
  void badNonce() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(24, 24))
        .check((key, nonceA, message, nonceB) -> {
          final SecretBox box = new SecretBox(key);
          return !box.open(nonceB, box.seal(nonceA, message)).isPresent();
        });
  }

  @Test
  void badCiphertext() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096),
        integers().allPositive())
        .check((key, nonce, message, v) -> {
          final SecretBox box = new SecretBox(key);
          final byte[] ciphertext = box.seal(nonce, message);
          // flip a single random bit of plaintext
          int mask = (1 << (v % 8));
          if (mask == 0) {
            mask = 1;
          }
          ciphertext[v % ciphertext.length] ^= mask;
          return !box.open(nonce, ciphertext).isPresent();
        });
  }

  @Test
  void randomNonce() throws Exception {
    final SecretBox box = new SecretBox(new byte[32]);
    final List<byte[]> nonces = IntStream.range(0, 1000)
                                         .mapToObj(i -> box.nonce())
                                         .collect(Collectors.toList());
    qt().forAll(integers().between(1, 1000), integers().between(1, 1000))
        .assuming((x, y) -> !Objects.equals(x, y))
        .check((x, y) -> !Arrays.equals(nonces.get(x - 1), nonces.get(y - 1)));
    qt().forAll(integers().all())
        .check(i -> box.nonce().length == 24);
  }

  @Test
  void misuseResistantNonce() throws Exception {
    final SecretBox box = new SecretBox(new byte[32]);
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> box.nonce(message).length == 24);
  }

  @Test
  void fromUsToLibSodium() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final byte[] c = new SecretBox(key).seal(nonce, message);
          final org.abstractj.kalium.crypto.SecretBox theirBox =
              new org.abstractj.kalium.crypto.SecretBox(key);
          final Optional<byte[]> p = tryTo(() -> theirBox.decrypt(nonce, c));
          return p.map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  void fromLibSodiumToUs() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final byte[] c = new org.abstractj.kalium.crypto.SecretBox(key).encrypt(nonce, message);
          final Optional<byte[]> p = new SecretBox(key).open(nonce, c);
          return p.map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  void pkFromUsToLibSodium() throws Exception {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((privateKeyA, privateKeyB, nonce, message) -> {
          final byte[] publicKeyA = SecretBox.generatePublicKey(privateKeyA);
          final byte[] publicKeyB = SecretBox.generatePublicKey(privateKeyB);
          final SecretBox ourBox = new SecretBox(publicKeyB, privateKeyA);
          final byte[] c = ourBox.seal(nonce, message);
          final Box theirBox = new Box(publicKeyA, privateKeyB);
          final Optional<byte[]> p = tryTo(() -> theirBox.decrypt(nonce, c));
          return p.map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  void pkFromLibSodiumToUs() throws Exception {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((privateKeyA, privateKeyB, nonce, message) -> {
          final byte[] publicKeyA = SecretBox.generatePublicKey(privateKeyA);
          final byte[] publicKeyB = SecretBox.generatePublicKey(privateKeyB);
          final Box theirBox = new Box(publicKeyB, privateKeyA);
          final byte[] c = theirBox.encrypt(nonce, message);
          final SecretBox ourBox = new SecretBox(publicKeyA, privateKeyB);
          return ourBox.open(nonce, c).map(v -> Arrays.equals(v, message)).orElse(false);
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