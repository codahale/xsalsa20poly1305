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
import static com.codahale.xsalsa20poly1305.tests.Generators.keyPairs;
import static org.quicktheories.quicktheories.QuickTheory.qt;
import static org.quicktheories.quicktheories.generators.SourceDSL.integers;

import com.codahale.xsalsa20poly1305.SecretBox;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.abstractj.kalium.crypto.Box;
import org.junit.Test;

public class SecretBoxTest {

  @Test
  public void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final SecretBox box = new SecretBox(key);
          return box.open(nonce, box.seal(nonce, message))
                    .map(p -> Arrays.equals(p, message))
                    .orElse(false);
        });
  }

  @Test
  public void pkRoundTrip() throws Exception {
    qt().forAll(keyPairs(), keyPairs(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((pairA, pairB, nonce, message) -> {
          final SecretBox boxA = new SecretBox(pairB.publicKey, pairA.privateKey);
          final SecretBox boxB = new SecretBox(pairA.publicKey, pairB.privateKey);
          return boxB.open(nonce, boxA.seal(nonce, message))
                     .map(p -> Arrays.equals(p, message))
                     .orElse(false);
        });
  }

  @Test
  public void badKey() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(32, 32))
        .assuming((keyA, nonce, message, keyB) -> !Arrays.equals(keyA, keyB))
        .check((keyA, nonce, message, keyB) -> {
          final byte[] ciphertext = new SecretBox(keyA).seal(nonce, message);
          final Optional<byte[]> plaintext = new SecretBox(keyB).open(nonce, ciphertext);
          return !plaintext.isPresent();
        });
  }

  @Test
  public void badNonce() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(24, 24))
        .check((key, nonceA, message, nonceB) -> {
          final SecretBox box = new SecretBox(key);
          return !box.open(nonceB, box.seal(nonceA, message)).isPresent();
        });
  }

  @Test
  public void badCiphertext() throws Exception {
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
  public void randomNonce() throws Exception {
    final SecretBox box = new SecretBox(new byte[32]);
    final List<byte[]> nonces = IntStream.range(0, 1000)
                                         .mapToObj(i -> box.randomNonce())
                                         .collect(Collectors.toList());
    qt().forAll(integers().between(1, 1000), integers().between(1, 1000))
        .assuming((x, y) -> !Objects.equals(x, y))
        .check((x, y) -> !Arrays.equals(nonces.get(x - 1), nonces.get(y - 1)));
    qt().forAll(integers().all())
        .check(i -> box.randomNonce().length == 24);
  }

  @Test
  public void misuseResistantNonce() throws Exception {
    final SecretBox box = new SecretBox(new byte[32]);
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> box.misuseResistantNonce(message).length == 24);
  }

  @Test
  public void fromUsToLibSodium() throws Exception {
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
  public void fromLibSodiumToUs() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final byte[] c = new org.abstractj.kalium.crypto.SecretBox(key).encrypt(nonce, message);
          final Optional<byte[]> p = new SecretBox(key).open(nonce, c);
          return p.map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  public void pkFromUsToLibSodium() throws Exception {
    qt().forAll(keyPairs(), keyPairs(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((pairA, pairB, nonce, message) -> {
          final SecretBox ourBox = new SecretBox(pairB.publicKey, pairA.privateKey);
          final byte[] c = ourBox.seal(nonce, message);
          final Box theirBox = new Box(pairA.publicKey, pairB.privateKey);
          final Optional<byte[]> p = tryTo(() -> theirBox.decrypt(nonce, c));
          return p.map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  public void pkFromLibSodiumToUs() throws Exception {
    qt().forAll(keyPairs(), keyPairs(), byteArrays(24, 24), byteArrays(1, 4096))
        .check((pairA, pairB, nonce, message) -> {
          final Box theirBox = new Box(pairB.publicKey, pairA.privateKey);
          final byte[] c = theirBox.encrypt(nonce, message);
          final SecretBox ourBox = new SecretBox(pairA.publicKey, pairB.privateKey);
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