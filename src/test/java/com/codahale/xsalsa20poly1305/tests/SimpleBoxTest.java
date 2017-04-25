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
import static org.quicktheories.quicktheories.QuickTheory.qt;

import com.codahale.xsalsa20poly1305.SecretBox;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import org.junit.Test;

public class SimpleBoxTest {

  @Test
  public void generateSecretKey() throws Exception {
    final byte[] message = "this is a test".getBytes(StandardCharsets.UTF_8);
    final byte[] key = SimpleBox.generateSecretKey();
    final SimpleBox box = new SimpleBox(key);
    final byte[] c = box.seal(message);
    final Optional<byte[]> p = box.open(c);
    assertThat(p)
        .isNotEmpty()
        .contains(message);
  }

  @Test
  public void generateKeyPair() throws Exception {
    final byte[] message = "this is a test".getBytes(StandardCharsets.UTF_8);
    final byte[] privateKeyA = SimpleBox.generatePrivateKey();
    final byte[] publicKeyA = SimpleBox.generatePublicKey(privateKeyA);
    final byte[] privateKeyB = SimpleBox.generatePrivateKey();
    final byte[] publicKeyB = SimpleBox.generatePublicKey(privateKeyB);
    final SimpleBox boxA = new SimpleBox(publicKeyB, privateKeyA);
    final SimpleBox boxB = new SimpleBox(publicKeyA, privateKeyB);
    final byte[] c = boxA.seal(message);
    final Optional<byte[]> p = boxB.open(c);
    assertThat(p)
        .isNotEmpty()
        .contains(message);
  }

  @Test
  public void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> {
          final SimpleBox box = new SimpleBox(key);
          return box.open(box.seal(message)).map(v -> Arrays.equals(v, message)).orElse(false);
        });
  }

  @Test
  public void pkRoundTrip() throws Exception {
    qt().forAll(privateKeys(), privateKeys(), byteArrays(1, 4096))
        .check((privateKeyA, privateKeyB, message) -> {
          final byte[] publicKeyA = SecretBox.generatePublicKey(privateKeyA);
          final byte[] publicKeyB = SecretBox.generatePublicKey(privateKeyB);
          final SimpleBox boxA = new SimpleBox(publicKeyB, privateKeyA);
          final SimpleBox boxB = new SimpleBox(publicKeyA, privateKeyB);
          return boxB.open(boxA.seal(message)).map(p -> Arrays.equals(p, message)).orElse(false);
        });
  }

  @Test
  public void shortMessage() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 24))
        .check((key, message) -> !new SimpleBox(key).open(message).isPresent());
  }
}