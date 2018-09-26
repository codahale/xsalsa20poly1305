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

import static com.codahale.xsalsa20poly1305.tests.Generators.privateKeys;
import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.xsalsa20poly1305.Keys;
import com.codahale.xsalsa20poly1305.SecretBox;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.quicktheories.WithQuickTheories;

class KeysTest implements WithQuickTheories {

  @Test
  void generateSecretKey() {
    final byte[] message = "this is a test".getBytes(StandardCharsets.UTF_8);
    final byte[] key = Keys.generateSecretKey();
    final SecretBox box = new SecretBox(key);
    final byte[] n = box.nonce(message);
    assertThat(box.open(n, box.seal(n, message))).contains(message);
  }

  @Test
  void generateKeyPair() {
    final byte[] privateKeyA = Keys.generatePrivateKey();
    final byte[] publicKeyA = Keys.generatePublicKey(privateKeyA);
    final byte[] privateKeyB = Keys.generatePrivateKey();
    final byte[] publicKeyB = Keys.generatePublicKey(privateKeyB);

    assertThat(Keys.sharedSecret(publicKeyB, privateKeyA))
        .isEqualTo(Keys.sharedSecret(publicKeyA, privateKeyB));
  }

  @Test
  void sharedSecrets() {
    qt().forAll(privateKeys(), privateKeys())
        .check(
            (privateKeyA, privateKeyB) -> {
              final byte[] publicKeyA = Keys.generatePublicKey(privateKeyA);
              final byte[] publicKeyB = Keys.generatePublicKey(privateKeyB);

              final byte[] secretAB = Keys.sharedSecret(publicKeyA, privateKeyB);
              final byte[] secretBA = Keys.sharedSecret(publicKeyB, privateKeyA);

              return Arrays.equals(secretAB, secretBA);
            });
  }
}
