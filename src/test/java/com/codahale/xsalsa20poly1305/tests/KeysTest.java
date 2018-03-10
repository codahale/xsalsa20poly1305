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
import okio.ByteString;
import org.junit.jupiter.api.Test;
import org.quicktheories.WithQuickTheories;

class KeysTest implements WithQuickTheories {

  @Test
  void generateSecretKey() {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString key = Keys.generateSecretKey();
    final SecretBox box = new SecretBox(key);
    final ByteString n = box.nonce(message);
    assertThat(box.open(n, box.seal(n, message))).contains(message);
  }

  @Test
  void generateKeyPair() {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString privateKeyA = Keys.generatePrivateKey();
    final ByteString publicKeyA = Keys.generatePublicKey(privateKeyA);
    final ByteString privateKeyB = Keys.generatePrivateKey();
    final ByteString publicKeyB = Keys.generatePublicKey(privateKeyB);
    final SecretBox boxA = new SecretBox(publicKeyB, privateKeyA);
    final SecretBox boxB = new SecretBox(publicKeyA, privateKeyB);
    final ByteString n = boxA.nonce(message);
    assertThat(boxB.open(n, boxA.seal(n, message))).contains(message);
  }

  @Test
  void sharedSecrets() {
    qt().forAll(privateKeys(), privateKeys())
        .check(
            (privateKeyA, privateKeyB) -> {
              final ByteString publicKeyA = Keys.generatePublicKey(privateKeyA);
              final ByteString publicKeyB = Keys.generatePublicKey(privateKeyB);

              final ByteString secretAB = Keys.sharedSecret(publicKeyA, privateKeyB);
              final ByteString secretBA = Keys.sharedSecret(publicKeyB, privateKeyA);

              return secretAB.equals(secretBA);
            });
  }
}
