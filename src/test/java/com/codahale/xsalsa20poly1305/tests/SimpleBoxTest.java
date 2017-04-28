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

import static com.codahale.xsalsa20poly1305.tests.Generators.byteStrings;
import static com.codahale.xsalsa20poly1305.tests.Generators.privateKeys;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.quicktheories.quicktheories.QuickTheory.qt;

import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Optional;
import okio.ByteString;
import org.junit.jupiter.api.Test;

class SimpleBoxTest {

  @Test
  void generateSecretKey() throws Exception {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString key = SimpleBox.generateSecretKey();
    final SimpleBox box = new SimpleBox(key);
    final ByteString c = box.seal(message);
    final Optional<ByteString> p = box.open(c);
    assertEquals(message, p.orElseThrow(NullPointerException::new));
  }

  @Test
  void generateKeyPair() throws Exception {
    final ByteString message = ByteString.encodeUtf8("this is a test");
    final ByteString privateKeyA = SimpleBox.generatePrivateKey();
    final ByteString publicKeyA = SimpleBox.generatePublicKey(privateKeyA);
    final ByteString privateKeyB = SimpleBox.generatePrivateKey();
    final ByteString publicKeyB = SimpleBox.generatePublicKey(privateKeyB);
    final SimpleBox boxA = new SimpleBox(publicKeyB, privateKeyA);
    final SimpleBox boxB = new SimpleBox(publicKeyA, privateKeyB);
    final ByteString c = boxA.seal(message);
    final Optional<ByteString> p = boxB.open(c);
    assertEquals(message, p.orElseThrow(NullPointerException::new));
  }

  @Test
  void roundTrip() throws Exception {
    qt().forAll(byteStrings(32, 32), byteStrings(1, 4096))
        .check((key, message) -> {
          final SimpleBox box = new SimpleBox(key);
          return box.open(box.seal(message)).map(message::equals).orElse(false);
        });
  }

  @Test
  void pkRoundTrip() throws Exception {
    qt().forAll(privateKeys(), privateKeys(), byteStrings(1, 4096))
        .check((privateKeyA, privateKeyB, message) -> {
          final ByteString publicKeyA = SimpleBox.generatePublicKey(privateKeyA);
          final ByteString publicKeyB = SimpleBox.generatePublicKey(privateKeyB);
          final SimpleBox boxA = new SimpleBox(publicKeyB, privateKeyA);
          final SimpleBox boxB = new SimpleBox(publicKeyA, privateKeyB);
          return boxB.open(boxA.seal(message)).map(message::equals).orElse(false);
        });
  }

  @Test
  void shortMessage() throws Exception {
    qt().forAll(byteStrings(32, 32), byteStrings(1, 24))
        .check((key, message) -> !new SimpleBox(key).open(message).isPresent());
  }
}