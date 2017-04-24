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

import java.util.Arrays;
import java.util.StringJoiner;
import org.quicktheories.quicktheories.core.Source;
import org.whispersystems.curve25519.java.curve_sigs;

public interface Generators {

  static Source<byte[]> byteArrays(int minLength, int maxLength) {
    return Source.of((prng, step) -> {
      final byte[] bytes = new byte[prng.nextInt(minLength, maxLength)];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) prng.nextInt(0, 255);
      }
      return bytes;
    }).describedAs(Arrays::toString);
  }

  static Source<KeyPair> keyPairs() {
    return Source.of((prng, step) -> {
      final byte[] random = new byte[32];
      for (int i = 0; i < random.length; i++) {
        random[i] = (byte) prng.nextInt(0, 255);
      }
      final KeyPair pair = new KeyPair();
      pair.privateKey = generatePrivateKey(random);
      pair.publicKey = generatePublicKey(pair.privateKey);
      return pair;
    });
  }

  static byte[] generatePublicKey(byte[] privateKey) {
    final byte[] publicKey = new byte[32];
    curve_sigs.curve25519_keygen(publicKey, privateKey);
    return publicKey;
  }

  static byte[] generatePrivateKey(byte[] random) {
    final byte[] privateKey = new byte[32];
    System.arraycopy(random, 0, privateKey, 0, 32);
    privateKey[0] &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
    return privateKey;
  }

  class KeyPair {

    byte[] publicKey, privateKey;

    @Override
    public String toString() {
      return new StringJoiner(", ", this.getClass().getSimpleName() + "[", "]")
          .add("privateKey = " + Arrays.toString(privateKey))
          .add("publicKey = " + Arrays.toString(publicKey))
          .toString();
    }
  }
}
