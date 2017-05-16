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

package com.codahale.xsalsa20poly1305.benchmarks;

import com.codahale.xsalsa20poly1305.SecretBox;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import okio.ByteString;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class OurBenchmarks {

  @Param({"100", "1024", "10240"})
  private int size = 100;

  private SecretBox box;
  private SimpleBox simpleBox;
  private ByteString nonce;
  private ByteString plaintext;
  private ByteString boxCiphertext;
  private ByteString simpleCiphertext;

  @Setup
  public void setup() {
    this.box = new SecretBox(ByteString.of(new byte[32]));
    this.simpleBox = new SimpleBox(ByteString.of(new byte[32]));
    this.nonce = ByteString.of(new byte[24]);
    this.plaintext = ByteString.of(new byte[size]);
    this.boxCiphertext = box.seal(nonce, plaintext);
    this.simpleCiphertext = simpleBox.seal(plaintext);
  }

  @Benchmark
  public ByteString seal() {
    return box.seal(nonce, plaintext);
  }

  @Benchmark
  public Optional<ByteString> open() {
    return box.open(nonce, boxCiphertext);
  }

  @Benchmark
  public ByteString simpleSeal() {
    return simpleBox.seal(plaintext);
  }

  @Benchmark
  public Optional<ByteString> simpleOpen() {
    return simpleBox.open(simpleCiphertext);
  }
}
