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

import java.util.concurrent.TimeUnit;
import org.abstractj.kalium.crypto.SecretBox;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class KaliumBenchmarks {

  private static final byte[] key = new byte[32];
  private static final SecretBox box = new SecretBox(key);
  private static final byte[] nonce = new byte[24];
  private static final byte[] msg100 = new byte[100];
  private static final byte[] msg1K = new byte[1024];
  private static final byte[] msg10K = new byte[10 * 1024];

  @Benchmark
  public byte[] seal100Bytes() {
    return box.encrypt(nonce, msg100);
  }

  @Benchmark
  public byte[] seal1K() {
    return box.encrypt(nonce, msg1K);
  }

  @Benchmark
  public byte[] seal10K() {
    return box.encrypt(nonce, msg10K);
  }
}
