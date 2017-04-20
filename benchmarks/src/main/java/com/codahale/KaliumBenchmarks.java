package com.codahale;

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
