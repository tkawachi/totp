package com.github.tkawachi.totp

import java.nio.ByteBuffer
import javax.crypto.spec.SecretKeySpec

/**
 * Time-Based One-Time password algorithm.
 * See RFC 6238.
 */
object TOTP {

  private[totp] implicit class StringExt(val s: String) extends AnyVal {
    def lpad(length: Int, char: Char): String =
      (char.toString * (length - s.size)) + s
  }

  private def hmacSha(algo: MacAlgorithm, keyBytes: Array[Byte], text: Array[Byte]): Array[Byte] = {
    val hmac = algo.getInstance()
    val macKey = new SecretKeySpec(keyBytes, "RAW")
    hmac.init(macKey)
    hmac.doFinal(text)
  }

  private final val DIGITS_POWER: Array[Int] = Array(
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
  )

  def generateString(key: Array[Byte], steps: Long, codeDigits: Int, algo: MacAlgorithm): String = {
    val otp = generate(key, steps, codeDigits, algo)
    otp.toString.lpad(codeDigits, '0')
  }

  def generate(key: Array[Byte], steps: Long, codeDigits: Int, algo: MacAlgorithm): Int = {
    val msg = long2Bytes(steps)
    val hash = hmacSha(algo, key, msg)
    val offset = hash.last & 0xf
    val binary = ((hash(offset) & 0x7f) << 24) |
      ((hash(offset + 1) & 0xff) << 16) |
      ((hash(offset + 2) & 0xff) << 8) |
      (hash(offset + 3) & 0xff)
    binary % DIGITS_POWER(codeDigits)
  }

  private[totp] def long2Bytes(l: Long): Array[Byte] = {
    val buf = ByteBuffer.allocate(8)
    buf.putLong(l)
    buf.array()
  }

}
