package com.github.tkawachi.totp

import java.text.{ DateFormat, SimpleDateFormat }
import java.util.{ Date, TimeZone }
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import scala.util.Try

/**
 * Time-Based One-Time password algorithm.
 * See RFC 6238.
 */
object TOTP {
  val HMAC_SHA1 = "HmacSHA1"
  val HMAC_SHA256 = "HmacSHA256"
  val HMAC_SHA512 = "HmacSHA512"

  implicit class StringExt(val s: String) extends AnyVal {
    def padPrefix(length: Int, char: Char): String =
      (char.toString * (length - s.size)) + s
  }

  private def hmacSha(crypto: String, keyBytes: Array[Byte], text: Array[Byte]): Try[Array[Byte]] = Try {
    val hmac = Mac.getInstance(crypto)
    val macKey = new SecretKeySpec(keyBytes, "RAW")
    hmac.init(macKey)
    hmac.doFinal(text)
  }

  private def hexStr2Bytes(hex: String): Array[Byte] = {
    val bArray = BigInt("10" + hex, 16).toByteArray
    bArray.drop(1)
  }

  private final val DIGITS_POWER: Array[Int] = Array(
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
  )

  def generateTOTP(key: String, time: String, codeDigits: Int): Try[String] =
    generateTOTP(key, time, codeDigits, HMAC_SHA1)

  def generateTOTP256(key: String, time: String, codeDigits: Int): Try[String] =
    generateTOTP(key, time, codeDigits, HMAC_SHA256)

  def generateTOTP512(key: String, time: String, codeDigits: Int): Try[String] =
    generateTOTP(key, time, codeDigits, HMAC_SHA512)

  def generateTOTP(key: String, time: String, codeDigits: Int, crypto: String): Try[String] = {
    val paddedTime = time.padPrefix(16, '0')
    val msg = hexStr2Bytes(paddedTime)
    val k = hexStr2Bytes(key)
    for {
      hash <- hmacSha(crypto, k, msg)
    } yield {
      val offset = hash.last & 0xf
      val binary = ((hash(offset) & 0x7f) << 24) |
        ((hash(offset + 1) & 0xff) << 16) |
        ((hash(offset + 2) & 0xff) << 8) |
        (hash(offset + 3) & 0xff)
      val otp: Int = binary % DIGITS_POWER(codeDigits)
      otp.toString.padPrefix(codeDigits, '0')
    }
  }

  // TODO move to test
  def main(args: Array[String]) {
    val seed = "3132333435363738393031323334353637383930"
    val seed32 = "3132333435363738393031323334353637383930" +
      "313233343536373839303132"
    val seed64 = "3132333435363738393031323334353637383930" +
      "3132333435363738393031323334353637383930" +
      "3132333435363738393031323334353637383930" +
      "31323334"
    val T0 = 0L
    val X = 30L
    val testTime = Array(59L, 1111111109L, 1111111111L,
      1234567890L, 2000000000L, 20000000000L)
    val df: DateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    df.setTimeZone(TimeZone.getTimeZone("UTC"))

    println("+---------------+-----------------------+" +
      "------------------+--------+--------+")
    println("|  Time(sec)    |   Time (UTC format)   " +
      "| Value of T(Hex)  |  TOTP  | Mode   |")
    println("+---------------+-----------------------+" +
      "------------------+--------+--------+")
    for (t <- testTime) {
      val T = (t - T0) / X
      val steps = T.toHexString.toUpperCase.padPrefix(16, '0')
      val fmtTime = String.format("%1$-11s", new java.lang.Long(t))
      val utcTime = df.format(new Date(t * 1000))
      for (totp <- generateTOTP(seed, steps, 8, "HmacSHA1")) {
        println("|  " + fmtTime + "  |  " + utcTime +
          "  | " + steps + " |" + totp + "| SHA1   |")
      }
      for (totp <- generateTOTP256(seed32, steps, 8)) {
        println("|  " + fmtTime + "  |  " + utcTime +
          "  | " + steps + " |" + totp + "| SHA256 |")
      }
      for (totp <- generateTOTP512(seed64, steps, 8)) {
        println("|  " + fmtTime + "  |  " + utcTime +
          "  | " + steps + " |" + totp + "| SHA512 |")
      }
      println("+---------------+-----------------------+" +
        "------------------+--------+--------+")
    }
  }
}
