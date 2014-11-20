package com.github.tkawachi.totp

import java.text.{ SimpleDateFormat, DateFormat }
import java.util.{ Date, TimeZone }

import com.github.tkawachi.totp.MacAlgorithm.{ HmacSHA512, HmacSHA256, HmacSHA1 }
import org.scalatest.FunSpec

class TOTPTest extends FunSpec {
  import TOTP._

  private def hexStr2Bytes(hex: String): Array[Byte] = {
    val bArray = BigInt("10" + hex, 16).toByteArray
    bArray.drop(1)
  }

  it("prints a table") {
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
      val steps = (t - T0) / X
      val fmtTime = String.format("%1$-11s", new java.lang.Long(t))
      val utcTime = df.format(new Date(t * 1000))

      println("|  " + fmtTime + "  |  " + utcTime +
        f"  | $steps%016X |" + generateString(hexStr2Bytes(seed), steps, 8, HmacSHA1) + "| SHA1   |")

      println("|  " + fmtTime + "  |  " + utcTime +
        f"  | $steps%016X |" + generateString(hexStr2Bytes(seed32), steps, 8, HmacSHA256) + "| SHA256 |")

      println("|  " + fmtTime + "  |  " + utcTime +
        f"  | $steps%016X |" + generateString(hexStr2Bytes(seed64), steps, 8, HmacSHA512) + "| SHA512 |")

      println("+---------------+-----------------------+" +
        "------------------+--------+--------+")
    }
  }
}
