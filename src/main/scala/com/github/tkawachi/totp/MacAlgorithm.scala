package com.github.tkawachi.totp

import javax.crypto.Mac

sealed abstract class MacAlgorithm(name: String) {
  def getInstance() = Mac.getInstance(name)
}

object MacAlgorithm {
  // https://docs.oracle.com/javase/jp/6/technotes/guides/security/StandardNames.html#Mac
  object HmacMD5 extends MacAlgorithm("HmacMD5")
  object HmacSHA1 extends MacAlgorithm("HmacSHA1")
  object HmacSHA256 extends MacAlgorithm("HmacSHA256")
  object HmacSHA384 extends MacAlgorithm("HmacSHA384")
  object HmacSHA512 extends MacAlgorithm("HmacSHA512")
}
