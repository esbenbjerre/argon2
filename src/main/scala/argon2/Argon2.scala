package argon2

import java.security.{MessageDigest, SecureRandom}

import scala.language.{implicitConversions, postfixOps}
import scala.sys.process._

/**
  * Argon2 binding.
  * See [[https://github.com/P-H-C/phc-winner-argon2 argon2.Argon2]] for documentation.
  *
  * @param variant the variant (i, d, id)
  */
sealed abstract class Argon2(variant: String) {

  /**
    * Hashes an input using SHA256.
    *
    * @param input the input to hash
    * @return hexadecimal string
    */
  def sha256(input: String): String = {
    MessageDigest.getInstance("SHA-256")
      .digest(input.getBytes("UTF-8"))
      .map("%02x".format(_)).mkString
  }

  /**
    * Generates a cryptographically secure salt.
    *
    * @param byteLength the byte length of the salt
    * @return hexadecimal string
    */
  def salt(byteLength: Int): String = {
    val secureRandom = new SecureRandom()
    val salt: Array[Byte] = Array.ofDim[Byte](byteLength)
    secureRandom.nextBytes(salt)
    salt.map("%02x".format(_)).mkString
  }

  /**
    * Hashes an input using Argon2.
    *
    * @param input            the input to hash
    * @param salt             the salt to use
    * @param iterations       the number of iterations
    * @param memory           the amount of memory
    * @param threads          the number of threads
    * @param outputByteLength the byte length of the output
    * @return hexadecimal string
    */
  def hash(input: String, salt: String, iterations: Int, memory: Int, threads: Int, outputByteLength: Int): String = {
    (s"echo ${sha256(input)}" #| s"argon2 $salt -$variant -t $iterations -k $memory -p $threads -l $outputByteLength -r" !!).trim
  }

}

/**
  * Argon2i variant.
  */
case object Argon2i extends Argon2("i")

/**
  * Argon2d variant.
  */
case object Argon2d extends Argon2("d")

/**
  * Argon2id variant.
  */
case object Argon2id extends Argon2("id")