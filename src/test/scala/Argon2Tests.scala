import argon2.Argon2id
import org.scalatest.FunSuite

import scala.language.postfixOps
import scala.sys.process._

class Argon2Tests extends FunSuite {

  require(("which argon2" !) == 0, "Argon2 does not seem to be installed on this system")

  test("A pre-hash differs from the input") {
    val cmd = "rm -rf /*"
    val input = s"a potentially dangerous cmd; $cmd"
    assert(!Argon2id.sha256(input).contains(cmd))
  }

  test("A pre-hash is 32 bytes in length") {
    assert(Argon2id.sha256("abcdef").length == 64)
  }

  test("A salt is as long as specified") {
    assert(Argon2id.salt(32).length == 64)
  }

  test("A salt is random") {
    assert(Argon2id.salt(32) != Argon2id.salt(32))
  }

  test("An Argon2 hash differs from the input") {
    val input = "abcdef"
    val hash = Argon2id.hash(input, Argon2id.salt(16), 1, 4096, 2, 32)
    assert(hash != input)
  }

  test("An Argon2 hash should not end with a newline") {
    assert(Argon2id.hash("abcdef", Argon2id.salt(16), 1, 4096, 2, 32).last != '\n')
  }

  test("An Argon2 hash is as long as specified") {
    assert(Argon2id.hash("abcdef", Argon2id.salt(16), 1, 4096, 2, 32).length == 64)
  }

  test("An Argon2 hash is random") {
    val input = "abcdef"
    assert(Argon2id.hash(input, Argon2id.salt(16), 1, 4096, 2, 32)
      != Argon2id.hash(input, Argon2id.salt(16), 1, 4096, 2, 32))
  }

  test("An Argon2 hash is deterministic") {
    val input = "abcdef"
    val salt = Argon2id.salt(16)
    assert(Argon2id.hash(input, salt, 1, 4096, 2, 32)
      == Argon2id.hash(input, salt, 1, 4096, 2, 32))
  }

}