import argon2.Argon2id
import org.scalatest.FunSuite

class Argon2Tests extends FunSuite {

  test("A pre-hash differs from the input") {
    val input = "a potentially dangerous cmd; rm -rf /"
    assert(input != Argon2id.preHash(input))
  }

  test("A pre-hash is 32 bytes in length") {
    assert(Argon2id.preHash("abcdef").length == 64)
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