# argon2

A simple Scala wrapper around the [reference C implementation of Argon2](https://github.com/P-H-C/phc-winner-argon2).

## Usage

Use the hash method on any of the Argon2 variant objects. The provided input is pre-hashed using SHA256 to prevent arbitrary command execution.

```scala
def hash(input: String, salt: String, iterations: Int, memory: Int, threads: Int, outputByteLength: Int): String
```

## Example
```scala
scala> val salt = Argon2id.salt(16)
salt: String = bb96e54b1414f1b6cccf150c5006de7f

scala> val hash = Argon2id.hash("correct-horse-battery-staple", salt, 3, 4096, 8, 32)
hash: String = 558b68541016b7eb8b7f400386baf5bbc27aed2e01bcfedcb30c316991a8c25f
```