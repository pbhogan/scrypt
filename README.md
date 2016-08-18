scrypt [![Build Status](https://secure.travis-ci.org/pbhogan/scrypt.svg)](http://travis-ci.org/pbhogan/scrypt)
======

The scrypt key derivation function is designed to be far more secure against hardware brute-force attacks than alternative functions such as PBKDF2 or bcrypt.

* http://www.tarsnap.com/scrypt.html
* http://github.com/pbhogan/scrypt

## Why you should use scrypt

![KDF comparison](https://github.com/tarcieri/scrypt/raw/modern-readme/kdf-comparison.png)

The designers of scrypt estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20000 times greater than a similar attack against PBKDF2.

## How to install scrypt

```
gem install scrypt
```

## How to use scrypt

It works pretty similarly to ruby-bcrypt with a few minor differences, especially where the cost factor is concerned.

```ruby
require "scrypt"

# hash a user's password
password = SCrypt::Password.create("my grand secret")
# => "400$8$36$78f4ae6983f76119$37ec6ce55a2b928dc56ff9a7d0cdafbd7dbde49d9282c38a40b1434e88f24cf5"

# compare to strings
password == "my grand secret" # => true
password == "a paltry guess"  # => false
```

Password.create takes five options which will determine the key length and salt size, as well as the cost limits of the computation:

* `:key_len` specifies the length in bytes of the key you want to generate. The default is 32 bytes (256 bits). Minimum is 16 bytes (128 bits). Maximum is 512 bytes (4096 bits).
* `:salt_size` specifies the size in bytes of the random salt you want to generate. The default and maximum is 32 bytes (256 bits). Minimum is 8 bytes (64 bits).
* `:max_time` specifies the maximum number of seconds the computation should take.
* `:max_mem` specifies the maximum number of bytes the computation should take. A value of 0 specifies no upper limit. The minimum is always 1 MB.
* `:max_memfrac` specifies the maximum memory in a fraction of available resources to use. Any value equal to 0 or greater than 0.5 will result in 0.5 being used.
* `:cost` specifies a cost string (e.g. `'400$8$19$'`) from the `calibrate` method.  The `:max_*` options will be ignored if this option is given, or if `calibrate!` has been called.

Default options will result in calculation time of approx. 200 ms with 16 MB memory use.

## Other things you can do

```ruby
require "scrypt"

SCrypt::Engine.calibrate
# => "400$8$25$"

salt = SCrypt::Engine.generate_salt
# => "400$8$26$b62e0f787a5fc373"

SCrypt::Engine.hash_secret "my grand secret", salt
# => "400$8$26$b62e0f787a5fc373$0399ccd4fa26642d92741b17c366b7f6bd12ccea5214987af445d2bed97bc6a2"

SCrypt::Engine.calibrate!(max_mem: 16 * 1024 * 1024)
# => "4000$8$4$"

SCrypt::Engine.generate_salt
# => "4000$8$4$c6d101522d3cb045"
```

## Usage in Rails (and the like)

```ruby
# store it safely in the user model
user.update_attribute(:password, SCrypt::Password.create("my grand secret"))

# read it back later
user.reload!
password = SCrypt::Password.new(user.password)
password == "my grand secret" # => true
```
