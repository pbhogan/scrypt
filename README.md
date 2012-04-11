scrypt
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
include "scrypt"

# hash a user's password
@password = Password.create("my grand secret")
@password #=> "2000$8$1$f5f2fa5fe5484a7091f1299768fbe92b5a7fbc77$6a385f22c54d92c314b71a4fd5ef33967c93d679"

# store it safely
@user.update_attribute(:password, @password)

# read it back
@user.reload!
@db_password = Password.new(@user.password)

# compare it after retrieval
@db_password == "my grand secret" #=> true
@db_password == "a paltry guess"  #=> false
```

Password.create takes three options which will determine the cost limits of the computation:

* `:max_time` specifies the maximum number of seconds the computation should take.
* `:max_mem` specifies the maximum number of bytes the computation should take. A value of 0 specifies no upper limit. The minimum is always 1 MB.
* `:max_memfrac` specifies the maximum memory in a fraction of available resources to use. Any value equal to 0 or greater than 0.5 will result in 0.5 being used.

Default options will result in calculation time of approx. 200 ms with 1 MB memory use.
