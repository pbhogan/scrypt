# scrypt

A Ruby library providing a secure password hashing solution using the scrypt key derivation function.

[![Gem Version](https://badge.fury.io/rb/scrypt.svg)](https://badge.fury.io/rb/scrypt) [![Ruby](https://github.com/pbhogan/scrypt/actions/workflows/ruby.yml/badge.svg)](https://github.com/pbhogan/scrypt/actions/workflows/ruby.yml)

## About scrypt

The scrypt key derivation function is designed to be far more secure against hardware brute-force attacks than alternative functions such as PBKDF2 or bcrypt. It accomplishes this by being deliberately memory-intensive, making it expensive to implement in hardware.

**Key Features:**
- Memory-hard function that resists ASIC and FPGA attacks
- Configurable computational cost, memory usage, and parallelization
- Drop-in replacement for bcrypt in most applications
- Production-ready and battle-tested

**Resources:**
- [Original scrypt paper](http://www.tarsnap.com/scrypt.html)
- [GitHub repository](http://github.com/pbhogan/scrypt)

## Why you should use scrypt

![KDF comparison](https://github.com/tarcieri/scrypt/raw/modern-readme/kdf-comparison.png)

The designers of scrypt estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4,000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20,000 times greater than a similar attack against PBKDF2.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'scrypt'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install scrypt
```

## Basic Usage

The scrypt gem works similarly to ruby-bcrypt with a few minor differences, especially regarding the cost factor configuration.

```ruby
require "scrypt"

# Hash a user's password
password = SCrypt::Password.create("my grand secret")
# => "400$8$36$78f4ae6983f76119$37ec6ce55a2b928dc56ff9a7d0cdafbd7dbde49d9282c38a40b1434e88f24cf5"

# Compare passwords
password == "my grand secret" # => true
password == "a paltry guess"  # => false
```

### Configuration Options

`Password.create` accepts several options to customize the key length, salt size, and computational cost limits:

* **`:key_len`** - Length in bytes of the generated key. Default: 32 bytes (256 bits). Range: 16-512 bytes.
* **`:salt_size`** - Size in bytes of the random salt. Default: 32 bytes (256 bits). Range: 8-32 bytes.
* **`:max_time`** - Maximum computation time in seconds. Default: 0.2 seconds.
* **`:max_mem`** - Maximum memory usage in bytes. Default: 16 MB. Set to 0 for no limit (minimum 1 MB).
* **`:max_memfrac`** - Maximum memory as a fraction of available resources. Default: 0.5. Range: 0-0.5.
* **`:cost`** - Explicit cost string from `calibrate` method (e.g., `'400$8$19$'`). When provided, `max_*` options are ignored.

**Note:** Default options result in approximately 200ms computation time with 16 MB memory usage.

## Advanced Usage

### Engine Methods

The scrypt gem provides low-level access to the scrypt algorithm through the `SCrypt::Engine` class:

```ruby
require "scrypt"

# Calibrate scrypt parameters for your system
SCrypt::Engine.calibrate
# => "400$8$25$"

# Generate a salt with default parameters
salt = SCrypt::Engine.generate_salt
# => "400$8$26$b62e0f787a5fc373"

# Hash a secret with a specific salt
SCrypt::Engine.hash_secret("my grand secret", salt)
# => "400$8$26$b62e0f787a5fc373$0399ccd4fa26642d92741b17c366b7f6bd12ccea5214987af445d2bed97bc6a2"

# Calibrate with custom memory limits and save for future use
SCrypt::Engine.calibrate!(max_mem: 16 * 1024 * 1024)
# => "4000$8$4$"

# Subsequent salt generation will use the calibrated parameters
SCrypt::Engine.generate_salt
# => "4000$8$4$c6d101522d3cb045"
```

### Password Creation with Custom Options

```ruby
# Create password with custom parameters
password = SCrypt::Password.create("my secret", {
  key_len: 64,
  salt_size: 16,
  max_time: 0.5,
  max_mem: 32 * 1024 * 1024
})

# Create password with pre-calibrated cost
cost = SCrypt::Engine.calibrate(max_time: 0.1)
password = SCrypt::Password.create("my secret", cost: cost)
```

## Usage in Rails (and the like)

```ruby
## Usage in Rails (and similar frameworks)

# Store password safely in the user model
user.update_attribute(:password, SCrypt::Password.create("my grand secret"))

# Read it back later
user.reload!
password = SCrypt::Password.new(user.password)
password == "my grand secret" # => true
```

## Security Considerations

* **Memory Safety**: The scrypt algorithm requires significant memory, making it resistant to hardware-based attacks
* **Time-Memory Trade-off**: Higher memory requirements make it expensive to parallelize attacks
* **Parameter Selection**: Use `calibrate` to find optimal parameters for your system's performance requirements
* **Salt Generation**: Always use cryptographically secure random salts (handled automatically)

## Performance Tuning

The scrypt parameters can be tuned based on your security and performance requirements:

```ruby
# For high-security applications (slower)
password = SCrypt::Password.create("secret", max_time: 1.0, max_mem: 64 * 1024 * 1024)

# For faster authentication (less secure)
password = SCrypt::Password.create("secret", max_time: 0.1, max_mem: 8 * 1024 * 1024)

# Calibrate once and reuse parameters
SCrypt::Engine.calibrate!(max_time: 0.5)
# All subsequent Password.create calls will use these parameters
```

## Error Handling

The library raises specific exceptions for different error conditions:

```ruby
begin
  SCrypt::Password.new("invalid_hash_format")
rescue SCrypt::Errors::InvalidHash => e
  puts "Invalid hash format: #{e.message}"
end

begin
  SCrypt::Engine.hash_secret(nil, "salt")
rescue SCrypt::Errors::InvalidSecret => e
  puts "Invalid secret: #{e.message}"
end
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Acknowledgments

### Original scrypt Algorithm
- **Colin Percival** and **Tarsnap** for creating the scrypt key derivation function and providing the reference implementation
- The original scrypt paper: [Stronger Key Derivation via Sequential Memory-Hard Functions](http://www.tarsnap.com/scrypt.html)

### Core Collaborators

- **Patrick Hogan** ([@pbhogan](https://github.com/pbhogan))
- **Stephen von Takach** ([@stakach](https://github.com/stakach))
- **Rene van Paassen** ([@repagh](https://github.com/repagh))
- **Johanns Gregorian** ([@johanns](https://github.com/johanns))

### Special Thanks
- The Ruby community for testing and feedback
- Contributors who have submitted bug reports, feature requests, and patches
- The cryptography community for security reviews and recommendations

## License

This project is licensed under the BSD-3-Clause License - see the [COPYING](COPYING) file for details.
