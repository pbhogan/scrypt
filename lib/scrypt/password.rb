# frozen_string_literal: true

module SCrypt
  # A password management class which allows you to safely store users' passwords and compare them.
  #
  # Example usage:
  #
  #   include "scrypt"
  #
  #   # hash a user's password
  #   @password = Password.create("my grand secret")
  #   @password #=> "2000$8$1$f5f2fa5fe5484a7091f1299768fbe92b5a7fbc77$6a385f22c54d92c314b71a4fd5ef33967c93d679"
  #
  #   # store it safely
  #   @user.update_attribute(:password, @password)
  #
  #   # read it back
  #   @user.reload!
  #   @db_password = Password.new(@user.password)
  #
  #   # compare it after retrieval
  #   @db_password == "my grand secret" #=> true
  #   @db_password == "a paltry guess"  #=> false
  #
  class Password < String
    # The hash portion of the stored password hash.
    attr_reader :digest
    # The salt of the store password hash
    attr_reader :salt
    # The cost factor used to create the hash.
    attr_reader :cost

    class << self
      # Hashes a secret, returning a SCrypt::Password instance.
      # Takes five options (optional), which will determine the salt/key's length and the cost limits of the computation.
      # <tt>:key_len</tt> specifies the length in bytes of the key you want to generate. The default is 32 bytes (256 bits). Minimum is 16 bytes (128 bits). Maximum is 512 bytes (4096 bits).
      # <tt>:salt_size</tt> specifies the size in bytes of the random salt you want to generate. The default and minimum is 8 bytes (64 bits). Maximum is 32 bytes (256 bits).
      # <tt>:max_time</tt> specifies the maximum number of seconds the computation should take.
      # <tt>:max_mem</tt> specifies the maximum number of bytes the computation should take. A value of 0 specifies no upper limit. The minimum is always 1 MB.
      # <tt>:max_memfrac</tt> specifies the maximum memory in a fraction of available resources to use. Any value equal to 0 or greater than 0.5 will result in 0.5 being used.
      # The scrypt key derivation function is designed to be far more secure against hardware brute-force attacks than alternative functions such as PBKDF2 or bcrypt.
      # The designers of scrypt estimate that on modern (2009) hardware, if 5 seconds are spent computing a derived key, the cost of a hardware brute-force attack against scrypt is roughly 4000 times greater than the cost of a similar attack against bcrypt (to find the same password), and 20000 times greater than a similar attack against PBKDF2.
      # Default options will result in calculation time of approx. 200 ms with 1 MB memory use.
      #
      # Example:
      #   @password = SCrypt::Password.create("my secret", :max_time => 0.25)
      #
      def create(secret, options = {})
        options = SCrypt::Engine::DEFAULTS.merge(options)

        # Clamp minimum/maximum keylen
        options[:key_len] = 16 if options[:key_len] < 16
        options[:key_len] = 512 if options[:key_len] > 512

        # Clamp minimum/maximum salt_size
        options[:salt_size] = 8 if options[:salt_size] < 8
        options[:salt_size] = 32 if options[:salt_size] > 32

        salt = SCrypt::Engine.generate_salt(options)
        hash = SCrypt::Engine.hash_secret(secret, salt, options[:key_len])

        Password.new(hash)
      end
    end

    # Initializes a SCrypt::Password instance with the data from a stored hash.
    def initialize(raw_hash)
      raise Errors::InvalidHash, 'invalid hash' unless valid_hash?(raw_hash)

      replace(raw_hash)

      @cost, @salt, @digest = split_hash(to_s)
    end

    # Compares a potential secret against the hash. Returns true if the secret is the original secret, false otherwise.
    def ==(other)
      SecurityUtils.secure_compare(self, SCrypt::Engine.hash_secret(other, @cost + @salt, digest.length / 2))
    end
    alias is_password? ==

    private

    # Returns true if +h+ is a valid hash.
    def valid_hash?(h)
      h.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}\$[A-Za-z0-9]{32,1024}$/) != nil
    end

    # call-seq:
    #   split_hash(raw_hash) -> cost, salt, hash
    #
    # Splits +h+ into cost, salt, and hash and returns them in that order.
    def split_hash(h)
      n, v, r, salt, hash = h.split('$')
      [[n, v, r].join('$') + '$', salt, hash]
    end
  end
end
