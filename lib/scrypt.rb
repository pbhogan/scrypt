# A wrapper for the scrypt algorithm.

$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(__FILE__), "..", "ext", "mri")))
require "scrypt_ext"
require "openssl"
require "digest/sha1"
require "scanf"


module SCrypt

  module Errors
    class InvalidSalt   < StandardError; end  # The salt parameter provided is invalid.
    class InvalidHash   < StandardError; end  # The hash parameter provided is invalid.
    class InvalidSecret < StandardError; end  # The secret parameter provided is invalid.
  end

  class Engine
    DEFAULTS = {
      :key_len => 32,
      :max_mem => 1024 * 1024,
      :max_memfrac => 0.5,
      :max_time => 0.2
    }

    private_class_method :__sc_calibrate
    private_class_method :__sc_crypt

    # Given a secret and a valid salt (see SCrypt::Engine.generate_salt) calculates an scrypt password hash.
    def self.hash_secret(secret, salt, key_len = 32)
      if valid_secret?(secret)
        if valid_salt?(salt)
          cost = autodetect_cost(salt)
          if salt[-17,1] == "$" #Shorter salt means newer-style hash.
            salt + "$" + __sc_crypt(secret.to_s, salt, cost, key_len).unpack('H*').first.rjust(key_len * 2, '0')
          else #Longer salt means legacy-style hash.
            salt + "$" + Digest::SHA1.hexdigest(__sc_crypt(secret.to_s, salt, cost, 256))
          end
        else
          raise Errors::InvalidSalt.new("invalid salt")
        end
      else
        raise Errors::InvalidSecret.new("invalid secret")
      end
    end

    # Generates a random salt with a given computational cost.
    def self.generate_salt(options = {})
      options = DEFAULTS.merge(options)
      cost = calibrate(options)
      salt = OpenSSL::Random.random_bytes(8).unpack('H*').first.rjust(16,'0')
      cost + salt
    end

    # Returns true if +cost+ is a valid cost, false if not.
    def self.valid_cost?(cost)
      cost.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/) != nil
    end

    # Returns true if +salt+ is a valid salt, false if not.
    def self.valid_salt?(salt)
      salt.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,}$/) != nil
    end

    # Returns true if +secret+ is a valid secret, false if not.
    def self.valid_secret?(secret)
      secret.respond_to?(:to_s)
    end

    # Returns the cost value which will result in computation limits less than the given options.
    #
    # Options:
    # <tt>:max_time</tt> specifies the maximum number of seconds the computation should take.
    # <tt>:max_mem</tt> specifies the maximum number of bytes the computation should take. A value of 0 specifies no upper limit. The minimum is always 1 MB.
    # <tt>:max_memfrac</tt> specifies the maximum memory in a fraction of available resources to use. Any value equal to 0 or greater than 0.5 will result in 0.5 being used.
    #
    # Example:
    #
    #   # should take less than 200ms
    #   SCrypt.calibrate(:max_time => 0.2)
    #
    def self.calibrate(options = {})
      options = DEFAULTS.merge(options)
      __sc_calibrate(options[:max_mem], options[:max_memfrac], options[:max_time])
    end

    # Computes the memory use of the given +cost+
    def self.memory_use(cost)
      n, r, p = cost.scanf("%x$%x$%x$")
      (128 * r * p) + (256 * r) + (128 * r * n);
    end

    # Autodetects the cost from the salt string.
    def self.autodetect_cost(salt)
      salt[/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$/]
    end
  end

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
    attr_reader :hash
    # The salt of the store password hash
    attr_reader :salt
    # The cost factor used to create the hash.
    attr_reader :cost

    class << self
      # Hashes a secret, returning a SCrypt::Password instance.
      # Takes four options (optional), which will determine the key's length and the cost limits of the computation.
      # <tt>:key_len</tt> specifies the length in bytes of the key you want to generate. The default is 32 bytes (256 bits).
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
        #Clamp minimum key_len to 20 bytes for sanity and so the RegExp will always detect them.
        options[:key_len] = 20 if options[:key_len] < 20
        salt = SCrypt::Engine.generate_salt(options)
        hash = SCrypt::Engine.hash_secret(secret, salt, options[:key_len])
        Password.new(hash)
      end
    end

    # Initializes a SCrypt::Password instance with the data from a stored hash.
    def initialize(raw_hash)
      if valid_hash?(raw_hash)
        self.replace(raw_hash)
        @cost, @salt, @hash = split_hash(self.to_s)
      else
        raise Errors::InvalidHash.new("invalid hash")
      end
    end

    # Compares a potential secret against the hash. Returns true if the secret is the original secret, false otherwise.
    def ==(secret)
      super(SCrypt::Engine.hash_secret(secret, @cost + @salt, self.hash.length / 2))
    end
    alias_method :is_password?, :==

  private
    # Returns true if +h+ is a valid hash.
    def valid_hash?(h)
      h.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,}\$[A-Za-z0-9]{20,}$/) != nil
    end

    # call-seq:
    #   split_hash(raw_hash) -> cost, salt, hash
    #
    # Splits +h+ into cost, salt, and hash and returns them in that order.
    def split_hash(h)
      n, v, r, salt, hash = h.split('$')
      return [n, v, r].join('$') + "$", salt, hash
    end
  end
end
