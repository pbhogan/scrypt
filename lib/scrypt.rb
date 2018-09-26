# A wrapper for the scrypt algorithm.

require "scrypt/scrypt_ext"
require "scrypt/security_utils"
require "openssl"
require "scanf"
require "ffi"


module SCrypt

  module Ext
    # Bind the external functions
    attach_function :sc_calibrate, [:size_t, :double, :double, :pointer], :int, :blocking => true
    attach_function :crypto_scrypt, [:pointer, :size_t, :pointer, :size_t, :uint64, :uint32, :uint32, :pointer, :size_t], :int, :blocking => true # todo
  end

  module Errors
    class InvalidSalt   < StandardError; end  # The salt parameter provided is invalid.
    class InvalidHash   < StandardError; end  # The hash parameter provided is invalid.
    class InvalidSecret < StandardError; end  # The secret parameter provided is invalid.
  end

  class Engine
    DEFAULTS = {
      :key_len     => 32,
      :salt_size   => 32,
      :max_mem     => 16 * 1024 * 1024,
      :max_memfrac => 0.5,
      :max_time    => 0.2,
      :cost        => nil
    }

    def self.scrypt(secret, salt, *args)
      if args.length == 2
        # args is [cost_string, key_len]
        n, r, p = args[0].split('$').map{ |x| x.to_i(16) }
        key_len = args[1]
        __sc_crypt(secret, salt, n, r, p, key_len)
      elsif args.length == 4
        # args is [n, r, p, key_len]
        n, r, p = args[0, 3]
        key_len = args[3]
        __sc_crypt(secret, salt, n, r, p, key_len)
      else
        raise ArgumentError.new("invalid number of arguments (4 or 6)")
      end
    end

    # Given a secret and a valid salt (see SCrypt::Engine.generate_salt) calculates an scrypt password hash.
    def self.hash_secret(secret, salt, key_len = DEFAULTS[:key_len])
      if valid_secret?(secret)
        if valid_salt?(salt)
          cost = autodetect_cost(salt)
          salt_only = salt[/\$([A-Za-z0-9]{16,64})$/, 1]
          if salt_only.length == 40
            # Old-style hash with 40-character salt
            salt + "$" + Digest::SHA1.hexdigest(scrypt(secret.to_s, salt, cost, 256))
          else
            # New-style hash
            salt_only = [salt_only.sub(/^(00)+/, '')].pack('H*')
            salt + "$" + scrypt(secret.to_s, salt_only, cost, key_len).unpack('H*').first.rjust(key_len * 2, '0')
          end
        else
          raise Errors::InvalidSalt.new("invalid salt")
        end
      else
        raise Errors::InvalidSecret.new("invalid secret")
      end
    end

    # Generates a random salt with a given computational cost.  Uses a saved
    # cost if SCrypt::Engine.calibrate! has been called.
    #
    # Options:
    # <tt>:cost</tt> is a cost string returned by SCrypt::Engine.calibrate
    def self.generate_salt(options = {})
      options = DEFAULTS.merge(options)
      cost = options[:cost] || calibrate(options)
      salt = OpenSSL::Random.random_bytes(options[:salt_size]).unpack('H*').first.rjust(16,'0')
      if salt.length == 40
        #If salt is 40 characters, the regexp will think that it is an old-style hash, so add a '0'.
        salt = '0' + salt
      end
      cost + salt
    end

    # Returns true if +cost+ is a valid cost, false if not.
    def self.valid_cost?(cost)
      cost.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/) != nil
    end

    # Returns true if +salt+ is a valid salt, false if not.
    def self.valid_salt?(salt)
      salt.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}$/) != nil
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
    #   SCrypt::Engine.calibrate(:max_time => 0.2)
    #
    def self.calibrate(options = {})
      options = DEFAULTS.merge(options)
      "%x$%x$%x$" % __sc_calibrate(options[:max_mem], options[:max_memfrac], options[:max_time])
    end
    
    # Calls SCrypt::Engine.calibrate and saves the cost string for future calls to
    # SCrypt::Engine.generate_salt.
    def self.calibrate!(options = {})
      DEFAULTS[:cost] = calibrate(options)
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

    private

    class Calibration < FFI::Struct
      layout  :n, :uint64,
              :r, :uint32,
              :p, :uint32
    end

    def self.__sc_calibrate(max_mem, max_memfrac, max_time)
      result = nil

      calibration = Calibration.new
      retval = SCrypt::Ext.sc_calibrate(max_mem, max_memfrac, max_time, calibration)

      if retval == 0
        result = [calibration[:n], calibration[:r], calibration[:p]]
      else
        raise "calibration error #{result}"
      end

      result
    end

    def self.__sc_crypt(secret, salt, n, r, p, key_len)
      result = nil

      FFI::MemoryPointer.new(:char, key_len) do |buffer|
        retval = SCrypt::Ext.crypto_scrypt(
          secret, secret.bytesize, salt, salt.bytesize,
          n, r, p,
          buffer, key_len
        )
        if retval == 0
          result = buffer.read_string(key_len)
        else
          raise "scrypt error #{retval}"
        end
      end

      result
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
        #Clamp minimum/maximum keylen
        options[:key_len] = 16 if options[:key_len] < 16
        options[:key_len] = 512 if options[:key_len] > 512
        #Clamp minimum/maximum salt_size
        options[:salt_size] = 8 if options[:salt_size] < 8
        options[:salt_size] = 32 if options[:salt_size] > 32
        salt = SCrypt::Engine.generate_salt(options)
        hash = SCrypt::Engine.hash_secret(secret, salt, options[:key_len])
        Password.new(hash)
      end
    end

    # Initializes a SCrypt::Password instance with the data from a stored hash.
    def initialize(raw_hash)
      if valid_hash?(raw_hash)
        self.replace(raw_hash)
        @cost, @salt, @digest = split_hash(self.to_s)
      else
        raise Errors::InvalidHash.new("invalid hash")
      end
    end

    # Compares a potential secret against the hash. Returns true if the secret is the original secret, false otherwise.
    def ==(secret)
      SecurityUtils.secure_compare(self, SCrypt::Engine.hash_secret(secret, @cost + @salt, self.digest.length / 2))
    end
    alias_method :is_password?, :==

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
      return [n, v, r].join('$') + "$", salt, hash
    end
  end
end
