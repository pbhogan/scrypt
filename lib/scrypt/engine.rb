# frozen_string_literal: true

require 'ffi'
require 'openssl'

module SCrypt
  module Ext
    # Bind the external functions
    attach_function :sc_calibrate,
                    %i[size_t double double pointer],
                    :int,
                    blocking: true

    attach_function :crypto_scrypt,
                    %i[pointer size_t pointer size_t uint64 uint32 uint32 pointer size_t],
                    :int,
                    blocking: true # Use blocking: true for CPU-intensive operations to avoid GIL issues
  end

  class Engine
    # Regular expressions for validation
    COST_PATTERN = /^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/.freeze
    SALT_PATTERN = /^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}$/.freeze
    HASH_PATTERN = /^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}\$[A-Za-z0-9]{32,1024}$/.freeze

    # Constants for salt handling
    OLD_STYLE_SALT_LENGTH = 40
    SALT_MIN_LENGTH = 16

    DEFAULTS = {
      key_len: 32,
      salt_size: 32,
      max_mem: 16 * 1024 * 1024,
      max_memfrac: 0.5,
      max_time: 0.2,
      cost: nil
    }.freeze

    # Class variable to store calibrated cost, separate from defaults
    @calibrated_cost = nil

    class << self
      attr_accessor :calibrated_cost
    end

    class Calibration < FFI::Struct
      layout  :n, :uint64,
              :r, :uint32,
              :p, :uint32
    end

    class << self
      def scrypt(secret, salt, *args)
        case args.length
        when 2
          # args is [cost_string, key_len]
          cost_string, key_len = args
          cpu_cost, memory_cost, parallelization = parse_cost_string(cost_string)
          __sc_crypt(secret, salt, cpu_cost, memory_cost, parallelization, key_len)
        when 4
          # args is [n, r, p, key_len]
          cpu_cost, memory_cost, parallelization, key_len = args
          __sc_crypt(secret, salt, cpu_cost, memory_cost, parallelization, key_len)
        else
          raise ArgumentError, 'invalid number of arguments (4 or 6)'
        end
      end

      # Given a secret and a valid salt (see SCrypt::Engine.generate_salt) calculates an scrypt password hash.
      def hash_secret(secret, salt, key_len = DEFAULTS[:key_len])
        raise Errors::InvalidSecret, 'invalid secret' unless valid_secret?(secret)
        raise Errors::InvalidSalt, 'invalid salt' unless valid_salt?(salt)

        cost = autodetect_cost(salt)
        salt_only = extract_salt_from_string(salt)

        if old_style_hash?(salt_only)
          generate_old_style_hash(secret, salt, cost)
        else
          generate_new_style_hash(secret, salt, salt_only, cost, key_len)
        end
      end

      # Generates a random salt with a given computational cost.  Uses a saved
      # cost if SCrypt::Engine.calibrate! has been called.
      #
      # Options:
      # <tt>:cost</tt> is a cost string returned by SCrypt::Engine.calibrate
      def generate_salt(options = {})
        options = DEFAULTS.merge(options)
        cost = options[:cost] || @calibrated_cost || calibrate(options)
        salt = OpenSSL::Random.random_bytes(options[:salt_size]).unpack('H*').first.rjust(SALT_MIN_LENGTH, '0')

        salt = avoid_old_style_collision(salt)
        cost + salt
      end

      # Returns true if +cost+ is a valid cost, false if not.
      def valid_cost?(cost)
        !COST_PATTERN.match(cost).nil?
      end

      # Returns true if +salt+ is a valid salt, false if not.
      def valid_salt?(salt)
        !SALT_PATTERN.match(salt).nil?
      end

      # Returns true if +secret+ is a valid secret, false if not.
      def valid_secret?(secret)
        secret.respond_to?(:to_s)
      end

      # Returns the cost value which will result in computation limits less than the given options.
      #
      # Options:
      # <tt>:max_time</tt> specifies the maximum number of seconds the computation should take.
      # <tt>:max_mem</tt> specifies the maximum number of bytes the computation should take.
      # A value of 0 specifies no upper limit. The minimum is always 1 MB.
      # <tt>:max_memfrac</tt> specifies the maximum memory in a fraction of available resources to use.
      # Any value equal to 0 or greater than 0.5 will result in 0.5 being used.
      #
      # Example:
      #
      #   # should take less than 200ms
      #   SCrypt::Engine.calibrate(:max_time => 0.2)
      #
      def calibrate(options = {})
        options = DEFAULTS.merge(options)
        '%x$%x$%x$' % __sc_calibrate(options[:max_mem], options[:max_memfrac], options[:max_time])
      end

      # Calls SCrypt::Engine.calibrate and saves the cost string for future calls to
      # SCrypt::Engine.generate_salt.
      def calibrate!(options = {})
        @calibrated_cost = calibrate(options)
      end

      # Computes the memory use of the given +cost+
      def memory_use(cost)
        cpu_cost, memory_cost, parallelization = parse_cost_string(cost)
        (128 * memory_cost * parallelization) + (256 * memory_cost) + (128 * memory_cost * cpu_cost)
      end

      # Autodetects the cost from the salt string.
      def autodetect_cost(salt)
        salt[/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$/]
      end

      private

      # Extracts the salt portion from a salt string
      def extract_salt_from_string(salt)
        salt[/\$([A-Za-z0-9]{16,64})$/, 1]
      end

      # Checks if this is an old-style hash based on salt length
      def old_style_hash?(salt_only)
        salt_only.length == OLD_STYLE_SALT_LENGTH
      end

      # Generates old-style hash with SHA1
      def generate_old_style_hash(secret, salt, cost)
        "#{salt}$#{Digest::SHA1.hexdigest(scrypt(secret.to_s, salt, cost, 256))}"
      end

      # Generates new-style hash
      def generate_new_style_hash(secret, salt, salt_only, cost, key_len)
        processed_salt = [salt_only.sub(/^(00)+/, '')].pack('H*')
        hash_bytes = scrypt(secret.to_s, processed_salt, cost, key_len)
        "#{salt}$#{hash_bytes.unpack('H*').first.rjust(key_len * 2, '0')}"
      end

      # Avoids collision with old-style hash detection
      def avoid_old_style_collision(salt)
        if salt.length == OLD_STYLE_SALT_LENGTH
          # If salt is 40 characters, the regexp will think that it is an old-style hash, so add a '0'.
          "0#{salt}"
        else
          salt
        end
      end

      # Parses a cost string into its component values
      def parse_cost_string(cost_string)
        cost_string.split('$').map { |component| component.to_i(16) }
      end

      def __sc_calibrate(max_mem, max_memfrac, max_time)
        raise ArgumentError, 'max_mem must be non-negative' if max_mem.negative?
        raise ArgumentError, 'max_memfrac must be between 0 and 1' unless (0..1).cover?(max_memfrac)
        raise ArgumentError, 'max_time must be positive' if max_time <= 0

        calibration = Calibration.new
        ret_val = SCrypt::Ext.sc_calibrate(max_mem, max_memfrac, max_time, calibration)

        raise "calibration error: return value #{ret_val}" unless ret_val.zero?

        [calibration[:n], calibration[:r], calibration[:p]]
      end

      def __sc_crypt(secret, salt, cpu_cost, memory_cost, parallelization, key_len)
        raise ArgumentError, 'secret cannot be nil' if secret.nil?
        raise ArgumentError, 'salt cannot be nil' if salt.nil?
        raise ArgumentError, 'key_len must be positive' if key_len <= 0
        raise ArgumentError, 'cpu_cost must be positive' if cpu_cost <= 0
        raise ArgumentError, 'memory_cost must be positive' if memory_cost <= 0
        raise ArgumentError, 'parallelization must be positive' if parallelization <= 0

        result = nil

        FFI::MemoryPointer.new(:char, key_len) do |buffer|
          ret_val = SCrypt::Ext.crypto_scrypt(
            secret, secret.bytesize, salt, salt.bytesize,
            cpu_cost, memory_cost, parallelization,
            buffer, key_len
          )

          raise "scrypt error: return value #{ret_val}" unless ret_val.zero?

          result = buffer.read_string(key_len)
        end

        result
      end
    end
  end
end
