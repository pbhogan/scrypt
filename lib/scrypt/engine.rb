# frozen_string_literal: true

require 'ffi'
require 'openssl'

module SCrypt
  module Ext
    # rubocop:disable Style/SymbolArray
    # Bind the external functions
    attach_function :sc_calibrate,
                    [:size_t, :double, :double, :pointer],
                    :int,
                    blocking: true

    attach_function :crypto_scrypt,
                    [:pointer, :size_t, :pointer, :size_t, :uint64, :uint32, :uint32, :pointer, :size_t],
                    :int,
                    blocking: true # todo
    # rubocop:enable
  end

  class Engine
    # rubocop:disable Style/MutableConstant
    DEFAULTS = {
      key_len: 32,
      salt_size: 32,
      max_mem: 16 * 1024 * 1024,
      max_memfrac: 0.5,
      max_time: 0.2,
      cost: nil
    }
    # rubocop:enable

    class Calibration < FFI::Struct
      layout  :n, :uint64,
              :r, :uint32,
              :p, :uint32
    end

    class << self
      def scrypt(secret, salt, *args)
        if args.length == 2
          # args is [cost_string, key_len]
          n, r, p = args[0].split('$').map { |x| x.to_i(16) }
          key_len = args[1]

          __sc_crypt(secret, salt, n, r, p, key_len)
        elsif args.length == 4
          # args is [n, r, p, key_len]
          n, r, p = args[0, 3]
          key_len = args[3]

          __sc_crypt(secret, salt, n, r, p, key_len)
        else
          raise ArgumentError, 'invalid number of arguments (4 or 6)'
        end
      end

      # Given a secret and a valid salt (see SCrypt::Engine.generate_salt) calculates an scrypt password hash.
      def hash_secret(secret, salt, key_len = DEFAULTS[:key_len])
        raise Errors::InvalidSecret, 'invalid secret' unless valid_secret?(secret)
        raise Errors::InvalidSalt, 'invalid salt' unless valid_salt?(salt)

        cost = autodetect_cost(salt)
        salt_only = salt[/\$([A-Za-z0-9]{16,64})$/, 1]

        if salt_only.length == 40
          # Old-style hash with 40-character salt
          salt + '$' + Digest::SHA1.hexdigest(scrypt(secret.to_s, salt, cost, 256))
        else
          # New-style hash
          salt_only = [salt_only.sub(/^(00)+/, '')].pack('H*')
          salt + '$' + scrypt(secret.to_s, salt_only, cost, key_len).unpack('H*').first.rjust(key_len * 2, '0')
        end
      end

      # Generates a random salt with a given computational cost.  Uses a saved
      # cost if SCrypt::Engine.calibrate! has been called.
      #
      # Options:
      # <tt>:cost</tt> is a cost string returned by SCrypt::Engine.calibrate
      def generate_salt(options = {})
        options = DEFAULTS.merge(options)
        cost = options[:cost] || calibrate(options)
        salt = OpenSSL::Random.random_bytes(options[:salt_size]).unpack('H*').first.rjust(16, '0')

        if salt.length == 40
          # If salt is 40 characters, the regexp will think that it is an old-style hash, so add a '0'.
          salt = '0' + salt
        end
        cost + salt
      end

      # Returns true if +cost+ is a valid cost, false if not.
      def valid_cost?(cost)
        cost.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/) != nil
      end

      # Returns true if +salt+ is a valid salt, false if not.
      def valid_salt?(salt)
        salt.match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}$/) != nil
      end

      # Returns true if +secret+ is a valid secret, false if not.
      def valid_secret?(secret)
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
      def calibrate(options = {})
        options = DEFAULTS.merge(options)
        '%x$%x$%x$' % __sc_calibrate(options[:max_mem], options[:max_memfrac], options[:max_time])
      end

      # Calls SCrypt::Engine.calibrate and saves the cost string for future calls to
      # SCrypt::Engine.generate_salt.
      def calibrate!(options = {})
        DEFAULTS[:cost] = calibrate(options)
      end

      # Computes the memory use of the given +cost+
      def memory_use(cost)
        n, r, p = cost.split('$').map { |i| i.to_i(16) }
        (128 * r * p) + (256 * r) + (128 * r * n)
      end

      # Autodetects the cost from the salt string.
      def autodetect_cost(salt)
        salt[/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$/]
      end

      private

      def __sc_calibrate(max_mem, max_memfrac, max_time)
        result = nil

        calibration = Calibration.new
        ret_val = SCrypt::Ext.sc_calibrate(max_mem, max_memfrac, max_time, calibration)

        raise "calibration error #{result}" unless ret_val.zero?

        [calibration[:n], calibration[:r], calibration[:p]]
      end

      def __sc_crypt(secret, salt, n, r, p, key_len)
        result = nil

        FFI::MemoryPointer.new(:char, key_len) do |buffer|
          ret_val = SCrypt::Ext.crypto_scrypt(
            secret, secret.bytesize, salt, salt.bytesize,
            n, r, p,
            buffer, key_len
          )

          raise "scrypt error #{ret_val}" unless ret_val.zero?

          result = buffer.read_string(key_len)
        end

        result
      end
    end
  end
end
