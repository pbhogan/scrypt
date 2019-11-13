# frozen_string_literal: true

# NOTE:: a verbatim copy of https://github.com/rails/rails/blob/c8c660002f4b0e9606de96325f20b95248b6ff2d/activesupport/lib/active_support/security_utils.rb
# Please see the Rails license: https://github.com/rails/rails/blob/master/activesupport/MIT-LICENSE

module SCrypt
  module SecurityUtils
    # Constant time string comparison.
    #
    # The values compared should be of fixed length, such as strings
    # that have already been processed by HMAC. This should not be used
    # on variable length plaintext strings because it could leak length info
    # via timing attacks.
    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res.zero?
    end
  end
end
