# frozen_string_literal: true

module TestHelpers
  # Common test data
  VALID_SECRETS = [
    'simple_password',
    'complex_password_123!@#',
    '',
    'unicode_tésting',
    '🔒secure🔑'
  ].freeze

  INVALID_HASH_FORMATS = [
    '',
    'invalid',
    '400$8$d$invalid',
    '400$8$d$173a8189751c095a29b933789560b73bf17b2e01',
    '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$'
  ].freeze

  INVALID_SALT_FORMATS = [
    '',
    'invalid',
    'nino',
    '400$8$d$'
  ].freeze

  # Helper methods
  def self.generate_test_password(secret = 'test_secret', options = {})
    default_options = { max_time: 0.05 }
    SCrypt::Password.create(secret, default_options.merge(options))
  end

  def self.generate_test_salt(options = {})
    default_options = { max_time: 0.05 }
    SCrypt::Engine.generate_salt(default_options.merge(options))
  end

  def self.reset_calibration
    SCrypt::Engine.calibrated_cost = nil
  end
end

# Include helper methods in RSpec
RSpec.configure do |config|
  config.include TestHelpers
end
