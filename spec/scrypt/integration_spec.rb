# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'SCrypt Integration Tests' do
  describe 'Full password lifecycle' do
    let(:secret) { 'my_super_secret_password' }
    let(:options) { { max_time: 0.1, max_mem: 8 * 1024 * 1024 } }

    it 'create,s store, and verify passwords correctly' do
      # Create password
      password = SCrypt::Password.create(secret, options)
      expect(password).to be_a(SCrypt::Password)
      expect(password.to_s).to match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]+\$[A-Za-z0-9]+$/)

      # Verify password
      expect(password == secret).to be(true)
      expect(password == 'wrong_password').to be(false)

      # Re-instantiate from stored hash
      stored_hash = password.to_s
      recovered_password = SCrypt::Password.new(stored_hash)

      expect(recovered_password == secret).to be(true)
      expect(recovered_password == 'wrong_password').to be(false)
    end

    it 'handles calibration workflow correctly' do
      # Calibrate for fast testing
      cost = SCrypt::Engine.calibrate!(max_time: 0.05)
      expect(cost).to match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/)

      # Generate salt using calibrated cost
      salt = SCrypt::Engine.generate_salt
      expect(salt).to start_with(cost)

      # Hash secret with calibrated parameters
      hash = SCrypt::Engine.hash_secret(secret, salt)
      expect(hash).to be_a(String)
      expect(hash).to include(salt)

      # Verify the hash
      password = SCrypt::Password.new(hash)
      expect(password == secret).to be(true)

      # Reset calibration
      SCrypt::Engine.calibrated_cost = nil
    end
  end

  describe 'Cross-compatibility tests' do
    it 'is compatible between Engine and Password classes' do
      # Create using Password class
      password1 = SCrypt::Password.create('test_secret', max_time: 0.05)

      # Extract components and recreate using Engine
      cost = password1.cost
      salt_with_cost = cost + password1.salt
      hash2 = SCrypt::Engine.hash_secret('test_secret', salt_with_cost, password1.digest.length / 2)

      # Both should verify the same secret
      password2 = SCrypt::Password.new(hash2)
      expect(password1 == 'test_secret').to be(true)
      expect(password2 == 'test_secret').to be(true)
    end
  end

  describe 'Edge cases and error conditions' do
    it 'handles various secret types' do
      # String secret
      password1 = SCrypt::Password.create('string_secret', max_time: 0.05)
      expect(password1 == 'string_secret').to be(true)

      # Symbol secret
      password2 = SCrypt::Password.create(:symbol_secret, max_time: 0.05)
      expect(password2 == 'symbol_secret').to be(true)

      # Numeric secret
      password3 = SCrypt::Password.create(12_345, max_time: 0.05)
      expect(password3 == '12345').to be(true)

      # Boolean secret
      password4 = SCrypt::Password.create(false, max_time: 0.05)
      expect(password4 == 'false').to be(true)
    end

    it 'handles empty and nil secrets safely' do
      # Empty string
      password1 = SCrypt::Password.create('', max_time: 0.05)
      expect(password1 == '').to be(true)

      # Nil (converts to empty string)
      password2 = SCrypt::Password.create(nil, max_time: 0.05)
      expect(password2 == '').to be(true)
    end

    it 'validates input parameters' do
      # Invalid hash format
      expect { SCrypt::Password.new('invalid_hash') }.to raise_error(SCrypt::Errors::InvalidHash)

      # Invalid salt
      expect { SCrypt::Engine.hash_secret('secret', 'invalid_salt') }.to raise_error(SCrypt::Errors::InvalidSalt)
    end
  end

  describe 'Performance and memory tests' do
    it 'respects memory and time constraints' do
      start_time = Time.now

      # Use very low constraints for fast testing
      password = SCrypt::Password.create('test', max_time: 0.01, max_mem: 1024 * 1024)

      elapsed_time = Time.now - start_time

      # Should complete reasonably quickly (allowing some overhead)
      expect(elapsed_time).to be < 1.0
      expect(password == 'test').to be(true)
    end

    it 'calculates memory usage correctly' do
      cost = SCrypt::Engine.calibrate(max_time: 0.05)
      memory_usage = SCrypt::Engine.memory_use(cost)

      # Memory usage should be a reasonable number
      expect(memory_usage).to be > 0
      expect(memory_usage).to be < 100 * 1024 * 1024 # Less than 100MB
    end
  end
end
