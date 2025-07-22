# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'The SCrypt engine' do
  it 'calculates a valid cost factor' do
    first = SCrypt::Engine.calibrate(max_time: 0.2)
    expect(SCrypt::Engine.valid_cost?(first)).to equal(true)
  end
end

describe 'Generating SCrypt salts' do
  it 'produces strings' do
    expect(SCrypt::Engine.generate_salt).to be_an_instance_of(String)
  end

  it 'produces random data' do
    expect(SCrypt::Engine.generate_salt).not_to equal(SCrypt::Engine.generate_salt)
  end

  it 'uses the saved cost factor' do
    # Verify cost is different before saving
    cost = SCrypt::Engine.calibrate(max_time: 0.01)
    expect(SCrypt::Engine.generate_salt).not_to start_with(cost)

    cost = SCrypt::Engine.calibrate!(max_time: 0.01)
    expect(SCrypt::Engine.generate_salt).to start_with(cost)
  end

  it 'resets calibrated cost when setting new calibration' do
    # Set initial calibration
    first_cost = SCrypt::Engine.calibrate!(max_time: 0.01)
    expect(SCrypt::Engine.calibrated_cost).to eq(first_cost)

    # Set different calibration
    second_cost = SCrypt::Engine.calibrate!(max_time: 0.02)
    expect(SCrypt::Engine.calibrated_cost).to eq(second_cost)
    expect(SCrypt::Engine.calibrated_cost).not_to eq(first_cost)
  end
end

describe 'Autodetecting of salt cost' do
  it 'works' do
    expect(SCrypt::Engine.autodetect_cost('2a$08$c3$some_salt')).to eq('2a$08$c3$')
  end
end

describe 'Generating SCrypt hashes' do
  class MyInvalidSecret
    undef to_s
  end

  before do
    @salt = SCrypt::Engine.generate_salt
    @password = 'woo'
  end

  it 'produces a string' do
    expect(SCrypt::Engine.hash_secret(@password, @salt)).to be_an_instance_of(String)
  end

  it 'raises an InvalidSalt error if the salt is invalid' do
    expect { SCrypt::Engine.hash_secret(@password, 'nino') }.to raise_error(SCrypt::Errors::InvalidSalt)
  end

  it 'raises an InvalidSecret error if the secret is invalid' do
    expect { SCrypt::Engine.hash_secret(MyInvalidSecret.new, @salt) }.to raise_error(SCrypt::Errors::InvalidSecret)
    expect { SCrypt::Engine.hash_secret(nil, @salt) }.not_to raise_error
    expect { SCrypt::Engine.hash_secret(false, @salt) }.not_to raise_error
  end

  it 'calls #to_s on the secret and use the return value as the actual secret data' do
    expect(SCrypt::Engine.hash_secret(false, @salt)).to eq(SCrypt::Engine.hash_secret('false', @salt))
  end
end

describe 'SCrypt test vectors' do
  it 'matches results of SCrypt function' do
    TEST_VECTORS['scrypt_vectors'].each do |vector|
      next if vector['skip_reason'] # Skip memory-intensive tests

      result = SCrypt::Engine.scrypt(
        vector['password'],
        vector['salt'],
        vector['n'],
        vector['r'],
        vector['p'],
        vector['key_len']
      ).unpack('H*').first

      expect(result).to eq(vector['expected']), "Failed for: #{vector['description']}"
    end
  end

  it 'matches equivalent results sent through hash_secret() function' do
    TEST_VECTORS['hash_secret_vectors'].each do |vector|
      next if vector['skip_reason'] # Skip memory-intensive tests

      result = SCrypt::Engine.hash_secret(
        vector['password'],
        vector['salt'],
        vector['key_len']
      )

      # hash_secret returns: salt + '$' + hash_digest
      # So we expect: "salt$expected_pattern"
      expected_full_hash = "#{vector['salt']}$#{vector['expected_pattern']}"
      expect(result).to eq(expected_full_hash), "Failed for: #{vector['description']}"
    end
  end
end

describe 'Input validation' do
  describe '#calibrate' do
    it 'raises ArgumentError for negative max_mem' do
      expect do
        SCrypt::Engine.send(:__sc_calibrate, -1, 0.5, 0.2)
      end.to raise_error(ArgumentError, 'max_mem must be non-negative')
    end

    it 'raises ArgumentError for invalid max_memfrac' do
      expect do
        SCrypt::Engine.send(:__sc_calibrate, 1024, -0.1,
                            0.2)
      end.to raise_error(ArgumentError, 'max_memfrac must be between 0 and 1')
      expect do
        SCrypt::Engine.send(:__sc_calibrate, 1024, 1.1,
                            0.2)
      end.to raise_error(ArgumentError, 'max_memfrac must be between 0 and 1')
    end

    it 'raises ArgumentError for non-positive max_time' do
      expect do
        SCrypt::Engine.send(:__sc_calibrate, 1024, 0.5, 0)
      end.to raise_error(ArgumentError, 'max_time must be positive')

      expect do
        SCrypt::Engine.send(:__sc_calibrate, 1024, 0.5, -0.1)
      end.to raise_error(ArgumentError, 'max_time must be positive')
    end
  end

  describe '#scrypt' do
    it 'raises ArgumentError for nil secret' do
      expect do
        SCrypt::Engine.send(:__sc_crypt, nil, 'salt', 16, 1, 1, 32)
      end.to raise_error(ArgumentError, 'secret cannot be nil')
    end

    it 'raises ArgumentError for nil salt' do
      expect do
        SCrypt::Engine.send(:__sc_crypt, 'secret', nil, 16, 1, 1, 32)
      end.to raise_error(ArgumentError, 'salt cannot be nil')
    end

    it 'raises ArgumentError for non-positive parameters' do
      expect do
        SCrypt::Engine.send(:__sc_crypt, 'secret', 'salt', 0, 1, 1, 32)
      end.to raise_error(ArgumentError, 'cpu_cost must be positive')

      expect do
        SCrypt::Engine.send(:__sc_crypt, 'secret', 'salt', 16, 0, 1, 32)
      end.to raise_error(ArgumentError, 'memory_cost must be positive')

      expect do
        SCrypt::Engine.send(:__sc_crypt, 'secret', 'salt', 16, 1, 0, 32)
      end.to raise_error(ArgumentError, 'parallelization must be positive')

      expect do
        SCrypt::Engine.send(:__sc_crypt, 'secret', 'salt', 16, 1, 1,
                            0)
      end.to raise_error(ArgumentError, 'key_len must be positive')
    end
  end
end

describe 'Memory usage calculation' do
  it 'calculates memory usage correctly' do
    cost = '400$8$1$'
    memory = SCrypt::Engine.memory_use(cost)
    n = 0x400
    r = 8
    p = 1
    expected = (128 * r * p) + (256 * r) + (128 * r * n)
    expect(memory).to eq(expected)
  end
end

describe 'Calibrated cost management' do
  after do
    # Reset calibrated cost after each test
    SCrypt::Engine.calibrated_cost = nil
  end

  it 'initializes have no calibrated cost' do
    SCrypt::Engine.calibrated_cost = nil
    expect(SCrypt::Engine.calibrated_cost).to be_nil
  end

  it 'stores and retrieve calibrated cost' do
    cost = SCrypt::Engine.calibrate!(max_time: 0.01)
    expect(SCrypt::Engine.calibrated_cost).to eq(cost)
  end

  it 'uses calibrated cost in generate_salt when available' do
    cost = SCrypt::Engine.calibrate!(max_time: 0.01)
    salt = SCrypt::Engine.generate_salt
    expect(salt).to start_with(cost)
  end
end
