# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'Creating a hashed password' do
  before do
    @password = SCrypt::Password.create('s3cr3t', max_time: 0.25)
  end

  it 'returns a SCrypt::Password' do
    expect(@password).to be_an_instance_of(SCrypt::Password)
  end

  it 'returns a valid password' do
    expect { SCrypt::Password.new(@password) }.not_to raise_error
  end

  it 'behaves normally if the secret is not a string' do
    expect { SCrypt::Password.create(nil) }.not_to raise_error
    expect { SCrypt::Password.create(false) }.not_to raise_error
    expect { SCrypt::Password.create(42) }.not_to raise_error
  end

  it 'tolerates empty string secrets' do
    expect { SCrypt::Password.create('') }.not_to raise_error
    expect { SCrypt::Password.create('', max_time: 0.01) }.not_to raise_error
    expect(SCrypt::Password.create('')).to be_an_instance_of(SCrypt::Password)
  end
end

describe 'Reading a hashed password' do
  before do
    @secret = 'my secret'
    @hash = '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07'
  end

  it 'reads the cost, salt, and hash' do
    password = SCrypt::Password.new(@hash)
    expect(password.cost).to eq('400$8$d$')
    expect(password.salt).to eq('173a8189751c095a29b933789560b73bf17b2e01')
    expect(password.digest).to eq('9bf66d74bd6f3ebcf99da3b379b689b89db1cb07')
  end

  it 'raises an InvalidHashError when given an invalid hash' do
    expect { SCrypt::Password.new('invalid') }.to raise_error(SCrypt::Errors::InvalidHash)
  end
end

describe 'Comparing a hashed password with a secret' do
  before do
    @secret = 's3cr3t'
    @password = SCrypt::Password.create(@secret, max_time: 0.01)
  end

  it 'compares successfully to the original secret' do
    expect(@password == @secret).to be true
  end

  it 'compares unsuccessfully to anything besides original secret' do
    expect(@password == 'different').to be false
  end
end

describe 'non-default salt sizes' do
  before do
    @secret = 's3cret'
  end

  it 'enforces a minimum salt of 8 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 4, max_time: 0.01)
    expect(@password.salt.length).to eq(16) # 8 bytes * 2 (hex encoding)
  end

  it 'allows a salt of 32 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 32, max_time: 0.01)
    expect(@password.salt.length).to eq(64) # 32 bytes * 2 (hex encoding)
  end

  it 'enforces a maximum salt of 32 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 64, max_time: 0.01)
    expect(@password.salt.length).to eq(64) # 32 bytes * 2 (hex encoding)
  end

  it 'pads a 20-byte salt to not look like a 20-byte SHA1' do
    @password = SCrypt::Password.create(@secret, salt_size: 20)
    expect(@password.salt.length).to eq(41)
  end

  it 'properly compares a non-standard salt hash' do
    @password = SCrypt::Password.create(@secret, salt_size: 16, max_time: 0.01)
    expect(@password == @secret).to be true
  end
end

describe 'non-default key lengths' do
  before do
    @secret = 's3cret'
  end

  it 'enforces a minimum keylength of 16 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 8, max_time: 0.01)
    expect(@password.digest.length).to eq(32) # 16 bytes * 2 (hex encoding)
  end

  it 'allows a keylength of 512 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 512, max_time: 0.01)
    expect(@password.digest.length).to eq(1024) # 512 bytes * 2 (hex encoding)
  end

  it 'enforces a maximum keylength of 512 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 1024, max_time: 0.01)
    expect(@password.digest.length).to eq(1024) # 512 bytes * 2 (hex encoding)
  end

  it 'properly compares a non-standard hash' do
    @password = SCrypt::Password.create(@secret, key_len: 64, max_time: 0.01)
    expect(@password == @secret).to be true
  end
end

describe 'Old-style hashes' do
  before do
    @secret = 'my secret'
    @hash = '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07'
  end

  it 'compares successfully' do
    expect(SCrypt::Password.new(@hash) == @secret).to be true
  end
end

describe 'Respecting standard ruby behaviors' do
  it 'hashes as an integer' do
    password = SCrypt::Password.create('secret', max_time: 0.01)
    expect(password.hash).to be_an(Integer)
  end
end

describe 'Password validation and parsing' do
  it 'correctly parses hash components' do
    password = SCrypt::Password.new('400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07')

    expect(password.cost).to eq('400$8$d$')
    expect(password.salt).to eq('173a8189751c095a29b933789560b73bf17b2e01')
    expect(password.digest).to eq('9bf66d74bd6f3ebcf99da3b379b689b89db1cb07')
  end

  it 'validates hash format strictly' do
    valid_hash = '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07'

    expect { SCrypt::Password.new(valid_hash) }.not_to raise_error
    expect { SCrypt::Password.new('invalid') }.to raise_error(SCrypt::Errors::InvalidHash)
    expect { SCrypt::Password.new('') }.to raise_error(SCrypt::Errors::InvalidHash)
    expect { SCrypt::Password.new('400$8$d$') }.to raise_error(SCrypt::Errors::InvalidHash)
  end

  it 'handles alias method correctly' do
    password = SCrypt::Password.create('secret', max_time: 0.01)

    expect(password.is_password?('secret')).to be true
    expect(password.is_password?('wrong')).to be false
  end
end

describe 'Parameter boundary testing' do
  it 'enforces minimum and maximum key lengths correctly' do
    # Test minimum key length (should be clamped to 16)
    password_min = SCrypt::Password.create('secret', key_len: 8, max_time: 0.01)
    expect(password_min.digest.length).to eq(32) # 16 bytes * 2 (hex encoding)

    # Test maximum key length (should be clamped to 512)
    password_max = SCrypt::Password.create('secret', key_len: 1024, max_time: 0.01)
    expect(password_max.digest.length).to eq(1024) # 512 bytes * 2 (hex encoding)
  end

  it 'enforces minimum and maximum salt sizes correctly' do
    # Test minimum salt size (should be clamped to 8)
    password_min = SCrypt::Password.create('secret', salt_size: 4, max_time: 0.01)
    expect(password_min.salt.length).to eq(16) # 8 bytes * 2 (hex encoding)

    # Test maximum salt size (should be clamped to 32)
    password_max = SCrypt::Password.create('secret', salt_size: 64, max_time: 0.01)
    expect(password_max.salt.length).to eq(64) # 32 bytes * 2 (hex encoding)
  end
end
