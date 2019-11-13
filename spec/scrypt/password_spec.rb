# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'Creating a hashed password' do
  before :each do
    @password = SCrypt::Password.create('s3cr3t', max_time: 0.25)
  end

  it 'should return a SCrypt::Password' do
    expect(@password).to be_an_instance_of(SCrypt::Password)
  end

  it 'should return a valid password' do
    expect(-> { SCrypt::Password.new(@password) }).to_not raise_error
  end

  it 'should behave normally if the secret is not a string' do
    expect(-> { SCrypt::Password.create(nil) }).to_not raise_error
    expect(-> { SCrypt::Password.create(woo: 'yeah') }).to_not raise_error
    expect(-> { SCrypt::Password.create(false) }).to_not raise_error
  end

  it 'should tolerate empty string secrets' do
    expect(-> { SCrypt::Password.create("\n".chop) }).to_not raise_error
    expect(-> { SCrypt::Password.create('') }).to_not raise_error
    expect(-> { SCrypt::Password.create('') }).to_not raise_error
  end
end

describe 'Reading a hashed password' do
  before :each do
    @secret = 'my secret'
    @hash = '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07'
  end

  it 'should read the cost, salt, and hash' do
    password = SCrypt::Password.new(@hash)
    expect(password.cost).to eq('400$8$d$')
    expect(password.salt).to eq('173a8189751c095a29b933789560b73bf17b2e01')
    expect(password.to_s).to eq(@hash)
  end

  it 'should raise an InvalidHashError when given an invalid hash' do
    expect(-> { SCrypt::Password.new('not a valid hash') }).to raise_error(SCrypt::Errors::InvalidHash)
  end
end

describe 'Comparing a hashed password with a secret' do
  before :each do
    @secret = 's3cr3t'
    @password = SCrypt::Password.create(@secret)
  end

  it 'should compare successfully to the original secret' do
    expect((@password == @secret)).to be(true)
  end

  it 'should compare unsuccessfully to anything besides original secret' do
    expect((@password == '@secret')).to be(false)
  end
end

describe 'non-default salt sizes' do
  before :each do
    @secret = 's3cret'
  end

  it 'should enforce a minimum salt of 8 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 7)
    expect(@password.salt.length).to eq(8 * 2)
  end

  it 'should allow a salt of 32 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 32)
    expect(@password.salt.length).to eq(32 * 2)
  end

  it 'should enforce a maximum salt of 32 bytes' do
    @password = SCrypt::Password.create(@secret, salt_size: 33)
    expect(@password.salt.length).to eq(32 * 2)
  end

  it 'should pad a 20-byte salt to not look like a 20-byte SHA1' do
    @password = SCrypt::Password.create(@secret, salt_size: 20)
    expect(@password.salt.length).to eq(41)
  end

  it 'should properly compare a non-standard salt hash' do
    @password = SCrypt::Password.create(@secret, salt_size: 20)
    expect((SCrypt::Password.new(@password.to_s) == @secret)).to be(true)
  end
end

describe 'non-default key lengths' do
  before :each do
    @secret = 's3cret'
  end

  it 'should enforce a minimum keylength of 16 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 15)
    expect(@password.digest.length).to eq(16 * 2)
  end

  it 'should allow a keylength of 512 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 512)
    expect(@password.digest.length).to eq(512 * 2)
  end

  it 'should enforce a maximum keylength of 512 bytes' do
    @password = SCrypt::Password.create(@secret, key_len: 513)
    expect(@password.digest.length).to eq(512 * 2)
  end

  it 'should properly compare a non-standard hash' do
    @password = SCrypt::Password.create(@secret, key_len: 512)
    expect((SCrypt::Password.new(@password.to_s) == @secret)).to be(true)
  end
end

describe 'Old-style hashes' do
  before :each do
    @secret = 'my secret'
    @hash = '400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07'
  end

  it 'should compare successfully' do
    expect((SCrypt::Password.new(@hash) == @secret)).to be(true)
  end
end

describe 'Respecting standard ruby behaviors' do
  it 'should hash as an integer' do
    password = SCrypt::Password.create('')
    expect(password.hash).to be_kind_of(Integer)
  end
end
