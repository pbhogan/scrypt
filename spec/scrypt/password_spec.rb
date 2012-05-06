require File.expand_path(File.join(File.dirname(__FILE__), "..", "spec_helper"))

describe "Creating a hashed password" do
  before :each do
    @password = SCrypt::Password.create("s3cr3t", :max_time => 0.25)
  end

  it "should return a SCrypt::Password" do
    @password.should be_an_instance_of(SCrypt::Password)
  end

  it "should return a valid password" do
    lambda { SCrypt::Password.new(@password) }.should_not raise_error
  end

  it "should behave normally if the secret is not a string" do
    lambda { SCrypt::Password.create(nil) }.should_not raise_error(SCrypt::Errors::InvalidSecret)
    lambda { SCrypt::Password.create({:woo => "yeah"}) }.should_not raise_error(SCrypt::Errors::InvalidSecret)
    lambda { SCrypt::Password.create(false) }.should_not raise_error(SCrypt::Errors::InvalidSecret)
  end

  it "should tolerate empty string secrets" do
    lambda { SCrypt::Password.create( "\n".chop  ) }.should_not raise_error
    lambda { SCrypt::Password.create( ""         ) }.should_not raise_error
    lambda { SCrypt::Password.create( String.new ) }.should_not raise_error
  end
end


describe "Reading a hashed password" do
  before :each do
    @secret = "my secret"
    @hash = "400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07"
  end

  it "should read the cost, salt, and hash" do
    password = SCrypt::Password.new(@hash)
    password.cost.should == "400$8$d$"
    password.salt.should == "173a8189751c095a29b933789560b73bf17b2e01"
    password.to_s.should == @hash
  end

  it "should raise an InvalidHashError when given an invalid hash" do
    lambda { SCrypt::Password.new('not a valid hash') }.should raise_error(SCrypt::Errors::InvalidHash)
  end
end

describe "Comparing a hashed password with a secret" do
  before :each do
    @secret = "s3cr3t"
    @password = SCrypt::Password.create(@secret)
  end

  it "should compare successfully to the original secret" do
    (@password == @secret).should be(true)
  end

  it "should compare unsuccessfully to anything besides original secret" do
    (@password == "@secret").should be(false)
  end

end

describe "non-default salt sizes" do
  before :each do
    @secret = "s3cret"
  end

  it "should enforce a minimum salt of 8 bytes" do
    @password = SCrypt::Password.create(@secret, :salt_size => 7)
    @password.salt.length.should eq(8 * 2)
  end

  it "should allow a salt of 32 bytes" do
    @password = SCrypt::Password.create(@secret, :salt_size => 32)
    @password.salt.length.should eq(32 * 2)
  end

  it "should enforce a maximum salt of 32 bytes" do
    @password = SCrypt::Password.create(@secret, :salt_size => 33)
    @password.salt.length.should eq(32 * 2)
  end

  it "should pad a 20-byte salt to not look like a 20-byte SHA1" do
    @password = SCrypt::Password.create(@secret, :salt_size => 20)
    @password.salt.length.should eq(41)
  end

  it "should properly compare a non-standard salt hash" do
    @password = SCrypt::Password.create(@secret, :salt_size => 20)
    (SCrypt::Password.new(@password.to_s) == @secret).should be(true)
  end

end

describe "non-default key lengths" do
  before :each do
    @secret = "s3cret"
  end

  it "should enforce a minimum keylength of 16 bytes" do
    @password = SCrypt::Password.create(@secret, :key_len => 15)
    @password.hash.length.should eq(16 * 2)
  end

  it "should allow a keylength of 512 bytes" do
    @password = SCrypt::Password.create(@secret, :key_len => 512)
    @password.hash.length.should eq(512 * 2)
  end

  it "should enforce a maximum keylength of 512 bytes" do
    @password = SCrypt::Password.create(@secret, :key_len => 513)
    @password.hash.length.should eq(512 * 2)
  end

  it "should properly compare a non-standard hash" do
    @password = SCrypt::Password.create(@secret, :key_len => 512)
    (SCrypt::Password.new(@password.to_s) == @secret).should be(true)
  end

end

describe "SCrypt function" do
  it "should pass test vectors" do
    SCrypt::Engine.scrypt('', '', 16, 1, 1, 64).unpack('H*').first.should eq('77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906')
    SCrypt::Engine.scrypt('password', 'NaCl', 1024, 8, 16, 64).unpack('H*').first.should eq('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')
    SCrypt::Engine.scrypt('pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64).unpack('H*').first.should eq('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887')
    SCrypt::Engine.scrypt('pleaseletmein', 'SodiumChloride', 1048576, 8, 1, 64).unpack('H*').first.should eq('2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4')
  end
end

describe "Old-style hashes" do
  before :each do
    @secret = "my secret"
    @hash = "400$8$d$173a8189751c095a29b933789560b73bf17b2e01$9bf66d74bd6f3ebcf99da3b379b689b89db1cb07"
  end

  it "should compare successfully" do
    (SCrypt::Password.new(@hash) == @secret).should be(true)
  end
end
