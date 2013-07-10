require File.expand_path(File.join(File.dirname(__FILE__), "..", "spec_helper"))

describe "The SCrypt engine" do
  it "should calculate a valid cost factor" do
    first = SCrypt::Engine.calibrate(:max_time => 0.2)
    SCrypt::Engine.valid_cost?(first).should == true
  end
end


describe "Generating SCrypt salts" do
  it "should produce strings" do
    SCrypt::Engine.generate_salt.should be_an_instance_of(String)
  end

  it "should produce random data" do
    SCrypt::Engine.generate_salt.should_not equal(SCrypt::Engine.generate_salt)
  end
end


describe "Autodetecting of salt cost" do
  it "should work" do
    SCrypt::Engine.autodetect_cost("2a$08$c3$randomjunkgoeshere").should == "2a$08$c3$"
  end
end


describe "Generating SCrypt hashes" do

  class MyInvalidSecret
    undef to_s
  end

  before :each do
    @salt = SCrypt::Engine.generate_salt()
    @password = "woo"
  end

  it "should produce a string" do
    SCrypt::Engine.hash_secret(@password, @salt).should be_an_instance_of(String)
  end

  it "should raise an InvalidSalt error if the salt is invalid" do
    lambda { SCrypt::Engine.hash_secret(@password, 'nino') }.should raise_error(SCrypt::Errors::InvalidSalt)
  end

  it "should raise an InvalidSecret error if the secret is invalid" do
    lambda { SCrypt::Engine.hash_secret(MyInvalidSecret.new, @salt) }.should raise_error(SCrypt::Errors::InvalidSecret)
    lambda { SCrypt::Engine.hash_secret(nil, @salt) }.should_not raise_error
    lambda { SCrypt::Engine.hash_secret(false, @salt) }.should_not raise_error
  end

  it "should call #to_s on the secret and use the return value as the actual secret data" do
    SCrypt::Engine.hash_secret(false, @salt).should == SCrypt::Engine.hash_secret("false", @salt)
  end
end

describe "SCrypt test vectors" do
  it "should match results of SCrypt function" do
    SCrypt::Engine.scrypt('', '', 16, 1, 1, 64).unpack('H*').first.should eq('77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906')
    SCrypt::Engine.scrypt('password', 'NaCl', 1024, 8, 16, 64).unpack('H*').first.should eq('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')
    SCrypt::Engine.scrypt('pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64).unpack('H*').first.should eq('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887')
    SCrypt::Engine.scrypt('pleaseletmein', 'SodiumChloride', 1048576, 8, 1, 64).unpack('H*').first.should eq('2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4')
  end

  it "should match equivalent results sent through hash_secret() function" do
    SCrypt::Engine.hash_secret('', '10$1$1$0000000000000000', 64).should match(/\$77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906$/)
    SCrypt::Engine.hash_secret('password', '400$8$10$000000004e61436c', 64).should match(/\$fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640$/)
    SCrypt::Engine.hash_secret('pleaseletmein', '4000$8$1$536f6469756d43686c6f72696465', 64).should match(/\$7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887$/)
    SCrypt::Engine.hash_secret('pleaseletmein', '100000$8$1$536f6469756d43686c6f72696465', 64).should match(/\$2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4$/)
  end
end
