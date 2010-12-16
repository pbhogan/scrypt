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
    lambda { SCrypt::Engine.hash_secret(nil, @salt) }.should_not raise_error(SCrypt::Errors::InvalidSecret)
    lambda { SCrypt::Engine.hash_secret(false, @salt) }.should_not raise_error(SCrypt::Errors::InvalidSecret)
  end

  it "should call #to_s on the secret and use the return value as the actual secret data" do
    SCrypt::Engine.hash_secret(false, @salt).should == SCrypt::Engine.hash_secret("false", @salt)
  end
end
