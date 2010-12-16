require File.expand_path(File.join(File.dirname(__FILE__), "..", "spec_helper"))

describe "Creating a hashed password" do
  before :each do
    @password = SCrypt::Password.create("s3cr3t", :max_time => 0.25)
  end

  it "should return a SCrypt::Password" do
    @password.should be_an_instance_of(SCrypt::Password)
  end

  it "should return a valid bcrypt password" do
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
