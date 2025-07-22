# frozen_string_literal: true

# Shared examples for SCrypt tests
RSpec.shared_examples 'a valid scrypt hash' do
  it 'has the correct format' do
    expect(subject).to match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]+\$[A-Za-z0-9]+$/)
  end

  it 'is a string' do
    expect(subject).to be_a(String)
  end
end

RSpec.shared_examples 'a valid cost string' do
  it 'has the correct format' do
    expect(subject).to match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$$/)
  end

  it 'is valid according to Engine.valid_cost?' do
    expect(SCrypt::Engine.valid_cost?(subject)).to be(true)
  end
end

RSpec.shared_examples 'a valid salt string' do
  it 'has the correct format' do
    expect(subject).to match(/^[0-9a-z]+\$[0-9a-z]+\$[0-9a-z]+\$[A-Za-z0-9]{16,64}$/)
  end

  it 'is valid according to Engine.valid_salt?' do
    expect(SCrypt::Engine.valid_salt?(subject)).to be(true)
  end
end

RSpec.shared_examples 'proper input validation' do |method, args, error_class, error_message|
  it "raises #{error_class} for invalid input" do
    expect { subject.send(method, *args) }.to raise_error(error_class, error_message)
  end
end

RSpec.shared_examples 'deterministic output' do |method, args|
  it 'produces the same output for the same input' do
    result1 = subject.send(method, *args)
    result2 = subject.send(method, *args)
    expect(result1).to eq(result2)
  end
end
