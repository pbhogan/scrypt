# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'Security Utils' do
  it 'should perform a string comparison' do
    expect(SCrypt::SecurityUtils.secure_compare('a', 'a')).to equal(true)
    expect(SCrypt::SecurityUtils.secure_compare('a', 'b')).to equal(false)
    expect(SCrypt::SecurityUtils.secure_compare('aa', 'aa')).to equal(true)
    expect(SCrypt::SecurityUtils.secure_compare('aa', 'ab')).to equal(false)
    expect(SCrypt::SecurityUtils.secure_compare('aa', 'aaa')).to equal(false)
    expect(SCrypt::SecurityUtils.secure_compare('aaa', 'aa')).to equal(false)
  end
end
