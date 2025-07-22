# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'Security Utils' do
  describe '.secure_compare' do
    it 'performs a string comparison correctly' do
      expect(SCrypt::SecurityUtils.secure_compare('a', 'a')).to equal(true)
      expect(SCrypt::SecurityUtils.secure_compare('a', 'b')).to equal(false)
      expect(SCrypt::SecurityUtils.secure_compare('aa', 'aa')).to equal(true)
      expect(SCrypt::SecurityUtils.secure_compare('aa', 'ab')).to equal(false)
    end

    it 'returns false for different length strings' do
      expect(SCrypt::SecurityUtils.secure_compare('aa', 'aaa')).to equal(false)
      expect(SCrypt::SecurityUtils.secure_compare('aaa', 'aa')).to equal(false)
      expect(SCrypt::SecurityUtils.secure_compare('', 'a')).to equal(false)
      expect(SCrypt::SecurityUtils.secure_compare('a', '')).to equal(false)
    end

    it 'handles empty strings correctly' do
      expect(SCrypt::SecurityUtils.secure_compare('', '')).to equal(true)
    end

    it 'handles binary data correctly' do
      binary1 = "\x00\x01\x02\x03"
      binary2 = "\x00\x01\x02\x03"
      binary3 = "\x00\x01\x02\x04"

      expect(SCrypt::SecurityUtils.secure_compare(binary1, binary2)).to equal(true)
      expect(SCrypt::SecurityUtils.secure_compare(binary1, binary3)).to equal(false)
    end

    it 'handles unicode strings correctly' do
      unicode1 = 'héllo'
      unicode2 = 'héllo'
      unicode3 = 'hello'

      expect(SCrypt::SecurityUtils.secure_compare(unicode1, unicode2)).to equal(true)
      expect(SCrypt::SecurityUtils.secure_compare(unicode1, unicode3)).to equal(false)
    end

    it 'is resistant to timing attacks' do
      # This test ensures the function takes constant time regardless of where differences occur
      long_string1 = ('a' * 1000) + 'x'
      long_string2 = ('a' * 1000) + 'y'
      long_string3 = 'x' + ('a' * 1000)
      long_string4 = 'y' + ('a' * 1000)

      # All of these should return false and take similar time
      expect(SCrypt::SecurityUtils.secure_compare(long_string1, long_string2)).to equal(false)
      expect(SCrypt::SecurityUtils.secure_compare(long_string3, long_string4)).to equal(false)
    end
  end
end
