# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

describe 'SCrypt FFI Library Loading' do
  describe 'Extension loading' do
    it 'loads the scrypt extension successfully' do
      # This test verifies that the FFI library loads without error
      # If we get here, the library loaded successfully during require
      expect(SCrypt::Ext).to be_a(Module)
      expect(SCrypt::Ext).to respond_to(:sc_calibrate)
      expect(SCrypt::Ext).to respond_to(:crypto_scrypt)
    end

    it 'has proper FFI function signatures' do
      # Verify that the FFI functions are properly bound
      expect(SCrypt::Ext.method(:sc_calibrate)).to be_a(Method)
      expect(SCrypt::Ext.method(:crypto_scrypt)).to be_a(Method)
    end
  end

  describe 'FFI function behavior' do
    it 'handles basic calibration calls' do
      # Test that the FFI functions are callable
      expect { SCrypt::Engine.calibrate(max_time: 0.01) }.not_to raise_error
    end

    it 'handles basic scrypt calls' do
      salt = SCrypt::Engine.generate_salt(max_time: 0.01)
      expect { SCrypt::Engine.hash_secret('test', salt) }.not_to raise_error
    end
  end
end
