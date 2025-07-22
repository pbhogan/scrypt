# frozen_string_literal: true

require 'ffi'
require 'ffi-compiler/loader'

module SCrypt
  module Ext
    extend FFI::Library

    begin
      ffi_lib FFI::Compiler::Loader.find('scrypt_ext')
    rescue LoadError => e
      raise LoadError, "Failed to load scrypt extension library: #{e.message}"
    end
  end
end
