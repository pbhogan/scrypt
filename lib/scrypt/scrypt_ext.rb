# frozen_string_literal: true

require 'ffi'
require 'ffi-compiler/loader'

module SCrypt
  module Ext
    extend FFI::Library

    ffi_lib FFI::Compiler::Loader.find('scrypt_ext')
  end
end
