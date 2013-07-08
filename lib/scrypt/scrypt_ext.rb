require 'ffi'
require 'ffi-compiler/loader'

module SCrypt
  module Ext
    extend FFI::Library
    ffi_lib FFI::Compiler::Loader.find('scrypt_ext')

    # Bind the external functions
    attach_function :sc_calibrate, [:double, :double, :pointer], :int, :blocking => true
    attach_function :sc_crypt, [:string, :string, :pointer, :pointer], :int, :blocking => true
  end
end
