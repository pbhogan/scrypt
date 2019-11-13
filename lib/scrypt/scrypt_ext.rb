# frozen_string_literal: true

require 'ffi'
require 'ffi-compiler/loader'

module SCrypt
  module Ext
    extend FFI::Library

    ffi_lib FFI::Compiler::Loader.find('scrypt_ext')

    # rubocop:disable Style/SymbolArray

    # Bind the external functions
    attach_function :sc_calibrate,
                    [:size_t, :double, :double, :pointer],
                    :int,
                    blocking: true

    attach_function :crypto_scrypt,
                    [:pointer, :size_t, :pointer, :size_t, :uint64, :uint32, :uint32, :pointer, :size_t],
                    :int,
                    blocking: true # todo
    
    # rubocop:enable
  end
end
