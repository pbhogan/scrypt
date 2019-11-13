# frozen_string_literal: true

module SCrypt
  module Errors
    # The salt parameter provided is invalid.
    class InvalidSalt   < StandardError; end

    # The hash parameter provided is invalid.
    class InvalidHash   < StandardError; end

    # The secret parameter provided is invalid.
    class InvalidSecret < StandardError; end
  end
end
