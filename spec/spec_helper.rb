# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path(File.dirname(__FILE__) + '/../lib'))

require 'rubygems'
require 'rspec'
require 'yaml'
require 'scrypt'

# Load shared examples
Dir[File.expand_path('support/**/*.rb', __dir__)].each { |f| require f }

# Load test fixtures
TEST_VECTORS = YAML.load_file(File.expand_path('fixtures/test_vectors.yml', __dir__)).freeze

RSpec.configure do |config|
  # Use documentation format for better output
  config.default_formatter = 'doc' if config.files_to_run.one?

  # Run specs in random order to surface order dependencies
  config.order = :random

  # Seed global randomization in this process using the `--seed` CLI option
  Kernel.srand config.seed

  # Allow more verbose output when running a single file
  config.filter_run_when_matching :focus

  # Enable expect syntax (recommended)
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
    # Disable deprecated should syntax
    expectations.syntax = :expect
  end

  # Configure mocks
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # Enable shared context metadata behavior
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # Configure warnings and deprecations
  config.warnings = true
  config.raise_errors_for_deprecations!
end
