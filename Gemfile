# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

group :development, :test do
  gem 'irb'
  gem 'rdoc', '~> 6'

  gem 'rake', '~> 13'
  gem 'rspec', '~> 3'

  if RUBY_VERSION >= '3.0.0'
    gem 'rubocop', '~> 1'
    gem 'rubocop-performance', '~> 1'
    gem 'rubocop-rake', '~> 0.7'
    gem 'rubocop-rspec', '~> 3'
  end
end
