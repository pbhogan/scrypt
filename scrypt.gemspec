# frozen_string_literal: true

# rubocop:disable Performance/EndWith, Style/SpecialGlobalVars

$:.push File.expand_path("../lib", __FILE__)
require 'scrypt/version'

Gem::Specification.new do |s|
  s.name        = 'scrypt'
  s.version     = SCrypt::VERSION
  s.authors     = ['Patrick Hogan',
                   'Stephen von Takach',
                   'Rene van Paassen',
                   'Johanns Gregorian']
  s.email       = ['pbhogan@gmail.com',
                   'steve@advancedcontrol.com.au',
                   'rene.vanpaassen@gmail.com',
                   'io+scrypt@jsg.io']
  s.cert_chain  = ['certs/stakach.pem']
  s.license     = 'BSD-3-Clause'

  s.signing_key = File.expand_path('~/.ssh/gem-private_key.pem') if $0 =~ /gem\z/

  s.homepage    = 'https://github.com/pbhogan/scrypt'
  s.summary     = 'scrypt password hashing algorithm.'

  s.description = <<-DESC
    The scrypt key derivation function is designed to be far
    more secure against hardware brute-force attacks than
    alternative functions such as PBKDF2 or bcrypt.
  DESC

  s.add_dependency 'ffi-compiler', '>= 1.0', '< 2.0'
  s.add_development_dependency 'awesome_print', '>= 1', '< 2'
  s.add_development_dependency 'rake', '>= 9', '< 13'
  s.add_development_dependency 'rdoc', '>= 4', '< 5'
  s.add_development_dependency 'rspec', '>= 3', '< 4'

  if RUBY_VERSION >= '2.5'
    s.add_development_dependency 'rubocop', '>= 0.76.0', '< 1.0.0'
    s.add_development_dependency 'rubocop-gitlab-security', '>= 0.1.1', '< 0.2'
    s.add_development_dependency 'rubocop-performance', '>= 1.5.0', '< 1.6.0'
  end

  s.rubyforge_project = 'scrypt'

  s.extensions = ['ext/scrypt/Rakefile']

  s.files = %w[Rakefile scrypt.gemspec README.md COPYING] + Dir.glob('{lib,spec,autotest}/**/*')
  s.files += Dir.glob('ext/scrypt/*')
  s.test_files = Dir.glob('spec/**/*')
  s.require_paths = ['lib']
end

# rubocop:enable
