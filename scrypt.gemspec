# frozen_string_literal: true

$:.push File.expand_path('lib', __dir__)
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
  s.cert_chain  = ['certs/pbhogan.pem']
  s.license     = 'BSD-3-Clause'

  s.signing_key = File.expand_path('~/.ssh/gem-private_key.pem') if $0 =~ /gem\z/
  s.metadata['rubygems_mfa_required'] = 'true'

  s.homepage    = 'https://github.com/pbhogan/scrypt'
  s.summary     = 'scrypt password hashing algorithm.'

  s.description = <<-DESC
    The scrypt key derivation function is designed to be far
    more secure against hardware brute-force attacks than
    alternative functions such as PBKDF2 or bcrypt.
  DESC

  s.required_ruby_version = '>= 2.3.0'

  s.add_dependency 'ffi-compiler', '>= 1.0', '< 2.0'
  s.add_dependency 'rake', '~> 13'

  s.extensions = ['ext/scrypt/Rakefile']

  s.files = %w[Rakefile scrypt.gemspec README.md COPYING] + Dir.glob('{lib,spec}/**/*')
  s.files += Dir.glob('ext/scrypt/*')
  s.require_paths = ['lib']
end
