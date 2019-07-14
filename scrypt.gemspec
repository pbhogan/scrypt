# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "scrypt/version"

Gem::Specification.new do |s|
  s.name        = "scrypt"
  s.version     = SCrypt::VERSION
  s.authors     = ["Patrick Hogan", "Stephen von Takach", "Rene van Paassen" ]
  s.email       = ["pbhogan@gmail.com", "steve@advancedcontrol.com.au",
                   "rene.vanpaassen@gmail.com" ]
  s.cert_chain  = ['certs/pbhogan.pem']
  s.license     = 'BSD-3-Clause'
  s.signing_key = File.expand_path("~/.ssh/gem-private_key.pem") if $0 =~ /gem\z/
  s.homepage    = "https://github.com/pbhogan/scrypt"
  s.summary     = "scrypt password hashing algorithm."
  s.description = <<-EOF
    The scrypt key derivation function is designed to be far
    more secure against hardware brute-force attacks than
    alternative functions such as PBKDF2 or bcrypt.
  EOF

  s.add_dependency 'ffi-compiler', '>= 1.0', '< 2.0'
  s.add_development_dependency 'rake', '>= 9', '< 13'
  s.add_development_dependency 'rspec', '>= 3', '< 4'
  s.add_development_dependency 'rdoc', '>= 4', '< 5'
  s.add_development_dependency 'awesome_print', '>= 1', '< 2'

  s.extensions = ["ext/scrypt/Rakefile"]

  s.files = %w(Rakefile scrypt.gemspec README.md COPYING) + Dir.glob("{lib,spec,autotest}/**/*")
  s.files += Dir.glob("ext/scrypt/*")
  s.test_files = Dir.glob("spec/**/*")
  s.require_paths = ["lib"]
end

