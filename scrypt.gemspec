# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "scrypt/version"

Gem::Specification.new do |s|
  s.name        = "scrypt"
  s.version     = SCrypt::VERSION
  s.authors     = ["Patrick Hogan"]
  s.email       = ["pbhogan@gmail.com"]
  s.homepage    = "https://github.com/pbhogan/scrypt"
  s.summary     = "scrypt password hashing algorithm."
  s.description = <<-EOF
    The scrypt key derivation function is designed to be far
    more secure against hardware brute-force attacks than
    alternative functions such as PBKDF2 or bcrypt.
  EOF

  s.add_dependency 'ffi-compiler', '>= 0.0.2'
  s.add_dependency 'rake'
  s.add_development_dependency "rspec"
  s.add_development_dependency "rdoc"
  s.add_development_dependency "awesome_print"

  s.rubyforge_project = "scrypt"

  s.extensions = ["ext/scrypt/Rakefile"]

  s.files = %w(Rakefile scrypt.gemspec README.md COPYING) + Dir.glob("{lib,spec,autotest}/**/*")
  s.files += Dir.glob("ext/scrypt/*")
  s.test_files = Dir.glob("spec/**/*")
  s.require_paths = ["lib"]
end
