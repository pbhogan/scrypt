# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "scrypt/version"

Gem::Specification.new do |s|
  s.name        = "scrypt"
  s.version     = SCrypt::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Patrick Hogan"]
  s.email       = ["pbhogan@gmail.com"]
  s.homepage    = ""
  s.summary     = "scrypt password hashing algorithm."
  s.description = <<-EOF
    The scrypt key derivation function is designed to be far 
    more secure against hardware brute-force attacks than 
    alternative functions such as PBKDF2 or bcrypt.
  EOF

  s.add_runtime_dependency "jruby-openssl" if defined? JRUBY_VERSION

  s.add_development_dependency "rspec"
  s.add_development_dependency "rake"
  s.add_development_dependency "rake-compiler"

  s.rubyforge_project = "scrypt"

  s.extensions = ["ext/scrypt/extconf.rb"] unless defined? JRUBY_VERSION

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end
