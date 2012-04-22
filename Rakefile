require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake'
require 'rake/clean'
require 'rdoc/task'
require 'rspec/core/rake_task'

task :default => [:compile, :spec]


desc 'Generate RDoc'
rd = Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options << '--title' << 'scrypt-ruby' << '--line-numbers' << '--inline-source' << '--main' << 'README'
  rdoc.template = ENV['TEMPLATE'] if ENV['TEMPLATE']
  rdoc.rdoc_files.include('README', 'COPYING', 'CHANGELOG', 'lib/**/*.rb')
end


desc "Run all specs"
RSpec::Core::RakeTask.new do |t|
  rspec_opts = ['--colour','--backtrace']
end


if defined? JRUBY_VERSION
  require 'rake/javaextensiontask'
  Rake::JavaExtensionTask.new('scrypt_ext') do |ext|
    ext.ext_dir = 'ext/scrypt'
  end
else
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('scrypt_ext') do |ext|
    ext.ext_dir = 'ext/scrypt'
  end
end


CLEAN.include "**/*.o", "**/*.so", "**/*.bundle", "**/*.jar", "pkg", "tmp"
