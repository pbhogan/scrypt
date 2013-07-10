require 'bundler/setup'
require 'bundler/gem_tasks'

require 'rake'
require 'rake/clean'

require 'rspec/core/rake_task'

require 'ffi'
require 'ffi-compiler/compile_task'

require 'rubygems'
require 'rubygems/package_task'

require 'rdoc/task'

task :default => [:clean, :compile_ffi, :spec]

desc "clean, make and run specs"
task :spec  do
  RSpec::Core::RakeTask.new
end

desc "FFI compiler"
namespace "ffi-compiler" do
  FFI::Compiler::CompileTask.new('ext/scrypt/scrypt_ext') do |t|
    t.cflags << "-Wall -msse -msse2"
    t.cflags << "-D_GNU_SOURCE=1" if RbConfig::CONFIG["host_os"].downcase =~ /mingw/
    t.cflags << "-arch x86_64 -arch i386" if t.platform.mac?
    t.ldflags << "-arch x86_64 -arch i386" if t.platform.mac?
  end
end
task :compile_ffi => ["ffi-compiler:default"]

CLEAN.include('ext/scrypt/*{.o,.log,.so,.bundle}')
CLEAN.include('lib/**/*{.o,.log,.so,.bundle}')

desc 'Generate RDoc'
rd = Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options << '--title' << 'scrypt-ruby' << '--line-numbers' << '--inline-source' << '--main' << 'README'
  rdoc.template = ENV['TEMPLATE'] if ENV['TEMPLATE']
  rdoc.rdoc_files.include('COPYING', 'lib/**/*.rb')
end


desc "Run all specs"
RSpec::Core::RakeTask.new do |t|
  rspec_opts = ['--colour','--backtrace']
end

def gem_spec
  @gem_spec ||= Gem::Specification.load('scrypt.gemspec')
end

Gem::PackageTask.new(gem_spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
  pkg.package_dir = 'pkg'
end


