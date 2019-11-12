# frozen_string_literal: true

require 'bundler/setup'
require 'bundler/gem_tasks'

require 'rake'
require 'rake/clean'

require 'rspec/core/rake_task'

require 'ffi'
require 'ffi-compiler/compile_task'

require 'digest/sha2'
require './lib/scrypt/version'

require 'rubygems'
require 'rubygems/package_task'

require 'rdoc/task'

task default: [:clean, :compile_ffi, :spec]

desc 'clean, make and run specs'
task :spec do
  RSpec::Core::RakeTask.new
end

desc 'generate checksum'
task :checksum do
  built_gem_path = "pkg/scrypt-#{SCrypt::VERSION}.gem"
  checksum = Digest::SHA512.new.hexdigest(File.read(built_gem_path))
  checksum_path = "checksum/scrypt-#{SCrypt::VERSION}.gem.sha512"
  File.open(checksum_path, 'w') { |f| f.write(checksum) }
end

desc 'FFI compiler'
namespace 'ffi-compiler' do
  FFI::Compiler::CompileTask.new('ext/scrypt/scrypt_ext') do |t|
    target_cpu = RbConfig::CONFIG['target_cpu']

    t.cflags << '-Wall -std=c99'
    t.cflags << '-msse -msse2' if t.platform.arch.include? '86'
    t.cflags << '-D_GNU_SOURCE=1' if RbConfig::CONFIG['host_os'].downcase =~ /mingw/
    t.cflags << '-D_POSIX_C_SOURCE=199309L' if RbConfig::CONFIG['host_os'].downcase =~ /linux/

    if 1.size == 4 && target_cpu =~ /i386|x86_32/ && t.platform.mac?
      t.cflags << '-arch i386'
      t.ldflags << '-arch i386'
    elsif 1.size == 8 && target_cpu =~ /i686|x86_64/ && t.platform.mac?
      t.cflags << '-arch x86_64'
      t.ldflags << '-arch x86_64'
    end

    t.add_define 'WINDOWS_OS' if FFI::Platform.windows?
  end
end
task compile_ffi: ['ffi-compiler:default']

CLEAN.include('ext/scrypt/*{.o,.log,.so,.bundle}')
CLEAN.include('lib/**/*{.o,.log,.so,.bundle}')

desc 'Generate RDoc'
rd = Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options << '--title' << 'scrypt-ruby' << '--line-numbers' << '--inline-source' << '--main' << 'README'
  rdoc.template = ENV['TEMPLATE'] if ENV['TEMPLATE']
  rdoc.rdoc_files.include('COPYING', 'lib/**/*.rb')
end

desc 'Run all specs'
RSpec::Core::RakeTask.new do |_t|
  rspec_opts = ['--colour', '--backtrace']
end

def gem_spec
  @gem_spec ||= Gem::Specification.load('scrypt.gemspec')
end

Gem::PackageTask.new(gem_spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
  pkg.package_dir = 'pkg'
end
