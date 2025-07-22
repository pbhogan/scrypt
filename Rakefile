# frozen_string_literal: true

require 'bundler/setup'
require 'bundler/gem_tasks'
require 'digest/sha2'

require 'ffi'
require 'ffi-compiler/compile_task'

require 'fileutils'
require 'rake'
require 'rake/clean'
require 'rdoc/task'

require 'rspec/core/rake_task'

require 'rubygems'
require 'rubygems/package_task'

require './lib/scrypt/version'

task default: %i[clean compile_ffi spec]

desc 'Run all specs'
RSpec::Core::RakeTask.new(:spec) do |t|
  t.rspec_opts = ['--color', '--backtrace', '--format', 'documentation']
end

desc 'Generate checksum for built gem'
task :checksum do
  built_gem_path = "pkg/scrypt-#{SCrypt::VERSION}.gem"

  unless File.exist?(built_gem_path)
    puts "Gem file not found: #{built_gem_path}"
    puts "Run 'rake build' first to create the gem."
    exit 1
  end

  checksum = Digest::SHA512.new.hexdigest(File.read(built_gem_path))
  checksum_path = "checksum/scrypt-#{SCrypt::VERSION}.gem.sha512"

  # Ensure checksum directory exists
  FileUtils.mkdir_p(File.dirname(checksum_path))

  File.write(checksum_path, checksum)
  puts "Checksum written to: #{checksum_path}"
end

desc 'Compile FFI extension'
namespace :ffi_compiler do
  FFI::Compiler::CompileTask.new('ext/scrypt/scrypt_ext') do |t|
    target_cpu = RbConfig::CONFIG['target_cpu']

    t.cflags << '-Wall -std=c99'
    t.cflags << '-msse -msse2' if t.platform.arch.include?('86')
    t.cflags << '-D_GNU_SOURCE=1' if RbConfig::CONFIG['host_os'].downcase =~ /mingw/
    t.cflags << '-D_POSIX_C_SOURCE=200809L' if RbConfig::CONFIG['host_os'].downcase =~ /linux/

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
task compile_ffi: ['ffi_compiler:default']

CLEAN.include('ext/scrypt/*{.o,.log,.so,.bundle}')
CLEAN.include('lib/**/*{.o,.log,.so,.bundle}')

desc 'Generate RDoc documentation'
RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.options << '--force-update'
  rdoc.options << '-V'

  rdoc.template = ENV['TEMPLATE'] if ENV['TEMPLATE']
end

desc 'Run all specs'
RSpec::Core::RakeTask.new do |_t|
  # Task automatically runs specs based on RSpec defaults
end

def gem_spec
  @gem_spec ||= Gem::Specification.load('scrypt.gemspec')
end

Gem::PackageTask.new(gem_spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
  pkg.package_dir = 'pkg'
end
