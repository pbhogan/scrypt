require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake'
require 'rake/clean'
require 'rdoc/task'
require 'rspec/core/rake_task'

require 'rubygems'
require 'rubygems/package_task'
require 'ffi-compiler/export_task'


def gem_spec
  @gem_spec ||= Gem::Specification.load('scrypt.gemspec')
end


task :default => [:compile, :spec]


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


desc "Clean native extension build files."
task :clean do
end


desc "Compile the native extension."
task :compile do
  Dir.chdir('ext/scrypt') do
    ruby "rake"
  end
end


FFI::Compiler::ExportTask.new('lib/scrypt', 'ext', :gem_spec => gem_spec) do |t|
  t.export 'scrypt_ext.rb'
end


Gem::PackageTask.new(gem_spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
  pkg.package_dir = 'pkg'
end

