require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake'
require 'rake/clean'
require 'rake/rdoctask'
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


desc "Clean native extension build files."
task :clean do
  Dir.chdir('ext/mri') do
    ruby "extconf.rb"
    sh "make clean"
  end
end


desc "Compile the native extension."
task :compile do
  Dir.chdir('ext/mri') do
    ruby "extconf.rb"
    sh "make"
  end
end
