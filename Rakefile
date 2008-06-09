# -*- ruby -*-

require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'
require 'rake/packagetask'
require 'rake/gempackagetask'
require 'rake/contrib/rubyforgepublisher'

$: << './lib'
require 'dtrace'

desc "Uses extconf.rb and make to build the extension"
task :extensions do
  Dir.chdir('ext')
  system("ruby extconf.rb")
  system("make")
  Dir.chdir('dof')
  system("ruby extconf.rb")
  system("make")  
  Dir.chdir('../..')
end

desc "Clean all extensions"
task :clean_extensions do
  Dir.chdir('ext')
  system("make clean")
  Dir.chdir('dof')
  system("make clean")  
  Dir.chdir('../..')
end
 
PKG_NAME      = "ruby-dtrace"
PKG_BUILD     = ENV['PKG_BUILD'] ? '.' + ENV['PKG_BUILD'] : ''
PKG_VERSION   = Dtrace::VERSION + PKG_BUILD
PKG_FILE_NAME = "#{PKG_NAME}-#{PKG_VERSION}"
 
desc "Default task"
task :default => [ :test ]
 
desc "Build documentation"
task :doc => [ :rdoc ]
 
Rake::TestTask.new do |t|
  t.libs << "ext:lib"
  t.test_files = Dir["test/*.rb"]
  t.verbose = true
end
 
desc "Run code-coverage analysis using rcov"
task :coverage do
  rm_rf "coverage"
  files = Dir["test/*.rb"]
  system "rcov --sort coverage -Iext:lib #{files.join(' ')}"
end
 
GEM_SPEC = eval(File.read("#{File.dirname(__FILE__)}/#{PKG_NAME}.gemspec"))
 
Rake::GemPackageTask.new(GEM_SPEC) do |p|
  p.gem_spec = GEM_SPEC
  p.need_tar = true
  p.need_zip = true
end
 
desc "Build the RDoc API documentation"
Rake::RDocTask.new do |rdoc|
  rdoc.rdoc_dir = "doc"
  rdoc.title    = "Ruby-DTrace"
  rdoc.options += %w(--line-numbers --inline-source --main README.txt)
  rdoc.rdoc_files.include 'README.txt'
  rdoc.rdoc_files.include 'ext/**/*.c'
  rdoc.rdoc_files.include 'lib/**/*.rb'
end
