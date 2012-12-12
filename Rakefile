require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << "ext:lib"
  t.test_files = Dir["test/test_*.rb"]
  t.verbose = true
end

desc "Default task"
task :default => [ :test ]
