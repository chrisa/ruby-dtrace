# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.new('ruby-dtrace', '0.0.1') do |p|
  p.rubyforge_name = 'ruby-dtrace'
  p.author = 'Chris Andrews'
  p.email = 'chris@nodnol.org'
  p.summary = 'Ruby bindings for libdtrace'
  p.spec_extras = {:extensions => ['ext/extconf.rb']}
end

desc "Uses extconf.rb and make to build the extension"
task :extensions do
  Dir.chdir('ext')
  system("ruby extconf.rb")
  system("make")
  Dir.chdir('..')
end

# vim: syntax=Ruby
