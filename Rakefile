# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.new('ruby-dtrace', '0.0.1') do |p|
  p.rubyforge_name = 'ruby-dtrace'
  p.author = 'Chris Andrews'
  p.email = 'chris@nodnol.org'
  p.summary = 'Ruby bindings for libdtrace'
  p.description = <<EOD
ruby-dtrace is Ruby bindings for Dtrace, which lets you write D-based
programs in Ruby. It doesn't provide D probes for Ruby, but you can
use it with the probes found in the Joyent and Apple builds of Ruby.
EOD
  p.spec_extras = {:extensions => ['ext/extconf.rb']}
  p.url = "http://ruby-dtrace.rubyforge.org/"
end

desc "Uses extconf.rb and make to build the extension"
task :extensions do
  Dir.chdir('ext')
  system("ruby extconf.rb")
  system("make")
  Dir.chdir('..')
end

# vim: syntax=Ruby
