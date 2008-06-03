# -*- ruby -*-

require 'rubygems'
require 'hoe'

$: << './lib'
require 'dtrace'

Hoe.new('ruby-dtrace', Dtrace::VERSION) do |p|
  p.rubyforge_name = 'ruby-dtrace'
  p.author = 'Chris Andrews'
  p.email = 'chris@nodnol.org'
  p.summary = 'Ruby bindings for libdtrace'
  p.description = <<EOD
ruby-dtrace is Ruby bindings for Dtrace, which lets you write D-based
programs in Ruby. It also lets you define probes in your Ruby programs.
EOD
  p.spec_extras = {:extensions => ['ext/extconf.rb']}
  p.url = "http://ruby-dtrace.rubyforge.org/"
  p.changes = p.paragraphs_of('History.txt', 0..1).join("\n\n")
end

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

# vim: syntax=Ruby
