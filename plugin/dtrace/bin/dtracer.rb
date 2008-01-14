#!/usr/bin/env ruby

require 'rubygems'
require 'drb'
require 'pathname'

# allow running standalone or in a rails app
script_dir = Pathname.new(File.dirname(__FILE__)).realpath
rails_script = script_dir + '../vendor/plugins/dtrace/bin'
plugin_script = script_dir + '../../../../vendor/plugins/dtrace/bin'
if rails_script.directory?
  rails_root = script_dir + '../'
elsif plugin_script.directory?
  rails_root = script_dir + '../../../..'
end
$LOAD_PATH << File.join(rails_root + 'vendor/plugins/dtrace/lib')

require 'dtracer'

here = "druby://localhost:2999"
tracer = Dtracer.new
DRb.start_service here, tracer
puts "DTrace helper started"
begin
  DRb.thread.join
rescue Interrupt
  exit 0
end

