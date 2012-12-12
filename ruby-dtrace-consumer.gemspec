lib = File.expand_path("../lib", __FILE__)
$:.unshift lib unless $:.include?(lib)

require 'dtrace/version'

Gem::Specification.new do |s|
  s.name = 'ruby-dtrace-consumer'
  s.version = Dtrace::VERSION
  s.platform = Gem::Platform::RUBY
  s.summary = "DTrace Consumer library for Ruby"
  s.has_rdoc = true
  s.extensions  = ['ext/extconf.rb']
  s.require_paths = ['lib', 'ext']
  s.authors = ["Chris Andrews"]
  s.email = ["chris@nodnol.org"]
  s.homepage = "http://github.com/chrisa/ruby-dtrace"
  s.files = Dir.glob("{lib,ext,test}/**/*") + %w(README.md LICENCE)
end
