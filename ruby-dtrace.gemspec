Gem::Specification.new do |s|
  
  s.name = 'ruby-dtrace'
  s.version = Dtrace::VERSION
  s.platform = Gem::Platform::RUBY
  s.summary = <<-DESC.strip.gsub(/\n\s+/, " ")
                ruby-dtrace is Ruby bindings for Dtrace, which lets you write D-based
                programs in Ruby, and add probes to your Ruby programs.
	  DESC
  
  s.files = Dir.glob("{examples,ext,lib,plugin,test}/**/*") + %w(README.txt History.txt Manifest.txt Rakefile)
  s.require_path = 'lib'
  s.has_rdoc = true
  
  s.author = "Chris Andrews"
  s.email = "chris@nodnol.org"
  s.homepage = "http://ruby-dtrace.rubyforge.org"
  s.rubyforge_project = "ruby-dtrace"
  
end
