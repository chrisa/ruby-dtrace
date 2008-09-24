Ruby-DTrace is Ruby bindings for Dtrace, which allows you to add
DTrace probes to your Ruby programs, and to write D-based programs
with Ruby.

== FEEDBACK

Rubyforge mailing list: http://rubyforge.org/mailman/listinfo/ruby-dtrace-users

== FEATURES
  
Consumer:

* Access to the D API
* Probe metadata
* Run D programs
* Access aggregates
* Consume output from D programs

Probes:

* Create USDT providers from Ruby, at runtime.
* No code-generation or gcc/linker dependency

== SYNOPSIS

Consumer: see Dtrace

    require 'Dtrace'

    t = Dtrace.new 
    progtext = 'ruby$1:::function-entry{ @a[strjoin(strjoin(copyinstr(arg0),"."),copyinstr(arg1))] = count(); } END { printa(@a); }'
    prog = t.compile progtext
    prog.execute

    t.go

    [...]
    
    c = DtraceConsumer.new(t)
    c.consume_once do |rec|
      # handle records
    end

Probes: see Dtrace::Provider

    require 'dtrace/provider'

    Dtrace::Provider.create :rubyprog do |p|
      p.probe :foo, :string, :string
      p.probe :bar, :integer, :integer
    end

    Dtrace::Probe::Rubyprog.foo do |p|
      p.fire('fired!', 'again')
    end    

    Dtrace::Probe::Rubyprog.bar do |p|
      p.fire(42, 27)
    end    

== REQUIREMENTS

* For the consumer API, platform with DTrace support (OpenSolaris, Mac
  OS X 10.5 Leopard tested, possibly also FreeBSD).

* For the probe API, a platform with DTrace support (as for the
  consumer API), with a 32 bit Ruby build - i386, PowerPC (for OS X)
  and SPARC (for Solaris) are all supported. 64 bit builds are not,
  yet.
  
* root, or some/all of the dtrace privileges on Solaris: dtrace_user,
  dtrace_proc and dtrace_kernel.

== INSTALL

 $ sudo gem install chrisa-ruby-dtrace --source=http://gems.github.com

== LICENSE

Copyright (c) 2008 Chris Andrews <chris@nodnol.org>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
