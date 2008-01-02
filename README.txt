ruby-dtrace is Ruby bindings for Dtrace, which lets you write D-based
programs in Ruby. It doesn't provide D probes for Ruby, but you can
use it with the probes found in the Joyent and Apple builds of Ruby.

== FEATURES
  
* Access to the D API
* Probe metadata
* Run D programs
* Access aggregates
* Consume output from D programs

== SYNOPSIS

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

== REQUIREMENTS

* A platform with Dtrace support (OpenSolaris, Mac OS X 10.5 Leopard tested, possibly also FreeBSD).
* root, or some/all of the dtrace privileges on Solaris: dtrace_user, dtrace_proc and dtrace_kernel.

== INSTALL

 $ sudo gem install ruby-dtrace

== LICENSE

Copyright (c) 2007 Chris Andrews <chris@nodnol.org>

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
