ruby-dtrace-consumer is Ruby bindings for libdtrace, which allows you
to write D-based programs with Ruby, accessing traced data in Ruby.

The corresponding provider library, allowing you to create probes
meaningful to your Ruby programs, may be found as "ruby-usdt".

"ruby-dtrace", the predecessor to both these gems, is now deprecated
and will not be updated.

== FEEDBACK

Fork the repository on Github: http://github.com/chrisa/ruby-dtrace

== FEATURES
  
 * Access to the D API
 * Probe metadata
 * Run D programs
 * Access aggregates
 * Consume output from D programs

== SYNOPSIS

    require 'dtrace'

    t = DTrace.new 
    progtext = 'ruby$1:::function-entry{ @a[strjoin(strjoin(copyinstr(arg0),"."),copyinstr(arg1))] = count(); } END { printa(@a); }'
    prog = t.compile progtext
    prog.execute

    t.go

    [...]
    
    c = DTraceConsumer.new(t)
    c.consume_once do |rec|
      # handle records
    end

== REQUIREMENTS

 * For the consumer API, platform with DTrace support (Solaris and
   Illumos-derived systems, Mac OS X 10.5+, FreeBSD).
  
 * root, or some/all of the dtrace privileges on Solaris: dtrace_user,
   dtrace_proc and dtrace_kernel.

== INSTALL

 $ sudo gem install ruby-dtrace-consumer

