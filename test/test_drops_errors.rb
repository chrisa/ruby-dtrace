require 'test_helper'

# Tests for the DropData record.

class TestDropsErrors < DTraceTest

  def test_drops
    @dtp.setopt("bufsize", "512")
    @dtp.setopt("strsize", "1024")

    # drp.DTRACEDROP_PRINCIPAL.d
    progtext = <<EOD
BEGIN
{
	trace("Harding");
	trace("Hoover");
	trace("Nixon");
	trace("Bush");
}

BEGIN
{
	exit(0);
}
EOD

    prog = @dtp.compile progtext
    prog.execute

    c = Dtrace::Consumer.new(@dtp)
    assert c

    i = 0
    c.drophandler do |d|
      assert_match(/1 drop on CPU [0-9]+/, d.msg)
      assert_equal "drop to principal buffer", d.kind
      assert_not_nil d.cpu
      assert_equal 1, d.drops
      assert_not_nil d.total
      i = 1
    end

    @dtp.go
    c.consume do |d|
    end

    assert_equal 1, i
  end

  def test_error_handler_too_late
    progtext = <<EOD
BEGIN
{
   *(char *)NULL;
}
EOD

    prog = @dtp.compile progtext
    prog.execute
    @dtp.go

    c = Dtrace::Consumer.new(@dtp)
    assert c

    # since we've already said "go", we now can't apply an error
    # handler (DTrace will let us, but won't call it).
    assert_raise(Dtrace::Exception) do
      c.errhandler do |d|
        # nothing
      end
    end

  end

  def test_errors
    progtext = <<EOD
BEGIN
{
   *(char *)NULL;
}
EOD

    prog = @dtp.compile progtext
    prog.execute

    c = Dtrace::Consumer.new(@dtp)
    assert c

    i = 0
    c.errhandler do |d|
      assert_match(/error on enabled probe ID [0-9]+ \(ID [0-9]+: dtrace:::BEGIN\): invalid address \(0x0\) in action #1 at DIF offset 16/, d.msg)
      assert_not_nil d.cpu
      assert d.action
      assert d.offset
      assert d.fault
      assert_not_nil d.addr
      i = 1
    end

    @dtp.go
    c.consume_once do |d|
    end

    assert_equal 1, i
  end

  def test_error_and_drop_handler
    @dtp.setopt("bufsize", "512")
    @dtp.setopt("strsize", "1024")

    progtext = <<EOD
BEGIN
{
	trace("Harding");
	trace("Hoover");
	trace("Nixon");
	trace("Bush");
}

BEGIN
{
   *(char *)NULL;
}

ERROR
{
    exit(0);
}
EOD

    prog = @dtp.compile progtext
    prog.execute

    c = Dtrace::Consumer.new(@dtp)
    assert c

    errors = 0
    c.errhandler do |d|
      assert_match(/error on enabled probe ID [0-9]+ \(ID [0-9]+: dtrace:::BEGIN\): invalid address \(0x0\) in action #1 at DIF offset 16/, d.msg)
      assert_not_nil d.cpu
      assert d.action
      assert d.offset
      assert d.fault
      assert_not_nil d.addr
      errors = 1
    end

    drops = 0
    c.drophandler do |d|
      assert_match(/1 drop on CPU [0-9]+/, d.msg)
      assert_equal "drop to principal buffer", d.kind
      assert_not_nil d.cpu
      assert_equal 1, d.drops
      assert_not_nil d.total
      drops = 1
    end

    @dtp.go
    c.consume do |d|
    end

    assert_equal 1, errors
    assert_equal 1, drops
  end

end
