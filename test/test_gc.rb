require 'test_helper'

class TestGc < DTraceTest

  def test_gc_after_close
    @dtp.close
    @dtp = nil
    GC.start
  end

end
