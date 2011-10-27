#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::Section::Strtab < Dtrace::Dof::Section
  def initialize(index)
    super(DOF_SECT_STRTAB, index)
    self.data = []
    @idx = 1
  end

  def add(string)
    idx = @idx
    string = string.to_s
    @idx += (string.length + 1)
    self.data << string
    return idx
  end

  def length
    return @idx
  end

  def compute_entsize
    0
  end
end
