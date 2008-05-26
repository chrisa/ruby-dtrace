#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::Section::Strtab < Dtrace::Dof::Section
  def initialize(strings, index)
    super(DOF_SECT_STRTAB, index)
    
    # uniq the strings, and save them 
    strings.uniq!
    self.data = strings

    # compute and save the stridx values
    @strings = Hash.new
    i = 1
    strings.each do |s|
      @strings[s] = i
      i += (s.length + 1)
    end
  end

  def stridx(string)
    return @strings[string]
  end
end
