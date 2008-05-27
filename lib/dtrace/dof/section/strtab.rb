#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::Section::Strtab < Dtrace::Dof::Section
  def initialize(strings, index)
    super(DOF_SECT_STRTAB, index)
    
    # to_s and uniq the strings, and save them 
    self.data = strings.map {|s| s.to_s }.uniq

    # compute and save the stridx values
    @strings = Hash.new
    i = 1
    self.data.each do |s|
      @strings[s] = i
      i += (s.length + 1)
    end
  end

  def stridx(string)
    return @strings[string.to_s]
  end
end
