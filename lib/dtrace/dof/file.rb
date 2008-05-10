#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::File
  attr_accessor :sections

  def initialize
    @sections = []
  end

  def generate
    filesz = 0
    loadsz = 0
    sec_offsets = []
    sec_sizes = []

    @section_data = @sections.map do |s|
      sec_offsets << filesz

      dof = s.generate
      sec_sizes << dof.length
      
      # Include in loadable part of file?
      if s.flags & 1 # DOF_SECF_LOAD
        loadsz += dof.length
      end

      filesz += dof.length

      # for dofs_entsize:
      begin
        if s.data.class == Array
          len = s.data.length
          entsize = dof.length / s.data.length
          s.entsize = entsize
        end
      rescue ZeroDivisionError
        s.entsize = 0
      end

      dof
    end
    
    hdr = Dtrace::Dof::Header.new
    hdr.loadsz = loadsz
    hdr.filesz = filesz
    hdr.secnum = @sections.length

    dof = String.new
    dof << hdr.generate
    
    @sections.each do |s|
      s.offset = sec_offsets.shift + hdr.hdrlen
      s.size = sec_sizes.shift
      sec_hdr = s.generate_header
      dof << sec_hdr
    end
      
    @section_data.each do |d|
      dof << d
    end

    dof
  end
end
  
