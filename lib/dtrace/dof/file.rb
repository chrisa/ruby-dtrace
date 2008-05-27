#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::File
  include Dtrace::Dof::Constants
  attr_accessor :sections

  def initialize
    @sections = []
  end

  def generate
    hdr = Dtrace::Dof::Header.new
    hdr.secnum = @sections.length
    filesz = hdr.hdrlen
    loadsz = filesz
    dof_version = 1

    @sections.each do |s|
      # Presence of is_enabled probes forces DOF version 2.
      if s.section_type == DOF_SECT_PRENOFFS
        dof_version = 2
      end
      
      length = s.generate
      s.offset = filesz

      pad = 0
      if s.align > 1
        i = s.offset.to_f % s.align
        if i > 0
          pad = (s.align - i).to_i
          s.offset = pad + s.offset
          s.pad = "\000" * pad
        end
      end

      s.size = length + pad

      loadsz += s.size if (s.flags & 1) == 1 # DOF_SECF_LOAD
      filesz += s.size

    end
    
    hdr.loadsz = loadsz
    hdr.filesz = filesz
    hdr.dof_version = dof_version

    dof = String.new
    dof << hdr.generate
    
    @sections.each do |s|
      dof << s.generate_header
    end
      
    @sections.each do |s|
      dof << s.pad if s.pad
      dof << s.dof
    end

    dof
  end
end
  
