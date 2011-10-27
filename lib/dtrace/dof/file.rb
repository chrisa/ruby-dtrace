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

      s.size = length

      loadsz += (s.size + pad) if (s.flags & 1) == 1 # DOF_SECF_LOAD
      filesz += (s.size + pad)

    end

    hdr.loadsz = loadsz
    hdr.filesz = filesz
    hdr.dof_version = dof_version

    self << hdr.generate

    @sections.each do |s|
      self << s.generate_header
    end

    @sections.each do |s|
      self << s.pad if s.pad
      self << s.dof
    end

  end
end

