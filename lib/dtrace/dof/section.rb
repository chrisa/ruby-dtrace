#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::Section
  include Dtrace::Dof::Constants
  attr_writer :entsize
  attr_accessor :flags, :data, :offset, :align, :pad, :size
  attr_reader :section_type, :dof
  
  def initialize(type, index)
    @section_type  = type
    @index         = index
    @flags         = 1 # DOF_SECF_LOAD
  end

  def generate
    case @section_type
    when DOF_SECT_COMMENTS
      @align = 1
      @dof = dof_generate_comments
    when DOF_SECT_STRTAB
      @align = 1
      @dof = dof_generate_strtab
    when DOF_SECT_PROBES
      @align = 8
      @dof = dof_generate_probes
    when DOF_SECT_PRARGS
      @align = 1
      @dof = dof_generate_prargs
    when DOF_SECT_PROFFS
      @align = 4
      @dof = dof_generate_proffs
    when DOF_SECT_PRENOFFS
      @align = 4
      @dof = dof_generate_prenoffs
    when DOF_SECT_PROVIDER
      @align = 4
      @dof = dof_generate_provider
    when DOF_SECT_RELTAB
      @align = 8
      @dof = dof_generate_reltab
    when DOF_SECT_URELHDR
      @align = 4
      @dof = dof_generate_relhdr
    when DOF_SECT_UTSNAME
      @align = 1
      @dof = dof_generate_utsname
    else
      @dof = ''
    end

    begin
      if @data.class == Array
        @entsize = @dof.length / @data.length
      else
        @entsize = 0
      end
    rescue ZeroDivisionError
      @entsize = 0
    end

    return @dof.length
  end
end
