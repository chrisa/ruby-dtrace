#
# Ruby-Dtrace
# (c) 2008 Chris Andrews <chris@nodnol.org>
#

class Dtrace::Dof::Section
  include Dtrace::Dof::Constants
  attr_writer :data, :offset, :size
  attr_reader :flags
  
  def initialize(type, index)
    @section_type  = type
    @index         = index
    @flags         = 1 # DOF_SECF_LOAD
  end

  def generate
    case @section_type
    when DOF_SECT_COMMENTS
      @dof = dof_generate_comments
    when DOF_SECT_STRTAB
      @dof = dof_generate_strtab
    when DOF_SECT_PROBES
      @dof = dof_generate_probes
    when DOF_SECT_PRARGS
      @dof = dof_generate_prargs
    when DOF_SECT_PROFFS
      @dof = dof_generate_proffs
    when DOF_SECT_PRENOFFS
      @dof = dof_generate_prenoffs
    when DOF_SECT_PROVIDER
      @dof = dof_generate_provider
    when DOF_SECT_RELTAB
      @dof = dof_generate_reltab
    when DOF_SECT_URELHDR
      @dof = dof_generate_urelhdr
    when DOF_SECT_UTSNAME
      @dof = dof_generate_utsname
    else
      @dof = ''
    end
  end
end
