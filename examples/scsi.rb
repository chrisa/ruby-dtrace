#!/usr/bin/env ruby
require 'rubygems'
require 'dtrace'
require 'getoptlong'

# scsi.rb: part of ruby-dtrace, (c) Chris Andrews, 2007
#
# This is a ruby reimplementation of Chris Gerhard's "scsi.d" script, 
# obtained from here:
#   http://blogs.sun.com/chrisg/resource/scsi_d/scsi.d-1.12
#
# It's meant as an example of how you might use ruby to keep the D
# script simple. For actually debugging SCSI, scsi.d is probably a
# better bet!

class ScsiCdb
  attr_reader :op, :len, :control, :lba, :cdblen

  def initialize(group, cdb_bytes)
    @bytes = cdb_bytes
    @group = group
    parse
  end

  def raw
    @bytes.slice(0, @cdblen).inject('') {|string, b| string + sprintf('%2.2x', b) }
  end

  def parse

    case @group
    when 0
      @lba     = int32([0, @bytes[1] & 0x1f, @bytes[2], @bytes[3]])
      @lbalen  = 6;
      @len     = int8(@bytes[4])
      @control = @bytes[5]
      @sa      = 0
      @cdblen  = 6

    when 1
      @lba     = int32(@bytes[2..5])
      @lbalen  = 8
      @len     = int16(@bytes[7..8])
      @control = @bytes[9]
      @sa      = 0
      @cdblen  = 10
      
    when 2
      @lba     = int32(@bytes[2..5])
      @lbalen  = 8
      @len     = int16(@bytes[7..8])
      @control = @bytes[9]
      @sa      = 0
      @cdblen  = 10      

    when 3
      @lba     = int64(@bytes[12..19])
      @lbalen  = 16;
      @len     = int32(@bytes[28..31])
      @control = @bytes[1]
      @sa      = int16(@bytes[8..9])
      @cdblen  = 32

    when 4
      @lba     = int64(@bytes[2..9])
      @lbalen  = 16
      @len     = int32(@bytes[10.13])
      @control = @bytes[15]
      @sa      = 0
      @cdblen  = 16

    when 5
      @lba     = int32(@bytes[2..5])
      @lbalen  = 8;
      @len     = int32(@bytes[6..9])
      @control = @bytes[11]
      @sa      = 0
      @cdblen  = 12
      
    when 6 .. 7
      @lba     = 0
      @lbalen  = 0
      @len     = 0
      @control = 0
      @sa      = 0

    end

    @op = scsi_op(@bytes[0], @sa)
  end

  private
  def int8(byte)
    return byte & 0x0ff;
  end

  def int16(bytes)
    return (int8(bytes[0]) << 8) + int8(bytes[1])
  end

  def int32(bytes)
    return (int16(bytes[0..1]) << 16) + int16(bytes[2..3])
  end
  
  def int64(bytes)
    return (int32(bytes[0..3]) << 32) + int32(bytes[4..7])
  end

  def scsi_op(code, code2)
    scsi_ops = {
      0x000 => "TEST_UNIT_READY",
      0x001 => "REZERO_UNIT_or_REWIND",
      0x003 => "REQUEST_SENSE",
      0x004 => "FORMAT_UNIT",
      0x007 => "REASSIGN_BLOCKS",
      0x008 => "READ(6)",
      0x00a => "WRITE(6)",
      0x00b => "SEEK(6)",
      0x012 => "INQUIRY",
      0x015 => "MODE_SELECT(6)",
      0x016 => "RESERVE(6)",
      0x017 => "RELEASE(6)",
      0x018 => "COPY",
      0x019 => "ERASE(6)",
      0x01a => "MODE_SENSE(6)",
      0x01b => "START_STOP_UNIT",
      0x01c => "RECIEVE_DIAGNOSTIC_RESULTS",
      0x01d => "SEND_DIAGNOSTIC",
      0x01e => "PREVENT_ALLOW_MEDIUM_REMOVAL",
      0x025 => "READ_CAPACITY(10)",
      0x028 => "READ(10)",
      0x02a => "WRITE(10)",
      0x02b => "SEEK(10)_or_LOCATE(10)",
      0x02e => "WRITE_AND_VERIFY(10)",
      0x02f => "VERIFY(10)",
      0x030 => "SEARCH_DATA_HIGH",
      0x031 => "SEARCH_DATA_EQUAL",
      0x032 => "SEARCH_DATA_LOW",
      0x033 => "SET_LIMITS(10)",
      0x034 => "PRE-FETCH(10)",
      0x035 => "SYNCHRONIZE_CACHE(10)",
      0x036 => "LOCK_UNLOCK_CACHE(10)",
      0x037 => "READ_DEFECT_DATA(10)",
      0x039 => "COMPARE",
      0x03a => "COPY_AND_WRITE",
      0x03b => "WRITE_BUFFER",
      0x03c => "READ_BUFFER",
      0x03e => "READ_LONG",
      0x03f => "WRITE_LONG",
      0x040 => "CHANGE_DEFINITION",
      0x041 => "WRITE_SAME(10)",
      0x04c => "LOG_SELECT",
      0x04d => "LOG_SENSE",
      0x050 => "XDWRITE(10)",
      0x051 => "XPWRITE(10)",
      0x052 => "XDREAD(10)",
      0x053 => "XDWRITEREAD(10)",
      0x055 => "MODE_SELECT(10)",
      0x056 => "RESERVE(10)",
      0x057 => "RELEASE(10)",
      0x05a => "MODE_SENSE(10)",
      0x05e => "PERSISTENT_RESERVE_IN",
      0x05f => "PERSISTENT_RESERVE_OUT",
      0x07f => "Variable_Length_CDB",
      0x080 => "XDWRITE_EXTENDED(16)",
      0x081 => "REBUILD(16)",
      0x082 => "REGENERATE(16)",
      0x083 => "EXTENDED_COPY",
      0x086 => "ACCESS_CONTROL_IN",
      0x087 => "ACCESS_CONTROL_OUT",
      0x088 => "READ(16)",
      0x08a => "WRITE(16)",
      0x08c => "READ_ATTRIBUTES",
      0x08d => "WRITE_ATTRIBUTES",
      0x08e => "WRITE_AND_VERIFY(16)",
      0x08f => "VERIFY(16)",
      0x090 => "PRE-FETCH(16)",
      0x091 => "SYNCHRONIZE_CACHE(16)",
      0x092 => "LOCK_UNLOCK_CACHE(16)_or_LOCATE(16)",
      0x093 => "WRITE_SAME(16)_or_ERASE(16)",
      0x09e => "SERVICE_IN_or_READ_CAPACITY(16)",
      0x0a0 => "REPORT_LUNS",
      0x0a3 => "MAINTENANCE_IN_or_REPORT_TARGET_PORT_GROUPS",
      0x0a4 => "MAINTENANCE_OUT_or_SET_TARGET_PORT_GROUPS",
      0x0a7 => "MOVE_MEDIUM",
      0x0a8 => "READ(12)",
      0x0aa => "WRITE(12)",
      0x0ae => "WRITE_AND_VERIFY(12)",
      0x0af => "VERIFY(12)",
      0x0b3 => "SET_LIMITS(12)",
      0x0b4 => "READ_ELEMENT_STATUS",
      0x0b7 => "READ_DEFECT_DATA(12)",
      0x0ba => "REDUNDANCY_GROUP_IN",
      0x0bb => "REDUNDANCY_GROUP_OUT",
      0x0bc => "SPARE_IN",
      0x0bd => "SPARE_OUT",
      0x0be => "VOLUME_SET_IN",
      0x0bf => "VOLUME_SET_OUT",
      0x0d0 => "EXPLICIT_LUN_FAILOVER",
      0x0f1 => "STOREDGE_CONTROLLER"
    }

    variable_length_ops = {
      0x3 => "XDREAD(32)",
      0x4 => "XDWRITE(32)",
      0x6 => "XPWRITE(32)",
      0x7 => "XDWRITEREAD(32)",
      0x9 => "READ(32)",
      0xb => "WRITE(32)",
      0xa => "VERIFY(32)",
      0xc => "WRITE_AND_VERIFY(32)"
    }

    op = scsi_ops[code]
    if op == 'Variable_Length_CDB'
      return variable_length_ops[code2]
    else
      return op
    end
  end

end

def scsi_reason(code)
  scsi_reasons = {
    0 => "COMPLETED",
    1 => "INCOMPLETE",
    2 => "DMA_ERR",
    3 => "TRAN_ERR",
    4 => "RESET",
    5 => "ABORTED",
    6 => "TIMEOUT",
    7 => "DATA_OVERRUN",
    8 => "COMMAND_OVERRUN",
    9 => "STATUS_OVERRUN",
    10 => "Bad_Message",
    11 => "No_Message_Out",
    12 => "XID_Failed",
    13 => "IDE_Failed",
    14 => "Abort_Failed",
    15 => "Reject_Failed",
    16 => "Nop_Failed",
    17 => "Message_Parity_Error_Failed",
    18 => "Bus_Device_Reset_Failed",
    19 => "Identify_Message_Rejected",
    20 => "Unexpected_Bus_free",
    21 => "Tag_Rejected",
    22 => "TERMINATED",
    24 => "Device_Gone"
  }
  return scsi_reasons[code]
end

timeout = 0
opts = GetoptLong.new([ '-T', GetoptLong::REQUIRED_ARGUMENT ])
opts.each do |opt, arg|
  if opt == '-T'
    timeout = arg
  end
end

devname = ARGV.shift
devinst = ARGV.shift

if devname && devinst
  matchdev = "/this->devname == \"#{devname}\" && this->devinst == #{devinst}/"
elsif devname
  matchdev = "/this->devname == \"#{devname}\"/"
else
  matchdev = ""
end

progtext =<<"EOD"

struct scsi_cdb {
  uint8_t bytes[32];
};

BEGIN
{
        script_start_time = timestamp;
        timeout = #{timeout};
	end_time = timestamp + (timeout * 1000000000);
}

fbt:scsi:scsi_transport:entry,
fbt:scsi:scsi_destroy_pkt:entry
/timeout != 0 && end_time < timestamp/
{
	exit(0);
}

fbt:scsi:scsi_transport:entry,
fbt:scsi:scsi_destroy_pkt:entry
{
	this->pkt = (struct scsi_pkt *)arg0;
	this->scb = (uchar_t *)this->pkt->pkt_scbp;

        this->devinfo = ((struct dev_info *)((this->pkt->pkt_address.a_hba_tran)->tran_hba_dip));
        this->devname = stringof(`devnamesp[this->devinfo->devi_major].dn_name);
        this->devinst = this->devinfo->devi_instance;

        relevant[this->scb] = 0;
}

fbt:scsi:scsi_transport:entry,
fbt:scsi:scsi_destroy_pkt:entry
#{matchdev}
{
        relevant[this->scb] = 1;
}

fbt:scsi:scsi_transport:entry
/relevant[this->scb] == 1/
{
	start_time[this->scb] = timestamp;
	this->dir = 1;
}

fbt:scsi:scsi_destroy_pkt:entry
/relevant[this->scb] == 1/
{
	req_time[this->scb] = start_time[this->scb] != 0 ?
		    (timestamp - start_time[this->scb])/1000 : 0;
        start_time[this->scb] = 0;
	this->dir = 0;
}

fbt:scsi:scsi_transport:entry,
fbt:scsi:scsi_destroy_pkt:entry
/relevant[this->scb] == 1/
{
	this->cdb = (uchar_t *)this->pkt->pkt_cdbp;
	this->group = ((this->cdb[0] & 0xe0) >> 5);

        /* timestamp */
	trace((timestamp - script_start_time)/1000000000);
        trace((timestamp - script_start_time)%1000000000);

        /* devname, devinst */
        trace(this->devname);
        trace(this->devinst);

        /* scsi cdb */
        trace(this->cdb);
        trace(this->group);
        trace(*(struct scsi_cdb *)(this->cdb));

        /* command or response? */
        trace(this->dir);

        /* target and LUN */
        trace(this->pkt->pkt_address.a_target);
	trace(this->pkt->pkt_address.a_lun);

        /* timeout */
        trace(this->pkt->pkt_time);

        /* executable and pid, for commands */
        trace(execname);
        trace(pid);

        /* reason and state, for responses */
        trace(this->pkt->pkt_reason);
        trace(this->pkt->pkt_state);

        /* elapsed time for this command/response */
        trace(req_time[this->scb]);
        req_time[this->scb] = 0;

        relevant[this->scb] = 0;
}

EOD
#`

t = Dtrace.new 
t.setopt("bufsize", "4m")
prog = t.compile progtext
prog.execute
t.go

begin
  c = DtraceConsumer.new(t)
  
  c.consume do |e|
    records = e.records
    
    # D exit at timeout
    if records.length == 1 && records[0].value == 0
      exit 0
    end
    
    # first two elements are timestamp
    t = sprintf("%05.5d.%09.9d", records.shift.value, records.shift.value)

    # next two elements are devname/devinst
    dev = sprintf('%s%d', records.shift.value, records.shift.value)
    
    # next is CBDP, group, then 32 bytes of CDB
    cdbp = records.shift.value
    group = records.shift.value
    cdb_bytes = records.shift.value
    
    # then dir flag
    dir = (records.shift.value == 1) ? '->' : '<-'

    # address
    address_target = records.shift.value
    address_lun    = records.shift.value

    # timeout
    timeout = records.shift.value

    # execname and pid
    execname = records.shift.value
    pid      = records.shift.value
    
    # reason, state, request time
    reason   = records.shift.value
    state    = records.shift.value
    req_time = records.shift.value

    # parse the CDB
    cdb = ScsiCdb.new(group, cdb_bytes)
    
    printf "%s %s:%s 0x%2.2x %9s address %2.2d:%2.2d, lba 0x%08x, len 0x%6.6x, control 0x%2.2x timeout %d CDBP 0x%x", 
    t, dev, dir, cdb_bytes[0], cdb.op, address_target, address_lun, 
    cdb.lba, cdb.len, cdb.control, timeout, cdbp, execname, pid

    case dir
    when '->'
      printf " %s(%d) cdb(%d) %s\n", execname, pid, cdb.cdblen, cdb.raw
    when '<-'
      printf ", reason 0x%x (%s) state 0x%x Time %dus\n", reason, scsi_reason(reason), state, req_time
    end
  end
  
rescue Interrupt => e
  exit
end

