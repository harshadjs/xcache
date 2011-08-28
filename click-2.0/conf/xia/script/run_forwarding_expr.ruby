#!/usr/bin/env ruby

# This script assumes that you have the following files in both ROTUER and PACKETGEN machines
LOAD_CLICK_CMD = "/home/dongsuh/xia-core/click-2.0/load_kernel_click.sh"
IP_ROUTER_SCRIPT = "/home/dongsuh/xia-core/click-2.0/conf/xia/script/run_ip_router.sh"
IP_PKT_GEN_SCRIPT = "/home/dongsuh/xia-core/click-2.0/conf/xia/script/run_ip_pktgen.sh"
XIA_ROUTER_SCRIPT = "/home/dongsuh/xia-core/click-2.0/conf/xia/script/run_xia_router.sh" 
XIA_PKT_GEN_SCRIPT = "/home/dongsuh/xia-core/click-2.0/conf/xia/script/run_xia_pktgen.sh"
RECORD_STAT_SCRIPT = "/home/dongsuh/xia-core/click-2.0/conf/xia/script/record_stat.sh"

SCRIPT = {:XIA => [ XIA_PKT_GEN_SCRIPT, XIA_ROUTER_SCRIPT, 20+64], :IP=>[IP_PKT_GEN_SCRIPT, IP_ROUTER_SCRIPT, 20]}

class Flags
  @flag_bit = 0
  public
  class << self
  def set(*syms)
    syms.each { |s| const_set(s, 2**@flag_bit) ;@flag_bit+=1 }
    const_set(:DEFAULT, syms.first) unless syms.nil?
  end
  end
end

Flags.set(:BACKGROUND_EXIT)

ROUTER="ng2.nan.cs.cmu.edu"
PACKETGEN ="ng3.nan.cs.cmu.edu"
LOCAL = "localhost"

def run_command(machine, cmd, mode = Flags::BACKGROUND_EXIT)
  if (mode & Flags::BACKGROUND_EXIT)
    cmd = "\"#{cmd.to_s} & exit \""
  else
    cmd = "\"#{cmd.to_s} ; exit\""
  end
  ssh = "ssh #{machine} #{cmd}"
  puts ssh
  system(#{ssh})
end

def load_click(machine)
  run_command(machine, LOAD_CLICK_CMD)
end

def collect_stats(machine, size)
  run_command (machine, "#{RECORD_STAT_SCRIPT} #{size}", 0) 
end

if __FILE__ ==$0
  #pkt_size = [ 64, 128, 256, 1024, 1500]
  pkt_size = [90]
  type = [:XIA, :IP]

  pkt_size.each do |size|
    type.each do |t|
      pktgen_script, router_script, hdr_size = SCRIPT[t]
      load_click(ROUTER)
      load_click(PACKETGEN)
      sleep(10)

      # run router
      run_command(ROUTER, router_script)
      # run packet gen
      run_command(PACKETGEN, "#{pktgen_script} #{(size-hdr_size)}")
      
      sleep(20)
      collect_stats(ROUTER, "#{type.to_s}-#{size}")  
      sleep(3)
    end
  end
end

