#!/usr/bin/env ruby

require_relative '../vlink.rb'

# Fetch all broadcast UDP traffic and dump the payloads to stdout
link = VLink.new(ARGV.first || 'eth0')
loop do
  pkt = link.parse(link.recv)           # brab and parse each packet
  dst = link.ip_addr(0xFFFFFFFF)

  # For every ARP request...
  if pkt[:protocol] == :udp and pkt[:dst_ip] == dst
    $stdout.print(pkt[:payload])
  end
end
    
