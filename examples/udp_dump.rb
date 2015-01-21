#!/usr/bin/env ruby

require_relative '../vlink.rb'

# Fetch all broadcast UDP traffic and dump the payloads to stdout
link = VLink.new(ARGV.first || 'eth0')
broadcast = link.ip_addr(0xFFFFFFFF)

loop do
  pkt = link.parse(link.recv)           # grab and parse each packet

  # For every UDP packet bound for the broadcast address...
  if pkt[:protocol] == :udp and pkt[:dst_ip] == broadcast
    puts pkt[:payload].inspect
  end
end
    
