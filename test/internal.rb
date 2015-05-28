#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# This test constructs a tap interface that responds to all ping packets,
# then opens a layer-2 raw socket on that interface to inject pings and receive
# responses.

require 'ipaddr'
require 'test/unit'
require_relative '../lib/socket2'
require_relative '../extra/vtap.rb'

class TapTestHelper

  def initialize
    @tap_name = "ttap#{rand(9000) + 1000}"
    @tap = VTap.new(@tap_name)
    @ping_thread = nil
    @sock = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)
    @sock.bind_if @tap_name
  end
  attr_reader :tap_name, :tap, :sock, :ping_thread

  # This method spawns a thread
  def answer_pings
    @ping_thread = Thread.new do
      begin
        loop do
          pkt = @tap.recv
          icmp = icmp_offset(pkt)
          if icmp and pkt[icmp] == "\x08"      # type == Echo Request
            pkt[icmp, 1] = "\x00"              # type == Echo Reply
            pkt[26, 4], pkt[30, 4] = pkt[30, 4], pkt[26, 4]  # reverse IPs
            @tap.inject(pkt)
          end
        end
      rescue Object
        $stderr.puts $!
        $stderr.puts $@
        Kernel.exit(1)
      end
    end
  end

  # If this is an IPv4 ICMP packet, return its payload offset, otherwise
  # return false / nil
  def icmp_offset(pkt)
    return false unless pkt[12, 2] == "\x08\x00" and  # ethertype = IPv4
                        pkt[23, 1] == "\x01"          # IPProto = ICMP
    offset = 14 + ([ pkt[14].ord & 0x0F, 5 ].max * 4)
  end

  # Return the MAC address of the tap device
  def tap_mac
    @sock.local_address.to_sockaddr[-6, 6]
  end

  # Wait for and return the next ping reply on the raw socket up to timeout
  def ping_reply(timeout = 1.0)
    loop do
      st = Time.now.to_f
      act = select([@sock], [], [@sock], timeout)
      return nil if !act or act.first.empty?
      pkt = @sock.recv(1514)
      icmp = icmp_offset(pkt)
      return pkt if icmp and pkt[icmp] == "\x00"   # type = Echo Reply
      timeout = timeout - Time.now.to_f + st
      return nil if timeout <= 0
    end
  end

  # Send the given raw layer-2 packet to the tap
  def inject(frame)
    @sock.send(frame, 0)
  end

end

class TestSocket2 < Test::Unit::TestCase

  def setup
    begin
      @tt = TapTestHelper.new
    rescue Errno::EPERM
      $stderr.puts "You must be root to create raw sockets"
      Kernel.exit(1)
    end

    # Tell the test tap to respond to ping packets
    @tt.answer_pings

    # Define a basic ping packet manually
    @ping = [
      # Ethernet header
      @tt.tap_mac,                           # dst MAC
      @tt.tap_mac,                           # source MAC
      [ 0x0800 ].pack('S>'),                 # IPv4 ethertype

      # IP header
      [ 0x45, 0, 20 + 8 ].pack('CCS>'),      # version, IHL, header + total len
      [ rand(2**16), 0 ].pack('S>S>'),       # packet ID, fragmentation
      [ 64, 1, rand(2**16) ].pack('CCS>'),   # TTL, protocol, garbage checksum
      IPAddr.new('1.2.3.4').hton,            # src IP
      IPAddr.new('9.8.7.6').hton,            # dst IP

      # ICMP
      [ 8, 0, 0, 0 ].pack('CCS>L>'),         # type, code, checksum, RoH
    ].join
  end

  # Inject the ping, wait for a reply
  def test_ping_basic
    @tt.sock.send(@ping, 0)
    pong = @tt.ping_reply
    assert_equal(42, pong.length)
    assert_equal(pong[0, 6], @tt.tap_mac)
    assert_equal(pong[30, 4], @ping[26, 4])
    assert_equal(pong[26, 4], @ping[30, 4])
  end

end
