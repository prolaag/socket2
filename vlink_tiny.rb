# encoding: ASCII-8BIT

require 'socket'

# This class provides raw, layer-2 packet access - no more, no less.
class VLinkTiny
  ETH_P_ALL       = 0x00_03   # linux/if_ether.h
  SIOCGIFINDEX    = 0x89_33   # bits/ioctls.h
  SIOCGIFHWADDR   = 0x89_27   # linux/sockios.h

  def initialize(interface)
    @eth_p_all_hbo = [ ETH_P_ALL ].pack('S>').unpack('S').first
    @raw = Socket.open(AF_PACKET, Socket::SOCK_RAW, @eth_p_all_hbo)

    # Use an ioctl to get the MAC address of the provided interface
    ifreq = [ interface ].pack('a32')
    @raw.ioctl(SIOCGIFHWADDR, ifreq)
    @src_mac = ifreq[18, 6]

    # Also get the system's internal interface index value
    ifreq = [ interface ].pack('a32')
    @raw.ioctl(SIOCGIFINDEX, ifreq)
    index_str = ifreq[16, 4]

    # Construct our sockaddr_ll structure.  This is defined in
    # linux/if_packet.h, and it requires the interface index
    @sll = [ AF_PACKET ].pack('S')    # needs to be in HBO
    @sll << [ ETH_P_ALL ].pack('S>')  # needs to be in NBO
    @sll << index_str    # ifr_ifindex field of ifreq structure
    @sll << ("\x00" * 12)
    @raw.bind(@sll)
  end
  attr_accessor :src_mac
  attr_reader :raw

  # Send raw data out of our little socket.  Provide an ethernet frame
  # starting at the 6-byte destination MAC address.
  def inject(frame)
    @raw.send(frame, Socket::SOCK_RAW, @sll)
  end

  # Receive and return one raw frame.
  def recv
    @raw.recvfrom(4000).first
  end

end
