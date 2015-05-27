module Socket2
  VERSION = "0.1.0"
end

require 'socket'

class Socket

  SIOCGIFINDEX    = 0x8933   # bits/ioctls.h
  SIOCGIFHWADDR   = 0x8927   # linux/sockios.h

  # linux/if_ether.h, needs to be native-endian uint16_t
  ETH_P_ALL = [ 0x0003 ].pack('S>').unpack('S').first

  # Bind a layer-2 raw socket to the given interface
  def bind_if(interface)
    # Get the system's internal interface index value
    ifreq = [ interface, '' ].pack('a16a16')
    self.ioctl(SIOCGIFINDEX, ifreq)
    index_str = ifreq[16, 4]

    # Build our sockaddr_ll struct so we can bind to this interface. The struct
    # is defined in linux/if_packet.h and requires the interface index.
    sll = [ Socket::AF_PACKET, ETH_P_ALL, index_str ].pack('SS>a16')
    self.bind(sll)
  end

end

# Example
# -------
#
# 1) Create a raw, layer-2 socket:
#   sock = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)
#
# 2) Bind to a network interface:
#   sock.bind_if('eth0')
#
# 3) Receive a packet starting at the beginning of its Ethernet header:
#   payload, peer_addr = sock.recvfrom(1514)
#
# 4) Send that same raw packet:
#   sock.send(payload, 0)
#
# 5) Fetch the MAC address of the bound interface:
#   sock.local_address.to_sockaddr[-6, 6]
#
#
# License
# -------
# MIT
