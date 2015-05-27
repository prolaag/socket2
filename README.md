socket2
=======

Addition to the native Socket class that allows layer-2 raw packet manipulation in Ruby (for Linux)

Ruby only natively supports raw socket access at the network (IP) layer. This is fine if you want the system to perform services on your behalf such as address resolution, but those who want complete control have only been left with options that take us out of pure Ruby space.

This single-file, pure-Ruby class provides an alternative: Access to raw sockets at the data-link (Ethernet) layer without an intermediary like libpcap.

### Dependencies

None.

### Platform

* Linux
* Ruby 1.9

### License

MIT

### Example

```ruby
require_relative 'socket2.rb'

# Create a layer-2 socket in a mostly familiar way
sock = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)

# Bind that socket to an interface
sock.bind_if(ARGV.first || 'eth0')

# Receive a packet starting at the beginning of its Ethernet header
payload, peer_addr = sock.recvfrom(1514)

# Send out that same raw packet
sock.send(payload, 0)
```

### How does it work?

This file opens the Socket class and adds three constants and one method to support layer-2 raw sockets. The ```bind_if()``` method manually crafts the arguments and structures normally found in linux/if_ether.h, bits/ioctls.h, and linux/sockios.h - in particular the sockaddr_ll (link layer) address structure and ifreq interface indexing structure. Ruby 1.9 doesn't define these structures for you, but we assemble the raw memory representations of those structures ourselves and Ruby passes them along through the necessary ioctl() calls.
