vlink
=====

Layer-2 raw packet manipulation in Ruby (for Linux)

Ruby only natively supports raw socket access at the network (IP) layer.  This is fine if you want the system to perform services on your behalf such as address resolution, but those of us who want complete control have only been left with options that take us out of pure Ruby space.

This single-file, pure-Ruby class provides an alternative: Access to raw sockets at the data-link (Ethernet) layer without an intermediary like libpcap.

### Dependencies

None.  That's the point.

### Platform

* Linux
* Ruby 1.9

### License

Public domain.  Enjoy.

### Example

```ruby
# Be an ill-behaved network citizen and claim ownership of all IP addresses
# using ARP.
require_relative 'vlink.rb'

link = VLink.new(ARGV.first || 'eth0')
loop do
  pkt = link.parse(link.recv)           # brab and parse each packet

  # For every ARP request...
  if pkt[:protocol] == :arp and pkt[:operation] == :request
    reply = link.reverse(pkt)           # base our reply off the request
    reply[:sender_mac] = link.src_mac   # claim that IP belongs to our MAC
    reply[:operation] = :reply          # indicate to ARP that this is a reply
    link.unparse(reply)                 # send the packet
  end
end
```

### How does it work?

The VLink initializer manually crafts the arguments and structures normally found in linux/if_ether.h, bits/ioctls.h, and linux/sockios.h - in particular the sockaddr_ll (link layer) address structure and ifreq interface indexing structure.  Ruby 1.9 doesn't define these structures for you, but if you assemble the raw memory representations of those structures yourself, Ruby will pass them along through the ioctl() calls necessary to operate at layer 2.

### For which protocols do you provide additional, high-level support?
- IPv4
- TCP
- UDP
- ARP
- ICMP

### Why do you include a pseudo-random number generator?

Determinism.  We use VLink as a QA tool, and we fields like IPv4 fragment IDs and TCP SEQ numbers to be consistent from one invocation to the next.

### Do you have an ultra-minimalist version of the library available?

Naturally.  vlink_tiny.rb
