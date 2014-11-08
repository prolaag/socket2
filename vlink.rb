# encoding: ASCII-8BIT

require 'socket'
require 'ipaddr'

# This class provides raw, layer-2 packet access to a single device.
# Arbitrary ethernet payloads can be injected and received, though some
# convenience functions exist on top:
#  Sending:
#  ===============
#    frame() - send a properly constructed ethernet frame with given payload
#    packet() - send a properly formatted IPv4/6 packet with a given payload
#    segment() - send a TCP segment with the given payload
#    datagram() - send a UDP datagram with the given payload
#    control_message() - send an ICMP packet
#    arp() - send an ARP request or reply
#    unparse() - send a packet and option hash exactly as produced by parse()
#
#  Receiving:
#  ===============
#    parse() - parses a raw packet received through recv() and returns an
#      appropriate "opts" hash and the highest payload level parseable.
#      packet types are :ethernet, :ipv4, :ipv6, :tcp, :udp, :arp.
#
#  opts Hash:
#  ===============
#    :src/dst_mac - six byte NBO mac address
#    :src/dst_ip - IPv4 or IPv6 address
#    :src/dst_port - integer 1-65535 representing TCP/UDP port
#    :norecurse - flag indicating non-recursive construction
#    :noinject - flag that no injection should be performed, only construction
#    :flags - array of TCP flags to be set on segments, :syn, :ack, :fin, :rst
#    :frag - hash of fragmentation options, :df, :mf, and :offset
#    :seq - sequence number (TCP only)
#    :ack - acknowledgement number (TCP only)
#    :window - flow control window to advertise (TCP only, defaults to 0x8000)
#    :sender/target_mac - six byte NBO mac address for ARP packets
#    :sender/target_ip - IPv4 (not IPv6) address for ARP packets
class VLink
  ETH_P_ALL       = 0x00_03   # linux/if_ether.h
  SIOCGIFINDEX    = 0x89_33   # bits/ioctls.h
  SIOCGIFHWADDR   = 0x89_27   # linux/sockios.h
  IFR_HWADDR_OFF  = 18        # offset of MAC data in ifreq struct
  AF_INET         = Socket::AF_INET       #  2
  AF_INET6        = Socket::AF_INET6      # 10
  AF_PACKET       = Socket::AF_PACKET     # 17
  LCG_A           = 6364136223846793005
  LCG_C           = 1442695040888963407
  IP_PROTO_TCP    = Socket::IPPROTO_TCP   #  6
  IP_PROTO_UDP    = Socket::IPPROTO_UDP   # 17
  IP_PROTO_ICMP   = Socket::IPPROTO_ICMP  #  1
  ETHERTYPE_IP    = 0x0800
  ETHERTYPE_IPV6  = 0x86dd
  ETHERTYPE_ARP   = 0x0806

  # Provide the name of a physical interface (eth0), or nil if you don't
  # want to bind to an interface at all.
  def initialize(interface)
    @pseed = 2147483587
    @dst_mac = "\xff" * 6    # broadcast by default

    # Without an interface use a dummy source MAC
    unless interface
      @src_mac = "SRCMAC"
      return nil
    end

    # Open our layer-2 raw socket
    @eth_p_all_hbo = [ ETH_P_ALL ].pack('S>').unpack('S').first
    @raw = Socket.open(AF_PACKET, Socket::SOCK_RAW, @eth_p_all_hbo)

    # Use an ioctl to get the MAC address of the provided interface
    ifreq = [ interface ].pack('a32')
    @raw.ioctl(SIOCGIFHWADDR, ifreq)
    @src_mac = ifreq[IFR_HWADDR_OFF, 6]

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

    # The setsockopt() call with SO_BINDTODEVICE only binds the socket to the
    # given interface for the purpose of sending.  bind(), on the other hand,
    # works for both.  So that's all we call.
    # @raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, interface)
    # @raw.getsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF).inspect
    @raw.bind(@sll)
  end
  attr_accessor :src_mac, :dst_mac
  attr_reader :raw


  ##  Core injection and reception functions  ##

  # Send raw data out of our little socket.  Provide an ethernet frame
  # starting at the 6-byte destination MAC address.
  def inject(frame)
    @raw.send(frame, Socket::SOCK_RAW, @sll) if @raw
  end

  # Receive and return one raw frame.
  def recv
    @raw.recvfrom(4000).first if @raw
  end


  ##  Packet injection  ##

  # Construct an ethernet frame with the given payload and ethertype
  def frame(ethertype, payload, opts = {})
    src_mac = opts[:src_mac] || @src_mac
    dst_mac = opts[:dst_mac] || @dst_mac
    ethertype = [ ethertype ].pack('S>') if ethertype.class <= Integer
    frm = dst_mac + src_mac + ethertype + payload
    inject(frm) unless opts[:noinject] or opts[:norecurse]
    frm
  end

  # Construct an ARP packet that's either a :request or a :reply.  Only IPv4
  # over ethernet is supported
  def arp(operation, opts = {})
    sender_mac = opts[:sender_mac] || opts[:src_mac] || @src_mac
    target_mac = opts[:target_mac] || "\x00\x00\x00\x00\x00\x00"
    sender_ip = ip_addr(opts[:sender_ip])
    target_ip = ip_addr(opts[:target_ip])
    unless sender_ip.length == 4 and target_ip.length == 4
      raise "ARP: not an IPv4 address"
    end

    # Construct our packet.  All types have the same form
    pkt = "\x00\x01\x08\x00\06\x04"   # hardware/protocol type and sizes
    pkt << { :request => "\x00\x01", :reply => "\x00\x02" }[operation]
    pkt << sender_mac
    pkt << sender_ip
    pkt << target_mac
    pkt << target_ip
    return frame(ETHERTYPE_ARP, pkt, opts) unless opts[:norecurse]
    pkt
  end

  # Construct an IP packet with the given payload and next protocol
  def packet(protocol, payload, opts = {})
    src_ip = ip_addr(opts[:src_ip])
    dst_ip = ip_addr(opts[:dst_ip])
    pkt = ''
    ipsum_offset = tcpsum_offset = nil
    ipo = opts[:ip_options] || ''
    raise "IP options must be a multiple of 4 bytes" if ipo.length % 4 != 0
    raise "IP options too long" if ipo.length > 40

    # IPv4 header
    if src_ip.length == 4 and dst_ip.length == 4
      frag = 0

      # Calculate our fragmentation fields
      if opts[:frag]
        frag |= 0x4000 if opts[:frag][:df]
        frag |= 0x2000 if opts[:frag][:mf]
        offset = opts[:frag][:offset].to_i
        if (offset & 7) != 0 or offset > 65528 or offset < 0
          raise "invalid IP fragment offset"
        end
        frag += (offset / 8)
      end

      # Pre-pack our numeric fields.  Total length, in this case, hard codes
      # a fixed header length, which allows for no IP options.
      total_len = [ payload.length + 20 + ipo.length ].pack('S>')
      hdr = (0x45 + (ipo.length / 4)).chr
      frag = [ frag ].pack('S>')

      # Construct our packet
      pkt << "#{hdr}\x00#{total_len}"    # IP version, ToS, length
      pkt << "#{prand(2)}#{frag}\x40"    # ID, fragmentation, TTL
      pkt << protocol.chr                # transport protocol
      ipsum_offset = pkt.length          # IP checksum offset for later
      pkt << "\x00\x00"                  # checksum placeholder
      pkt << src_ip
      pkt << dst_ip
      pkt << ipo
      tcpsum_offset = pkt.length + 16    # TCP checksum offset for later
      pkt << payload.to_s

    # IPv6 header
    elsif src_ip.length == 16 and dst_ip.length == 16
      # ADD CODE HERE
      raise "IPv6 not yet supported"
    else
      raise "IP version mismatch"
    end

    # Now if we're using TCP, we need to calculate its checksum
    if protocol == IP_PROTO_TCP
      checksum = 6 + payload.length
      pos = ipsum_offset + 2
      while pos < pkt.length
        checksum += (pkt[pos].ord << 8) + (pkt[pos+1] || 0).ord
        checksum = (checksum + 1) & 0xFFFF if checksum > 0xFFFF
        pos += 2
      end
      checksum = checksum ^ 0xFFFF
      pkt[tcpsum_offset, 2] = [ checksum ].pack('S>')
    end

    # Finally, calculate the IP checksum (unless IPv6, which has no checksum)
    if src_ip.length == 4
      pos = checksum = 0
      while pos < 20 + ipo.length
        checksum += (pkt[pos].ord << 8) + pkt[pos + 1].ord;
        checksum = (checksum + 1) & 0xFFFF if checksum > 0xFFFF
        pos += 2
      end
      checksum = checksum ^ 0xFFFF
      pkt[ipsum_offset, 2] = [ checksum ].pack('S>')
    end

    # If we're injecting, recurse down
    return frame(ETHERTYPE_IP, pkt, opts) unless opts[:norecurse]
    pkt
  end

  # Create a TCP segment with the provided payload
  def segment(payload, opts = {})
    src_port = opts[:src_port].to_i
    dst_port = opts[:dst_port].to_i
    seq, ack = opts[:seq].to_i, opts[:ack].to_i
    fw = opts.fetch(:window, 0x8000)

    # Validate our flags
    flags = opts.fetch(:flags, [:ack])
    unless flags.include?(:ack) or flags.include?(:syn)
      raise "TCP segments must have either SYN or ACK set"
    end
    ack = 0 unless flags.include?(:ack)

    # Construct the segment, starting with src and dst ports
    seg = [src_port].pack('S>') + [dst_port].pack('S>')
    seg << [seq].pack('L>') + [ack].pack('L>')         # sequence numbers
    flag_bits = 0
    flag_bits |= 0x01 if flags.include?(:fin)
    flag_bits |= 0x02 if flags.include?(:syn)
    flag_bits |= 0x04 if flags.include?(:rst)
    flag_bits |= 0x08 if flags.include?(:psh)
    flag_bits |= 0x10 if flags.include?(:ack)
    seg << "\x50#{flag_bits.chr}#{[fw].pack('S>')}"    # hdr_len, flags, window
    seg << "\x00\x00\x00\x00"                          # checksum, URG pointer
    seg << payload.to_s
    return packet(IP_PROTO_TCP, seg, opts) unless opts[:norecurse]
    seg    
  end

  # Create a UDP datagram with the provided payload
  def datagram(payload, opts = {})
    src_port = (opts[:src_port]).to_i
    dst_port = (opts[:dst_port]).to_i
    dgram = [src_port].pack('S>') + [dst_port].pack('S>')
    dgram << [payload.length + 8].pack('S>')    # total length
    dgram << "\x00\x00"                         # zero out the checksum
    dgram << payload.to_s
    return packet(IP_PROTO_UDP, dgram, opts) unless opts[:norecurse]
    dgram
  end

  # Create an ICMP control message with the provided payload.  The checksum
  # will be inserted over the 3rd and 4th bytes of the provided payload.
  def control_message(payload, opts = {})
    msg = payload.dup
    msg[2, 2] = "\0\0"

    # Calculate the checksum
    checksum = pos = 0
    while pos < msg.length do
      checksum += (msg[pos].ord << 8) + (msg[pos+1] || 0).ord
      checksum = (checksum + 1) & 0xFFFF if checksum > 0xFFFF
      pos += 2
    end
    checksum = checksum ^ 0xFFFF
    msg[2, 2] = [ checksum ].pack('S>')
    return packet(IP_PROTO_ICMP, msg, opts) unless opts[:norecurse]
    msg
  end


  ##  Frame parsing and unparsing  ##

  # Parse a received frame up to the highest level understood by VLink.  If
  # a parsing error was encountered, it will be made available in :error.
  def parse(frame)
    opts = { :frame => frame,
             :dst_mac => frame[0, 6],
             :src_mac => frame[6, 6],
             :ethertype => frame[12, 2].unpack('S>').first }

    # Parse out our different layer 3 protocols
    parser = { ETHERTYPE_ARP => :parse_arp,
               ETHERTYPE_IP => :parse_ipv4,
               ETHERTYPE_IPV6 => :parse_ipv6 }[opts[:ethertype]]
    begin
      return method(parser).call(frame[14..-1], opts) if parser
    rescue
      opts[:error] = $!.to_s
    end

    # If we got this far, all we know is that it's an ethernet frame
    opts[:protocol] = :ethernet
    opts[:payload] = frame[14..-1]
    return opts
  end

  def parse_arp(data, opts)
    if data.length < 28 or data[0, 6] != "\x00\x01\x08\x00\x06\x04"
      raise "ARP: truncated packet or not ethernet-IP"
    end
    op = { "\x00\x01" => :request, "\x00\x02" => :reply }[data[6, 2]]
    raise "ARP: invalid operation" unless op
    opts[:operation] = op
    opts[:sender_mac] = data[8, 6]
    opts[:sender_ip] = data[14, 4]
    opts[:target_mac] = data[18, 6]
    opts[:target_ip] = data[24, 4]
    opts[:protocol] = :arp
    return opts
  end

  def parse_ipv4(data, opts)
    raise "IPv4: truncated packet" unless data.length > 20

    # Parse and validate the header
    hdr_len = (data[0].ord - 0x40) * 4
    raise "IPv4: invalid hdr_len" if hdr_len > data.length or hdr_len < 20
    payload_len = data[2, 2].unpack('S>').first - hdr_len
    raise "IPv4: truncated payload" if payload_len + hdr_len > data.length
    raise "IPv4: negative payload length" if payload_len < 0
    payload = data[hdr_len, payload_len]

    # Gather and store fragmentation data
    frag_bits = data[6, 2].unpack('S>').first
    if frag_bits != 0
      opts[:frag] = frag = { :offset => frag_bits & 0x1FFF }
      frag[:mf] = true if (frag_bits & 0x2000) != 0
      frag[:df] = true if (frag_bits & 0x4000) != 0
    end

    # It all looks good, construct our packet description
    opts[:transport] = data[9].ord
    opts[:src_ip] = data[12, 4]
    opts[:dst_ip] = data[16, 4]

    # Don't parse any higher-layer protocols if this is a fragment
    opts[:transport] = 0 if (frag_bits & 0x3FFF) > 0

    # Recurse into the payload if we understand the transport protocol
    parser = { IP_PROTO_TCP => :parse_tcp,
               IP_PROTO_UDP => :parse_udp }[opts[:transport]]
    begin
      return method(parser).call(payload, opts) if parser
    rescue
      opts[:error] = $!.to_s
    end

    # If we got this far, all we know is that it's an IP packet
    opts[:protocol] = :ipv4
    opts[:protocol] = :icmp if opts[:transport] == IP_PROTO_ICMP
    opts[:payload] = payload
    return opts
  end

  def parse_ipv6(data, opts)
    raise "IPv6: not yet supported"
  end

  def parse_tcp(data, opts)
    raise "TCP: truncated segment" if data.length < 20

    # Validate the header.  If reserved bits are set, meh
    hdr_len = data[12].ord >> 2
    raise "TCP: invalid hdr_len" if data.length < hdr_len or hdr_len < 20

    # Okay, this looks good, construct our segment description
    hdr_vals = data.unpack('S>S>L>L>')
    opts[:src_port], opts[:dst_port], opts[:seq], opts[:ack] = hdr_vals
    flag_bits = data[13].ord
    flags = opts[:flags] = []
    flags << :fin if (flag_bits & 0x01) != 0
    flags << :syn if (flag_bits & 0x02) != 0
    flags << :rst if (flag_bits & 0x04) != 0
    flags << :psh if (flag_bits & 0x08) != 0
    flags << :ack if (flag_bits & 0x10) != 0
    opts[:payload] = data[hdr_len..-1]
    opts[:protocol] = :tcp
    return opts
  end

  def parse_udp(data, opts)
    raise "UDP: truncated datagram" if data.length < 8
    src, dst, tot_len = data.unpack('S>S>S>')
    raise "UDP: truncated payload" if tot_len < data.length

    # Alright, this packet looks good.  Pass it along.
    opts[:src_port], opts[:dst_port] = src, dst
    opts[:payload] = data[8, tot_len - 8]
    opts[:protocol] = :udp
    return opts
  end

  # Take a parsed packet and return a src <-> dst reversed copy.
  PACKET_REVERSAL = {
    :src_mac => :dst_mac,         :dst_mac => :src_mac,
    :src_ip => :dst_ip,           :dst_ip => :src_ip,
    :src_port => :dst_port,       :dst_port => :src_port,
    :sender_mac => :target_mac,   :target_mac => :sender_mac,
    :sender_ip => :target_ip,     :target_ip => :sender_ip,
  }
  def reverse(opts)
    rev = {}
    opts.each { |k,v| rev[PACKET_REVERSAL[k] || k] = v }
    rev.delete :src_mac
    rev
  end

  # This nifty method takes an opts hash returned by parse() and calls the
  # appropriate injector method with the appropriate options set.
  def unparse(opts)
    case opts[:protocol]
      when :ethernet
        frame(opts[:ethertype], opts[:payload], opts)
      when :arp
        arp(opts[:operation], opts)
      when :ipv4
        packet(opts[:transport], opts[:payload], opts)
      when :ipv6
        packet(opts[:transport], opts[:payload], opts)
      when :tcp
        segment(opts[:payload], opts)
      when :udp
        datagram(opts[:payload], opts)
      when :icmp
        control_message(opts[:payload], opts)
      else
        raise "Unknown protocol: #{opts[:protocol]}"
    end
  end


  ##  Helper functions  ##

  # Helper routine to generate pseudorandom integers. Provide a width to get an
  # array of random bytes, otherwise a random 64-bit integer will be returned.
  def prand(width = nil)
    @pseed = (@pseed * LCG_A + LCG_C) % 2**64
    if width
      return [ @pseed ].pack("Q") + prand(width - 8) if width > 8
      return [ @pseed ].pack("Q")[0, width]
    end
    @pseed
  end

  # Helper routine which takes an integer, IPAddr object, dotted-quad string,
  # or 4/16 character NBO string and homogenizes it into the latter form.
  def ip_addr(val)
    case val
      when Integer
        return [val].pack('L>') if val <= 0xFFFFFFFF
        return IPAddr.new(val, AF_INET6).hton
      when IPAddr
        return val.hton
      when String
        return val if val.length == 4 || val.length == 16
        return IPAddr.new(val).hton rescue nil
    end
    raise "invalid IP address: #{val.inspect}"
  end

end
