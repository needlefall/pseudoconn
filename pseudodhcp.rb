#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'ipaddr'
require_relative 'pseudoconn.rb'

# DHCP extension to the PseudoConn packet-writing class.  
class PseudoConn

  # BOOTP opcodes (RFC 951)
  DHCP_OP = {
    :request => 0x01,
    :reply => 0x02
  }
  
  # Hardware type (RFC 1700)
  DHCP_HTYPE = {
    :ethernet => 0x01,
    :experimental_ethernet => 0x02,
    :amateur_radio => 0x03,
    :token_ring => 0x04,
    :chaos => 0x05,
    :ieee802 => 0x06,
    :hyper_channel => 0x08,
    :arcnet => 0x07,
    :lanstar => 0x09
  }
  
  # Supported DHCP options
  DHCP_OPTION_CODE = {
    :subnet_mask => 1,
    :router => 3,
    :domain_name_server => 6,
    :requested_ip_address => 50,
    :ip_address_lease_time => 51,
    :dhcp_message_type => 53,
    :dhcp_server => 54,
    :parameter_request_list => 55
  }
  
  # Codes for the DHCP message type option
  DHCP_MESSAGE_TYPE_CODE = {
    :discover => 0x01,
    :offer => 0x02,
    :request => 0x03,
    :decline => 0x04,
    :ack => 0x05,
    :nak => 0x06,
    :release => 0x07,
    :inform => 0x08
  }
  
  # Hardware (MAC) address length for Ethernet and 802.11 protocols
  DHCP_HLEN_ETHERNET = 0x06
  
  # Bit-flag for broadcasted packets
  DHCP_FLAG_BROADCAST = 0x8000
  
  # Magic cookie value (RFC 1497)
  DHCP_MAGIC_COOKIE = 0x63825363
  
  # Null IP address, for blanking fields
  DHCP_IP_NULL = IPAddr.new('0.0.0.0').hton
  
  class Connection

    def dhcp_discover(transaction, *options)
      message_info = {
        :op => :request,
        :htype => :ethernet,
        :hops => 0,
        :xid => transaction.id,
        :timestamp => transaction.current_time,
        :broadcast => true,
        :ciaddr => DHCP_IP_NULL,
        :yiaddr => DHCP_IP_NULL,
        :siaddr => DHCP_IP_NULL,
        :giaddr => DHCP_IP_NULL,
        :chaddr => @opts[:src_mac],
        :options => {
          :dhcp_message_type => :discover
        }
      }
      
      options.each do |key, value|
        message_info[:options][key] = value
      end
      
      proto_client(dhcp_message(message_info), :mac_broadcast, :ipv4_broadcast)
    end
    
    def dhcp_offer(transaction, offered_addr, lease_time, *options)
      message_info = {
        :op => :reply,
        :htype => :ethernet,
        :hops => 0,
        :xid => transaction.id,
        :timestamp => transaction.current_time,
        :broadcast => false,
        :ciaddr => DHCP_IP_NULL,
        :yiaddr => offered_addr,
        :siaddr => @opts[:dst_ip],
        :giaddr => DHCP_IP_NULL,
        :chaddr => @opts[:src_mac],
        :options => {
          :dhcp_message_type => :offer,
          :ip_address_lease_time => lease_time,
          :dhcp_server => @opts[:dst_ip]
        }
      }
      
      options.each do |key, value|
        message_info[:options][key] = value
      end
      
      proto_server(dhcp_message(message_info), :ipv4_broadcast)
    end
    
    def dhcp_request(transaction, requested_addr, *options)
      message_info = {
        :op => :request,
        :htype => :ethernet,
        :hops => 0,
        :xid => transaction.id,
        :timestamp => transaction.current_time,
        :broadcast => false,
        :ciaddr => DHCP_IP_NULL,
        :yiaddr => DHCP_IP_NULL,
        :siaddr => @opts[:dst_ip],
        :giaddr => DHCP_IP_NULL,
        :chaddr => @opts[:src_mac],
        :options => {
            :dhcp_message_type => :request,
            :requested_ip_address => requested_addr,
            :dhcp_server => @opts[:dst_ip]
        }
      }
      
      options.each do |key, value|
        message_info[:options][key] = value
      end
      
      proto_client(dhcp_message(message_info), :ipv4_broadcast)
    end
    
    def dhcp_ack(transaction, accepted_addr, lease_time, *options)
      message_info = {
        :op => :reply,
        :htype => :ethernet,
        :hops => 0,
        :xid => transaction.id,
        :timestamp => transaction.current_time,
        :broadcast => false,
        :ciaddr => DHCP_IP_NULL,
        :yiaddr => accepted_addr,
        :siaddr => @opts[:dst_ip],
        :giaddr => DHCP_IP_NULL,
        :chaddr => @opts[:src_mac],
        :options => {
          :dhcp_message_type => :ack,
          :ip_address_lease_time => lease_time,
          :dhcp_server => @opts[:dst_ip]
        }
      }
      
      options.each do |key, value|
        message_info[:options][key] = value
      end
      
      proto_server(dhcp_message(message_info), :ipv4_broadcast)
    end
    
    def dhcp_nak(transaction, *options)
      message_info = {
        :op => :reply,
        :htype => :ethernet,
        :hops => 0,
        :xid => transaction.id,
        :timestamp => transaction.current_time,
        :broadcast => false,
        :ciaddr => DHCP_IP_NULL,
        :yiaddr => DHCP_IP_NULL,
        :siaddr => @opts[:dst_ip],
        :giaddr => DHCP_IP_NULL,
        :chaddr => @opts[:src_mac],
        :options => {
          :dhcp_message_type => :nak
        }
      }
      
      proto_server(dhcp_message(message_info), :ipv4_broadcast)
    end
    
    private
    
    # Format a DHCP message. All DHCP messages have an identical structure defined by the BOOTP protocol
    def dhcp_message(fields)
    
      data = ''
      data << DHCP_OP[fields[:op]].chr           # OP
      data << DHCP_HTYPE[fields[:htype]].chr     # HTYPE
      data << DHCP_HLEN_ETHERNET.chr             # HLEN
      data << fields[:hops].chr                  # HOPS
      data << itonl(fields[:xid])                # XID
      data << itons(fields[:timestamp])          # SECS
      
      broadcast_flag = fields[:broadcast] ? DHCP_FLAG_BROADCAST : 0
      data << itons(broadcast_flag)              # FLAGS
      data << fields[:ciaddr]                    # CIADDR
      data << fields[:yiaddr]                    # YIADDR
      data << fields[:yiaddr]                    # SIADDR
      data << fields[:yiaddr]                    # GIADDR
      data << fields[:chaddr].ljust(16, "\x00")  # CHADDR
      data << "\x00" * 64                        # SNAME
      data << "\x00" * 128                       # FILE
      data << itonl(DHCP_MAGIC_COOKIE)           # MAGIC COOKIE
      
      fields[:options].each do |key, value| 
        data << DHCP_OPTION_CODE[key].chr
        case key
          when :subnet_mask
            dhcp_option_value_str(data, IPAddr.new(value).hton)
          when :router
            dhcp_option_value_str_array(data, value.map { |n| IPAddr.new(n).hton })
          when :domain_name_server
            dhcp_option_value_str_array(data, value.map { |n| IPAddr.new(n).hton })
          when :requested_ip_address
            dhcp_option_value_str(data, value)
          when :ip_address_lease_time
            dhcp_option_value_dword(data, value)
          when :dhcp_message_type
            dhcp_option_value_byte(data, DHCP_MESSAGE_TYPE_CODE[value])
          when :dhcp_server
            dhcp_option_value_str(data, value)
          when :parameter_request_list
            dhcp_option_value_byte_array(data, value.map {|n| DHCP_OPTION_CODE[n] })
        end
      end
      
      # End option
      data << "\xFF"
      
      return data
    end
    
    # Pack 32-bit integer value into data
    def dhcp_option_value_dword(data, value)
      data << 0x04.chr
      data << itonl(value)
    end
    
    # Pack byte value into data
    def dhcp_option_value_byte(data, value)
      data << 0x01.chr
      data << value.chr
    end
    
    # Pack array of strings value into data
    def dhcp_option_value_str_array(data, value)
      total = 0
      value.each do
        |n| total += n.length
      end
      data << total.chr # TODO: throw exception for > 256 characters
      value.each do |element|
        data << element
      end
    end

    # Pack array of bytes value into data
    def dhcp_option_value_byte_array(data, value)
      data << value.length.chr
      value.each do |element| 
        data << element.chr
      end
    end
    
    # Pack string into data
    def dhcp_option_value_str(data, value)
      data << value.length.chr
      data << value
    end
  end
  
  def dhcp_transaction(*conn_opts, &blk)
    dhcp = DHCPTransaction.new(self, *conn_opts)
    raise ArgumentError, 'PseudoConn::dhcp_transaction() block not supplied' unless blk
    dhcp.instance_eval &blk
  end
  
  # Encapsulation of a DHCP transaction
  class DHCPTransaction
    def initialize(owner, *conn_opts)
      @owner = owner
      @start = owner.timestamp
      @owner.random[:dhcp_id] ||= PseudoRand.new(0xcafe)
      @id = @owner.random[:dhcp_id].pseudo_rand() & 0xFFFFFFFF
      @conn_opts = conn_opts.first || {}
      @conn_opts[:transport] ||= :udp
      @conn_opts[:src_port] ||= 68
      @conn_opts[:dst_port] ||= 67
      @conn_opts[:src_ip] ||= '0.0.0.0'
      @conn_opts[:dst_ip] ||= '192.168.1.1'
    end
    
    # Simulated time from the start of the transaction
    def current_time
      return @owner.timestamp.to_i - @start.to_i
    end
    
    # Transaction ID
    def id
      return @id
    end
    
    # Insert a delay to demonstrate the SEC 
    def insert_delay(sec)
      @owner.connection(@conn_opts) do
        insert_delay(sec)
      end
    end
  
    # DHCPDISCOVER
    def discover(options = {})
      transaction = self
      @owner.connection(@conn_opts) do
        dhcp_discover(transaction, *options)
      end
    end 
  
    # DHCPOFFER
    def offer(offered_ip_address, lease_time, options = {})
      transaction = self
      @owner.connection(@conn_opts) do
        dhcp_offer(transaction, IPAddr.new(offered_ip_address).hton, lease_time, *options)
      end
    end
  
    # DHCPREQUEST
    def request(requested_ip_address, options = {})
      transaction = self
      @owner.connection(@conn_opts) do
        dhcp_request(transaction, IPAddr.new(requested_ip_address).hton, *options)
      end
    end
    
    # DHCPACK
    def ack(accepted_ip_address, lease_time, options = {})
      transaction = self
      @owner.connection(@conn_opts) do
        dhcp_ack(transaction, IPAddr.new(accepted_ip_address).hton, lease_time, *options)
      end
    end
    
    # DHCPNAK
    def nak(options = {})
      transaction = self
      @owner.connection(@conn_opts) do
        dhcp_nak(transaction, *options)
      end
    end
  end  
end