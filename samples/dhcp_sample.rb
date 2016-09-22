#!/usr/bin/env ruby

$LOAD_PATH << File.split(__FILE__).first
require 'pseudodhcp.rb'

pcap = PseudoConn.pcap do

  # Acquire an IP address
  dhcp_transaction do
    discover
    offer('192.168.0.151', 84600)
    request('192.168.0.151')
    insert_delay(2)
    ack('192.168.0.151', 84600)
  end
  
  # Reject a request
  dhcp_transaction do
    discover
    offer('192.168.0.114', 48300)
    request('192.168.0.114')
    nak()
  end
  
  # Include optional DHCP parameters this time
  dhcp_transaction do
    discover({
      :parameter_request_list => [:subnet_mask, :router, :domain_name_server]
    })
    offer('192.168.0.111', 169200, {
        :subnet_mask => '255.255.255.0',
        :router => ['192.168.1.1'],
        :domain_name_server => ['209.18.47.61', '209.18.47.62']
    })
    request('192.168.0.111')
    ack('192.168.0.111', 169200, {
        :subnet_mask => '255.255.255.0',
        :router => ['192.168.1.1'],
        :domain_name_server => ['209.18.47.61', '209.18.47.62']
    })
  end
end

File.open('sample.pcap', 'w') { |f| f.print pcap }
