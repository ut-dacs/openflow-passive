# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ipv6, tcp, udp
from ryu.lib.packet import ethernet
import os           # to access the env vars
import os.path
import signal       # to act on and send out signals
import time        # to 'wait' 
from threading import Timer # to 'wait'
import array
import subprocess   # to call awk

import numpy        # for mathematical purposes (mean, std)
import random        # testing purposes
import sys


from ryu.utils import hex_array # for utils.hex_array


class FlowRemListener(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    IDLE_TIMEOUT = 30
    HARD_TIMEOUT = 120
    OUTPUT_DIR = "/tmp/"
    INITIAL_RUNS = 1 # should be 10 or something?

    def __init__(self, *args, **kwargs):
        super(FlowRemListener, self).__init__(*args, **kwargs)
        #self.logfile = open(("%s/%s-%d.log" % (self.OUTPUT_DIR, self.TRACE, self.main_iterator)), 'w')
        self.logfile = open(("%s/%s.log" % (self.OUTPUT_DIR, "flow_rem_handler")), 'w')
        #self.logfile = open(self.logfile_name(), 'w')
        self.failed_counter     = 0
        self.packet_in_counter  = 0



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        print "got datapath"
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        #                                  #ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, match, actions, ofproto.OFP_NO_BUFFER, 0, 0)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print "got PACKET_IN (should not happen, returning..)"
        self.packet_in_counter += 1
        return;
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(array.array('B', msg.data))

        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            #print "NOT ETHERNET!!"
            self.failed_counter +=1
            return

        ip4 = pkt.get_protocol(ipv4.ipv4)

        if not ip4:
            #print "NOT IPv4!"
            self.failed_counter +=1
            return

        match = 1
        if ip4.proto == 6: # == TCP
            l4 = pkt.get_protocol(tcp.tcp)
            if l4 is not None:
                match = parser.OFPMatch(ip_proto=ip4.proto, ipv4_src=ip4.src, tcp_src=l4.src_port, ipv4_dst=ip4.dst, tcp_dst=l4.dst_port, eth_type=0x800)
            else:
                self.failed_counter += 1
                return
        elif ip4.proto == 17: # == UDP
            l4 = pkt.get_protocol(udp.udp)
            if l4 is not None:
                match = parser.OFPMatch(ip_proto=ip4.proto, ipv4_src=ip4.src, udp_src=l4.src_port, ipv4_dst=ip4.dst, udp_dst=l4.dst_port, eth_type=0x800)
            else:
                print "invalid UDP packet, returning"
                self.failed_counter +=1
                return
        else:
            # Not TCP nor UDP
            self.failed_counter +=1
            return

        actions = [parser.OFPActionOutput(2)] # ???
        #actions = []
        self.add_flow(datapath, 1, match, actions, msg.buffer_id)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        fixed_duration = -1
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
            fixed_duration = "%d.%d" % ((msg.duration_sec - msg.idle_timeout), msg.duration_nsec)
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
            fixed_duration = "%d.%d" % (msg.duration_sec, msg.duration_nsec)
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        #self.logger.info('OFPFlowRemoved received: '
        #                  'cookie=%d priority=%d reason=%s table_id=%d '
        #                  'duration_sec=%d duration_nsec=%d '
        #                  'idle_timeout=%d hard_timeout=%d '
        #                  'packet_count=%d byte_count=%d match.fields=%s',
        #                  msg.cookie, msg.priority, reason, msg.table_id,
        #                  msg.duration_sec, msg.duration_nsec,
        #                  msg.idle_timeout, msg.hard_timeout,
        #                  msg.packet_count, msg.byte_count, msg.match)

        m = msg.match
        ip_proto = m['ip_proto']
	src_ip = ''
	dst_ip = ''
	if 'ipv4_src' in m: # IP4
		src_ip = m['ipv4_src']
		dst_ip = m['ipv4_dst']
	if 'ipv6_src' in m: # IP6
		src_ip = m['ipv6_src']
		dst_ip = m['ipv6_dst']
        src_port = -1
        dst_port = -1
        if m['ip_proto'] == 6: # TCP
            src_port = m['tcp_src']
            dst_port = m['tcp_dst']
        elif m['ip_proto'] == 17: # UDP
            src_port = m['udp_src']
            dst_port = m['udp_dst']


        # TODO add start time as second field (UNIX timestamp)
        #print "%s %s %s %s %s %d %d %d" % (ip_proto, ipv4_src, src_port, ipv4_dst, dst_port, fixed_duration, msg.packet_count, msg.byte_count)
        current_timestamp = time.time()*1000
        #self.output("00:00:00.000 %d 00:00:00.000 %d %.3f %s %s %d %d" % (current_timestamp, current_timestamp+float(fixed_duration)*1000, float(fixed_duration), src_ip, dst_ip, msg.packet_count, msg.byte_count))
        self.output("cookie=0x%x, duration=%d.%ds, table=%d, n_packets=%d, n_bytes=%d" % (msg.cookie, msg.duration_sec, msg.duration_nsec, msg.table_id, msg.packet_count, msg.byte_count))
        # cookie=0x1fb, duration=55.017s, table=0, n_packets=18446744073709551615, n_bytes=2924,

        #self.output("%s %s %s %s %s %s %d %d" % (ip_proto, ipv4_src, src_port, ipv4_dst, dst_port, fixed_duration, msg.packet_count, msg.byte_count))



    def logfile_name(self):
        return "%s/%s-ito%d-hto%d-%d.log" % (self.OUTPUT_DIR, self.TRACE, self.IDLE_TIMEOUT, self.HARD_TIMEOUT, self.main_iterator)
    
    def output(self, msg):
        #self.logfile.write("00:00:00.000 %d 00:00:00.000 %s\n" % (time.time()*1000, msg))
        self.logfile.write("%s\n" % msg)
        self.logfile.flush()
	#print msg



    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x',# message=%s',
                          msg.type, msg.code)#, hex_array(msg.data))
