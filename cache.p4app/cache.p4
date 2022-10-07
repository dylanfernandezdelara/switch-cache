/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11;
const bit<32> CLIENT_IP = 0x0a000002;
const bit<32> SERVER_IP = 0x0a000001;
const bit<16> UDP_PORT     = 1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header request_t {
    bit<8> key;
}

header response_t {
    bit<8> key;
    bit<8> is_valid;
    bit<32> value;
}

struct metadata { }

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    request_t request;
    response_t response;
 }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            // 0x11 is the value for parsing udp (done in itch.p4 example)
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT: parse_request;
            default: parse_response;
        }
    }

    state parse_request {
        packet.extract(hdr.request);
        hdr.request.isValid();
        transition accept;
    }

    state parse_response {
        packet.extract(hdr.response);
        hdr.response.isValid();
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(256) myReg;
    bit<32> found_hit = 0;
    bit<32> found_value = 0;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action in_p4_cache_send_msg(bit<32> response_value){
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        macAddr_t tmpDstMac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmpDstMac;

        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;
        // the request vs response header can only change by a max of 40 bits, so 8 bytes
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;

        bit<16> tmpDstPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpDstPort;
        hdr.udp.length_ = hdr.udp.length_ + 5;
        hdr.udp.checksum = 0; // setting this because of the spec, but unsure why

        hdr.response.setValid();
        hdr.response.value = response_value;
        hdr.response.is_valid = 1;
        hdr.response.key = hdr.request.key;
       
        hdr.request.setInvalid();
    }

    action check_p4_register() {
        myReg.read(found_value, (bit<32>)hdr.request.key);

        if (found_value != 0) {
            found_hit = 1;
        }
    }

    table p4_cache {
        key = {
            hdr.request.key: exact;
        }
        actions = {
            in_p4_cache_send_msg;
            check_p4_register;
        }
        size = 1024;
        default_action = check_p4_register;
    } 

    apply {
        if (hdr.request.isValid()) {
            // applies actions if there is a hit, and only calls check_p4_register if there is no hit
            switch (p4_cache.apply().action_run) {
                check_p4_register: {
                    if (found_hit == 1) {
                        in_p4_cache_send_msg(found_value);
                        found_hit = 0;
                        found_value = 0;
                    }
                }
            }
        }
        // if the is_valid field is 0 (this is set in server.py) then you shouldn't write to the register
        else if (hdr.response.isValid() && hdr.response.is_valid == 1) {
            myReg.write((bit<32>)hdr.response.key, hdr.response.value);
        }
        
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	    update_checksum(
	        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
             hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { 
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);

        // only emits header if it is valid, so okay to have both in the deparser
        packet.emit(hdr.request);
        packet.emit(hdr.response);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
