//Azam and Xiang - p4 decision tree for intrusion detection
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define MAX_TABLE_SIZE 512
#define MAX_REGISTER_ARRAY_SIZE 512
#define REGISTER_SIZE 16
#define FEATURE_SIZE 30

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header class_t {
    bit<32> hash;
    bit<32> X7 ;
    bit<32> X14 ;
    // bit<32> X10 ;
    // bit<32> X12 ;
    // bit<32> X14 ;
    // bit<32> X16 ;
    // bit<32> X17 ;
    // bit<32> X21 ;
    // bit<32> X25 ;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    class_t      class;
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
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       transition parse_class_hdr;
    }

    state parse_class_hdr {
       packet.extract(hdr.class);
       transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    bit<8> class;
    bit<32> hash_value;
    bit<REGISTER_SIZE> syn_count;
    bit<REGISTER_SIZE> fin_count;
    bit<REGISTER_SIZE> rst_count;
    bit<REGISTER_SIZE> psh_count;
    bit<REGISTER_SIZE> urg_count;
    bit<REGISTER_SIZE> ack_count;
    bit<REGISTER_SIZE> num_packet;
    bit<32> max_pkt_size;
    bit<32> min_pkt_size;
    bit<32> total_flow_size;
    bit<REGISTER_SIZE> df_count;
    bit<REGISTER_SIZE> mf_count;
    bit<REGISTER_SIZE>  flow_duration;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) syn_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) fin_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) rst_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) psh_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) ack_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) urg_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) num_packets;
    register<bit<32>>(MAX_REGISTER_ARRAY_SIZE) max_pkt_sizes;
    register<bit<32>>(MAX_REGISTER_ARRAY_SIZE) min_pkt_sizes;
    register<bit<32>>(MAX_REGISTER_ARRAY_SIZE) total_flow_sizes;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) df_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) mf_counts;
    register<bit<REGISTER_SIZE>>(MAX_REGISTER_ARRAY_SIZE) flow_durations;

   
/*   action hash_packet(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2) {
        hash(hash_value, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)MAX_TABLE_SIZE);
    }
  */

    action hash_packet(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2) {
        hash(hash_value, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1},
                                                           (bit<32>)MAX_TABLE_SIZE);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
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
        default_action = NoAction();
    }

    apply {
        if (hdr.tcp.isValid()) {
            // Hash 4 tuple for register-array index
            hash_packet(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);


/*
            // Read flow's current state stored in switch registers
            syn_counts.read(syn_count, hash_value);
            fin_counts.read(fin_count, hash_value);
            rst_counts.read(rst_count, hash_value);
            psh_counts.read(psh_count, hash_value);
            ack_counts.read(ack_count, hash_value);
            urg_counts.read(urg_count, hash_value);
            num_packets.read(num_packet, hash_value);
            max_pkt_sizes.read(max_pkt_size, hash_value);
            min_pkt_sizes.read(min_pkt_size, hash_value);
            total_flow_sizes.read(total_flow_size, hash_value);
            df_counts.read(df_count, hash_value);
            mf_counts.read(mf_count, hash_value);
            flow_durations.read(flow_duration, hash_value);

            // Update flow state
            if (hdr.tcp.syn == 1){
                syn_count = syn_count + 1;
                syn_counts.write(hash_value, syn_count);
            }
            if (hdr.tcp.fin == 1){
                fin_count = fin_count + 1;
                fin_counts.write(hash_value, fin_count);
            }
            if (hdr.tcp.rst == 1){
                rst_count = rst_count + 1;
                rst_counts.write(hash_value, rst_count);
            }
            if (hdr.tcp.psh == 1){
                psh_count = psh_count + 1;
                psh_counts.write(hash_value, psh_count);
            }
            if (hdr.tcp.ack == 1){
                ack_count = ack_count + 1;
                ack_counts.write(hash_value, ack_count);
            }
            if (hdr.tcp.urg == 1){
                urg_count = urg_count + 1;
                urg_counts.write(hash_value, urg_count);
            }

            num_packet = num_packet + 1;
            num_packets.write(hash_value, num_packet);
            
            total_flow_size = total_flow_size + standard_metadata.packet_length;
            total_flow_sizes.write(hash_value, total_flow_size);

            if (standard_metadata.packet_length > max_pkt_size) {
                max_pkt_sizes.write(hash_value, standard_metadata.packet_length);
            }
            if (standard_metadata.packet_length < min_pkt_size) {
                min_pkt_sizes.write(hash_value, standard_metadata.packet_length);
            }

            if (hdr.ipv4.flags == 2) {
                df_count = df_count + 1;
                df_counts.write(hash_value, df_count);
            }
            if (hdr.ipv4.flags == 4) {
                mf_count = mf_count + 1;
                mf_counts.write(hash_value, mf_count);
            }
            if (hdr.ipv4.flags == 6) {
                mf_count = mf_count + 1;
                df_count = df_count + 1;
                mf_counts.write(hash_value, mf_count);
                df_counts.write(hash_value, df_count);
            }

            // Decision tree
            if (max_pkt_size <= 4343) {
                if (max_pkt_size == 0) {
                    if (hdr.tcp.dstPort < 108) {
                        if (flow_duration <= 9384) {
                            class = 2;
                        } else if (num_packet == 1) {
                            class = 3;
                        } else {
                            class = 0;
                        }
                    } else {
                        class = 0;
                    }
                } else {
                    if (fin_count == 0) {
                        class = 0;
                    } else if (hdr.tcp.dstPort <= 235) {
                        class = 2;
                    } else {
                        class = 0;
                    }
                }
            } else {
                if (hdr.tcp.dstPort < 262) {
                    if (total_flow_size < 11614) {
                        class = 2;
                    } else {
                        class = 1;
                    }
                } else {
                    class = 0;
                }
            }
*/

	bit<32>	x14 = hdr.class.X14;
	bit<32>	x7 = hdr.class.X7;
	
            // Write classification result to header
           // hdr.class.X7 = 0 - x14;
	    hdr.class.X14 = x14;
	    hdr.class.X7 = x7-x14;
	    	
            hdr.class.hash = hash_value;
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
	apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.class);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
