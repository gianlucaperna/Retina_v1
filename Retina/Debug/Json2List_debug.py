import pandas as pd
import os
from Decode import decode_stacked
import json

#Read json created with tshark and put it in a list
def json_to_list(output, json_path):

    def rtp_insert(obj, unique_flow, dict_flow_data, dictionary):
        try:
        # Retrive flow information
            ssrc = obj['layers']['rtp']['rtp_rtp_ssrc']
            if 'ipv6' in obj['layers'].keys():
                source_addr = obj['layers']['ipv6']['ipv6_ipv6_src']
                dest_addr = obj['layers']['ipv6']['ipv6_ipv6_dst']
                len_ip = int(obj['layers']['ipv6']['ipv6_ipv6_plen'])

            else:
                source_addr = obj['layers']['ip']['ip_ip_src']
                dest_addr = obj['layers']['ip']['ip_ip_dst']
                len_ip = int(obj['layers']['ip']['ip_ip_len'])

            source_port = int(obj['layers']['udp']['udp_udp_srcport'])
            dest_port = int(obj['layers']['udp']['udp_udp_dstport'])
            p_type = int(obj['layers']['rtp']['rtp_rtp_p_type'])

            # Save ssrc if new
            unique_tuple = (ssrc, source_addr, dest_addr, source_port, dest_port, p_type)
            unique_flow.add(unique_tuple)

            # Retrive packet information
            timestamp = float(obj['layers']['frame']['frame_frame_time_epoch'])
            frame_num = int(obj['layers']['frame']['frame_frame_number'])
            len_udp = int(obj['layers']['udp']['udp_udp_length'])
            len_frame = int(obj['layers']['frame']['frame_frame_len'])
            rtp_timestamp = int(obj['layers']['rtp']['rtp_rtp_timestamp'])
            rtp_seq_num = int(obj['layers']['rtp']['rtp_rtp_seq'])
            try:
                rtp_csrc = obj['layers']['rtp']['rtp_csrc_items_rtp_csrc_item']
            except:
                rtp_csrc = "fec"
            # Add new packet to dictionary
    #        columns = ['frame_num', 'p_type', 'len_udp', 'len_ip', 'len_frame', 'timestamps', 'rtp_timestamp', 'rtp_seq_num']
            data = [frame_num, p_type, len_udp, len_ip, len_frame,
                    timestamp, rtp_timestamp, rtp_seq_num, rtp_csrc]

            if unique_tuple in dictionary:
                dictionary[unique_tuple].append(data)
            else:
                dictionary[unique_tuple] = []
                dictionary[unique_tuple].append(data)
        except Exception as e:
            print(e)
            pass

    l_ipv6 = []
    l_turn = []
    l_stun = []

    l_dns = []
    l_mdns = []
    l_dtls = []
    l_rtcp = []
    l_tcp = []
    tls_domain_names = []
    dns_domain_names = []
    l_udp_undecoded_protocol = []
    l_other_udp = []

    l_rtp_event = []
    l_rtp_other = []
    l_rtp = []

    l_other = []
    counter = 0

    dict_data = {}

    try:
    #Find RTP flows
        unique_flow = set()
        dict_flow_data = {}

        # df containing unique flow
        df_unique_flow= pd.DataFrame(columns = ['ssrc',
                               'source_addr',
                               'dest_addr',
                               'source_port',
                               'dest_port',
                               'rtp_p_type'])


        for obj in decode_stacked(output):
            try:

                if 'index' in obj.keys():
                    continue
                if 'ipv6' in obj['layers'].keys():
                    l_ipv6.append(obj)
                if 'stun' in obj['layers'].keys():
                    if 'stun_stun_channel' in obj['layers']["stun"]:
                        l_turn.append(obj)
                    else:
                        l_stun.append(obj)
                elif 'dns' in obj['layers'].keys():
                    l_dns.append(obj)
                    if "text_dns_qry_name" in obj["layers"]["dns"].keys():
                        dns_domain_names.append(obj["layers"]["dns"]["text_dns_qry_name"])
                    if "text_dns_cname" in obj["layers"]["dns"].keys():
                        dns_domain_names.append(obj["layers"]["dns"]["text_dns_cname"])
                elif 'mdns' in obj['layers'].keys():
                    l_mdns.append(obj)
                elif 'dtls' in obj['layers'].keys():
                    l_dtls.append(obj)
                elif 'rtcp' in obj['layers'].keys():
                    l_rtcp.append(obj)
                elif 'tcp' in obj['layers'].keys():
                    l_tcp.append(obj)

                    protos = ["tls", "ssl"]
                    for proto in protos:
                        if proto in obj['layers'].keys():
                            if isinstance(obj['layers'][proto], dict):
                                if ("text_"+proto+"_handshake_extensions_server_name" in obj['layers'][proto].keys()):
                                    tls_domain_names.append(obj['layers'][proto]["text_"+proto+"_handshake_extensions_server_name"])

                elif (('rtp' not in obj['layers'].keys()) & ('udp' in obj['layers'].keys())):
                    if 'data' in obj['layers'].keys():
                        l_udp_undecoded_protocol.append(obj)
                    else:
                        l_other_udp.append(obj)

                #RTP packets handling
                elif (('rtp' in obj['layers'].keys())):
                    if ('rtpevent' in obj['layers'].keys()):
                        l_rtp_event.append(obj)
                        rtp_insert(obj, unique_flow, dict_flow_data, dict_data)
                    elif len(obj['layers']['rtp']) <= 3:
                        l_rtp_other.append(obj)
                    else:
                        l_rtp.append(obj)
                        rtp_insert(obj, unique_flow, dict_flow_data, dict_data)

                else:
                    l_other.append(obj)

                counter+= 1

            except Exception as e:
                continue

        for x in unique_flow:
            columns = ['frame_num', 'p_type', 'len_udp', 'len_ip', 'len_frame', 'timestamps', 'rtp_timestamp', 'rtp_seq_num', 'rtp_csrc']
            df = pd.DataFrame(dict_data[x], columns=columns)
            if (max(df["timestamps"]) - min(df["timestamps"])) > 10:
                dict_flow_data[x] = df
                df_unique_flow = df_unique_flow.append({
                         'ssrc': x[0], 'source_addr': x[1],
                         'dest_addr': x[2], 'source_port': x[3],
                         'dest_port': x[4], 'rtp_p_type': x[5]}, ignore_index = True)

        print("Unique flows:")
        print(df_unique_flow)

        return dict_flow_data, df_unique_flow, unique_flow, \
                l_ipv6, l_turn, l_stun, l_dns, dns_domain_names, l_mdns,\
                l_dtls, l_rtcp, l_tcp, tls_domain_names, l_udp_undecoded_protocol, l_other_udp, \
                l_rtp_event, l_rtp_other, l_rtp, l_other, counter


    except Exception as e:
        print (json_path+ " :"+ str(e))
