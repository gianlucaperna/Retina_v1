import pandas as pd
import os
import json
import sys
#Read json created with tshark and put it in a list
def json_to_list(output, json_path, duration_drop, json_file = False):

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
                rtp_marker = int(obj['layers']['rtp']['rtp_rtp_marker'])
            except:
                rtp_marker = -1
            try:
                rtp_csrc = obj['layers']['rtp']['rtp_csrc_items_rtp_csrc_item']
            except:
                rtp_csrc = "fec"
            data = [frame_num, p_type, len_udp, len_ip, len_frame,
                    timestamp, rtp_timestamp, rtp_seq_num, rtp_csrc, rtp_marker]

            if unique_tuple in dictionary:
                dictionary[unique_tuple].append(data)
            else:
                dictionary[unique_tuple] = []
                dictionary[unique_tuple].append(data)
        except Exception as e:
            print(e)
            pass

    dict_data = {}
    try:
    #Find RTP flows
        unique_flow = set()
        dict_flow_data = {}

        # df containign unique flow
        df_unique_flow= pd.DataFrame(columns = ['ssrc',
                               'source_addr',
                               'dest_addr',
                               'source_port',
                               'dest_port',
                               'rtp_p_type'])


        # Analyze each packet
        if json_file:
            file = open(json_path, "w", encoding = "utf-8")
            file.write("[")
            flag=False
        with open(output, "r", encoding="utf-8", errors='ignore') as file_output: #apro file output tshark
            for obj in file_output: #leggo una riga, che corrisponde ad un oggetto str di json
                try:
                    obj = json.loads(obj) #converto la stringa in dizionario
                    if (("rtp" in obj["layers"].keys())):
                        if len(obj['layers']['rtp']) <= 3:
                            #l_rtp_other.append(obj)
                            pass
                        else:
                            rtp_insert(obj, unique_flow, dict_flow_data, dict_data)
                            if ("rtpevent" not in obj["layers"].keys()):
                                del (obj['layers']["rtp"]["rtp_rtp_payload"])
                            #del (obj["layers"]["eth"])
                            #del (obj["layers"]["frame"])
                            if json_file:
                                if flag:
                                    file.write(",\n")
                                file.write(json.dumps(obj))
                                flag=True
                except Exception as e:
                    continue
        if json_file:
            file.write("]")
            file.close()
        for x in unique_flow:
            columns = ['frame_num', 'p_type', 'len_udp', 'len_ip', 'len_frame', 'timestamps', 'rtp_timestamp', 'rtp_seq_num', 'rtp_csrc', 'rtp_marker']
            df = pd.DataFrame(dict_data[x], columns=columns)
            if (max(df["timestamps"]) - min(df["timestamps"])) > duration_drop:
                dict_flow_data[x] = df
                df_unique_flow = df_unique_flow.append({
                         'ssrc': x[0], 'source_addr': x[1],
                         'dest_addr': x[2], 'source_port': x[3],
                         'dest_port': x[4], 'rtp_p_type': x[5]}, ignore_index = True)

        return dict_flow_data, df_unique_flow, unique_flow
    except Exception as e:
        print('Json2List (json_path): Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        raise NameError("Json2List error")
