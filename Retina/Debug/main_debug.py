#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import numpy as np
from Pcap2Json_debug import pcap_to_json, pcap_to_port
from datetime import tzinfo, timezone
from datetime import datetime as dt
from dateutil import parser
from InterStatistics import inter_statistic
import re
from Martino_log import compute_stats
from datetime import datetime
#%%
def kbps(series):
    return series.sum()*8/1024

def zeroes_count(series):
    a = series[series == 0].count()
    if np.isnan(a):
        return 0
    else:
        return a

def value_label(series):

    value = series.value_counts()
    try:
        return value.index[0]
    except:
        pass

def p25(x):
    return (x.quantile(0.25)* 0.01)

def p50(x):
    return (x.quantile(0.50)* 0.01)

def p75(x):
    return (x.quantile(0.75)* 0.01)

def max_min_diff(series):
    return series.max() - series.min()

def drop_packet(data):
    data = dict_flow_data[('0x34712a47', '69.26.161.221', '192.168.1.105', 5004, 64693, 101)]
    packet_loss = data["rtp_seq_num"].diff().abs()%(pow(2,16)-2)
    data["time_drop"] = pd.to_datetime(data["timestamps"], unit="s").astype('datetime64[s]')
    to_drop = data[packet_loss > 1]["time_drop"].unique()
    data = data[~data['time_drop'].isin(to_drop)]
    data.drop("time_drop", axis =1, inplace = True)
    return data
#%%
if __name__ == "__main__":

    #Put your path to pcap here
    source_pcap = r'C:\Users\Gianl\Desktop\ScreenSharing_Test_fps\WM\Video\Video_Game.pcapng'

    used_port = pcap_to_port(source_pcap)
    info = (source_pcap, used_port)

    dict_flow_data, df_unique_flow, unique_flow, \
    l_ipv6, l_turn, l_stun, l_dns, dns_domain_names, l_mdns,\
    l_dtls, l_rtcp, l_tcp, tls_domain_names, l_udp_undecoded_protocol, l_other_udp, \
    l_rtp_event, l_rtp_other, l_rtp, l_other, counter = \
            pcap_to_json(info)

#stats = df.groupby(["ip.src", "ip.dst", "udp.srcport", "udp.dstport", "data"]).apply(compute_stats).dropna().reset_index()

    #SECONDA PARTE DEBUG
#     LEN_DROP = 0
#     dict_flow_data, LEN_DROP = inter_statistic (dict_flow_data, LEN_DROP)
#     df_train = pd.DataFrame()
#     dict_flow_data_2 = {}
#     for flow_id in dict_flow_data.keys():
#            dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
#            dict_flow_data[flow_id].set_index('timestamps', inplace = True)
#            dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
#            dict_flow_data_2[flow_id] = dict_flow_data[flow_id].resample('s').agg({'interarrival' : ['std', 'mean', p25, p50, p75, max_min_diff], 'len_udp' : ['std', 'mean', 'count', kbps, p25, p50, p75, max_min_diff], \
#                'interlength_udp' : ['mean', p25, p50, p75, max_min_diff], 'rtp_interarrival' : ['std', 'mean', zeroes_count, max_min_diff] ,\
#                "inter_time_sequence": ['std', 'mean', p25, p50, p75, max_min_diff] })

#     for flow_id in dict_flow_data_2.keys():
#         dict_flow_data_2[flow_id].reset_index(inplace = True, drop = False)
#         new_header = [h[0] + "_" + h[1] if h[1] else h[0] for h in dict_flow_data_2[flow_id]]
#         dict_flow_data_2[flow_id].columns = new_header

#     #LAVORARE SU dict_flow_data_2 PER INTEGRARE NUOVO LOG

#     dir_file = r"C:\Users\Gianl\Desktop\Try_log_3p\ef24ba8e-193d-4707-81a9-8ba06ee42b12_1587404748173.log"
#     with open(dir_file, "r") as f:
#         #vado linea per line cosi
#         log = f.readlines()
#     #Ciaoo
#     #Dena - crea dict_flow_log_data per ogni flusso non-FEC
#     d_log_lines = {}
#     d_log = {}

#     for key in dict_flow_data.keys():
#         ssrc = key[0]
#         p_type = key[5]
#         d_log_lines[key] = []
#         inner = {k:[] for k in ["time", "ssrc_hex", "ssrc_dec", "label", "quality", "fps", "jitter"]}

#         for line in log:
#             #2020-04-20T14:01:59.342Z <Info> [9968] WME:0 :[SQ] [SQ] INFO: SQAudioTX - vid=0 csi=843778816 did=0 ssrc=1613872330 loss=0.000 drop=0.000 jitter=0 bytes=201518 rtp=1306 failed=0 bitrate=65016 rtt=33 bw=176000 inputRate=48552 errcnt=0 dtmf=0 codecType=4 encodeDropMs=0 rrWin=0 br=61400 type=UDP rtcp=156 cFecOn=0 fecBw=88000 fecBitRate=91392 fecPkt=1305 mari_loss=0.000 mari_qdelay=12 mari_rtt=47 mari_recvrate=130112 nbr=65016 cid__783311041
#             substring = "ssrc=" + str(int(ssrc, 16)) #converto ssrc hex in dec
#             if (substring in line) and ("[SQ]" in line):
#                 d_log_lines[key].append(line)
#                 label = re.findall(r"INFO: ([a-zA-Z]+)", line) #SQAudioTX
#                 quality = re.findall(r"w*h=([0-9]+x[0-9]+)", line) #1280x720
#                 fps = re.findall(r" fps=([0-9]+)", line) #15
#                 jitter = re.findall(r" jitter=([0-9]+)", line) #0

#                 inner["time"].append(line.split("<")[0]) # ex. 2020-04-20T14:01:59.342Z
#                 inner["ssrc_hex"].append(ssrc)
#                 inner["ssrc_dec"].append(int(ssrc, 16))
#                 if label: inner["label"].append(label[0])
#                 if quality: inner["quality"].append(quality[0])
#                 if fps: inner["fps"].append(int(fps[0]))
#                 if jitter: inner["jitter"].append(float(jitter[0]))

#         #Metti gli informazioni dentro il dizionario d_log
#         #Audio e video hanno info differenti (quality, fps) quindi cancella qualche colona su audio
#         try:
#             to_delete = [inner_key for inner_key in inner.keys() if not inner[inner_key]]
#             for i in to_delete:
#                 del inner[i]
#                 #inner.pop(i, None)
#             d_log[key] = pd.DataFrame(inner)
#         except Exception as e:
#             print(f"Cannot convert to Dataframe: {ssrc}\nError: {e}")
#             pass

#         #VANNO GESTITI I FEC, PER ORA LI IGNORO

#         for key in d_log.keys():
#             if not d_log[key].empty:
#                 d_log[key]["timestamps"]=d_log[key]["time"].apply(parser.parse).apply(dt.strftime, args =(("%Y-%m-%dT%H:%M:%S"),))
#                 d_log[key]["timestamps"] = pd.to_datetime(d_log[key]["timestamps"])

#         dict_merge = {}
#         for key in dict_flow_data_2.keys():
#             if not d_log[key].empty:
#                 dict_merge[key] = pd.merge( dict_flow_data_2[key],d_log[key], left_on = 'timestamps', right_on = 'timestamps', how ='inner')
#             else:
#                 dict_merge[key] = dict_flow_data_2[key]

# #index = list(dict_flow_data_2.keys())[0]
# #
#         SDP = [line for line in log if re.findall('\A[a-z]=rtpmap:', line)]
#         SDP_FEC = [line for line in SDP if "x-ulpfecuc" in line]#a=rtpmap:127 x-ulpfecuc/8000
#         SDP_FEC = list(set(SDP_FEC))
#         PT_FEC = [int(i.replace(' ', ':').split(":")[1]) for i in SDP_FEC]

#         for key in dict_merge.keys():
#             if key[5] in PT_FEC:
#                 dict_merge[key]["label"] = "Fec"


#MARKER RTP CODE FPS:
    
#sum(dict_flow_data[('0xcdc28618', '192.168.1.105', '150.253.227.38', 49356, 9000, 96)]["rtp_timestamp"].value_counts())       
#sum(dict_flow_data[('0xcdc28618', '192.168.1.105', '150.253.227.38', 49356, 9000, 96)]["rtp_marker"].value_counts())
#SCEGLI UN DICT CON PACCHETTI VIDEO DA DICT_FLOW_DATA
df_prova = dict_flow_data[('0x67f1a27c', '192.168.1.105', '170.133.163.164', 51939, 5004, 118)]    

 
# df_prova["timestamps"] = pd.to_datetime(df_prova["timestamps"], unit = 's')
# df_prova.set_index('timestamps', inplace = True)
# df_prova = df_prova.dropna()
# df_prova2 = df_prova.resample(f"s").agg({"rtp_marker" : [sum]})