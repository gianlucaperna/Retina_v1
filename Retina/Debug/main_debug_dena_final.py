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
from LogWebexManager import *
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



#%%
if __name__ == "__main__":

    #Put your path to pcap here
    source_pcap = r"C:\Users\Gianl\Desktop\Call_wih_log\Try_log_3p\3_p.pcapng"

    dir_file = r"C:\Users\Gianl\Desktop\Call_wih_log\Try_log_3p\ef24ba8e-193d-4707-81a9-8ba06ee42b12_1587404748173.log"
    with open(dir_file, "r") as f:
        #vado linea per line cosi
        log = f.readlines()

    used_port = pcap_to_port(source_pcap)
    info = (source_pcap, used_port)

    dict_flow_data, df_unique_flow, unique_flow, \
    l_ipv6, l_turn, l_stun, l_dns, dns_domain_names, l_mdns,\
    l_dtls, l_rtcp, l_tcp, tls_domain_names, l_udp_undecoded_protocol, l_other_udp, \
    l_rtp_event, l_rtp_other, l_rtp, l_other, counter = \
            pcap_to_json(info)

    #SECONDA PARTE DEBUG
    LEN_DROP = 0
    dict_flow_data, LEN_DROP = inter_statistic (dict_flow_data, LEN_DROP)
    df_train = pd.DataFrame()
    dict_flow_data_2 = {}
    for flow_id in dict_flow_data.keys():
           dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
           dict_flow_data[flow_id].set_index('timestamps', inplace = True)
           dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
           dict_flow_data_2[flow_id] = dict_flow_data[flow_id].resample('s').agg({'interarrival' : ['std', 'mean', p25, p50, p75, max_min_diff], 'len_udp' : ['std', 'mean', 'count', kbps, p25, p50, p75, max_min_diff], \
               'interlength_udp' : ['mean', p25, p50, p75, max_min_diff], 'rtp_interarrival' : ['std', 'mean', zeroes_count, max_min_diff] ,\
               "inter_time_sequence": ['std', 'mean', p25, p50, p75, max_min_diff] })

    for flow_id in dict_flow_data_2.keys():
        dict_flow_data_2[flow_id].reset_index(inplace = True, drop = False)
        new_header = [h[0] + "_" + h[1] if h[1] else h[0] for h in dict_flow_data_2[flow_id]]
        dict_flow_data_2[flow_id].columns = new_header


    #Gestione del LOG

    #Make fec_dict: fec_key: list of keys of all streams with the same csi
    fec_dict = make_fec_dict(log, dict_flow_data)
    #Crea d_log - {key come in dict_flow_data : Dataframe con dati dal log}
    #ha i dati di dal log per ogni flusso non-FEC
    #per i flussi FEC ha empty DataFrame
    d_log = make_d_log(log, dict_flow_data)
    #Merge dei dati del log e dict_flow_data_2
    dict_merge, flows_not_in_log = DictMerge(dict_flow_data_2, d_log, fec_dict)
    #Per rendere il codice operabile con json2stat
    #df_train = WebLogdf(dict_merge)