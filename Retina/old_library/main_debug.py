#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import json
import matplotlib.pyplot as plt
import sys
import numpy as np
import re
from plotting import plot_stuff
from MergeCSV import merge_csv
from InterStatistics import inter_statistic
from PacketLoss import calculate_packet_loss
from Json2List import json_to_list
from Pcap2Json import pcap_to_json
from plotting import make_rtp_data
from Label import labelling
from Label import labelling2
import os
import copy
#%%

counter_ssrc = 0

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

#%%
if __name__ == "__main__":
    # name field :layers - rtp -  rtp_csrc_items_rtp_csrc_item
    # name filed: rtp_timestamp
  
    #If you want to do by hand
    directory_p = r'C:\Users\Gianl\Desktop\Catture_Meetings\Screen_sharing\Gianluca_screen_no_video.pcapng'

    source_pcap = directory_p # only for debug
    LEN_DROP = 0
    name = os.path.basename(source_pcap).split(".")[0]
    pcap_path = os.path.dirname(source_pcap)
    output = pcap_to_json(source_pcap)
    dict_flow_data, df_unique_flow, l_rtp, l_non_rtp, l_stun, l_rtcp, l_turn, l_tcp, l_only_udp, unique_flow, l_err = \
        json_to_list(output)
    dict_flow_data, LEN_DROP = inter_statistic (dict_flow_data, LEN_DROP)
    element = os.listdir(pcap_path) #cerco se c'è un json file nel caso in cui il pcap sia una cattura di meetings
    # Salvo una copia così posso ripristinarla in fase di debug
    dict_flow_data_reserve = copy.deepcopy(dict_flow_data)
    
    if name +'.json' in element:
        with open(os.path.join(pcap_path, name+".json"), 'r') as f:
            datastore = json.load(f)
        dict_flow_data = labelling (dict_flow_data, int(datastore.get("audio")), int(datastore.get("video")),  datastore.get("ip"), screen = datastore.get("screen"), \
                                    quality= datastore.get("quality"))
        dict_flow_data = labelling2(dict_flow_data)
    else:
        dict_flow_data = labelling (dict_flow_data)
        dict_flow_data = labelling2(dict_flow_data)
        
            
    df_train = pd.DataFrame()
    for flow_id in dict_flow_data.keys():
        dict_flow_data[flow_id] = dict_flow_data[flow_id].reset_index()
        dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
        dict_flow_data[flow_id].set_index('timestamps', inplace = True)
        dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
        train = dict_flow_data[flow_id].resample('s').agg({'interarrival' : ['std', 'mean', p25, p50, p75], 'len_udp' : ['std', 'mean', 'count', kbps, p25, p50, p75], \
            'interlength_udp' : ['mean', p25, p50, p75], 'rtp_interarrival' : ['std', 'mean', zeroes_count] ,\
            "inter_time_sequence": ['std', 'mean', p25, p50, p75] ,"label": [value_label],  "label2": [value_label]})
        df_train = pd.concat([df_train, train])
    dataset_dropped = df_train.dropna()
    new_header = []
    for h in dataset_dropped.columns:
        new_header.append(h[0] + "_" + h[1])
    # dataset_dropped.columns = dataset_dropped.columns.droplevel(1)
    dataset_dropped.columns = new_header
    dataset_dropped = dataset_dropped.rename(columns={'label_value_label': 'label'})
    dataset_dropped = dataset_dropped.rename(columns={'label2_value_label': 'label2'})
    dataset_dropped = dataset_dropped.rename(columns={'len_udp_kbps': 'kbps'})
    dataset_dropped = dataset_dropped.rename(columns={'len_udp_count': 'num_packets'})
    dataset_dropped = dataset_dropped.rename(columns={'rtp_interarrival_std': 'rtp_inter_timestamp_std'})
    dataset_dropped = dataset_dropped.rename(columns={'rtp_interarrival_mean': 'rtp_inter_timestamp_mean'})
    dataset_dropped = dataset_dropped.rename(columns={'rtp_interarrival_zeroes_count': 'rtp_inter_timestamp_num_zeros'})

    pcap_path = os.path.join(pcap_path, name)
    dataset_dropped.to_csv( pcap_path + ".csv" )
    html = df_unique_flow.to_html()
    with open(pcap_path + ".html", "w") as text_file:
        text_file.write(html)
    with open(pcap_path + "_info.txt", "w") as file:
        string = "Pacchetti droppati %s" % LEN_DROP
        file.write(string)
#%%
    # if (args.join):
         # merge_csv(directory_p)
    # if (args.plot):
    #     plot_stuff(pcap_path, dict_flow_data, df_unique_flow)

