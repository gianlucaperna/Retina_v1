# -*- coding: utf-8 -*-
"""
Created on Sat Apr 25 14:11:23 2020

@author: Gianl
"""
import pandas as pd
import numpy as np
from Label import labelling
from Label import labelling2
from Label import etichetto_name
from InterStatistics import inter_statistic
from SeriesStats import *
from LogWebexManager import *
from scipy.stats import kurtosis, skew, moment


def moment3(series):
    return moment(series, moment=3)
def moment4(series):
    return moment(series, moment=4)


def OtherDataset(dict_flow_data, pcap_path, name, label, time_aggregation):
    try:
        df_train = pd.DataFrame()
        LEN_DROP = 0
        dict_flow_data, LEN_DROP = inter_statistic (dict_flow_data, LEN_DROP)
        percentili = [p10, p20, p25, p30, p40, p50, p60, p70, p75, p80, p90, p95, max_min_R, kurtosis, skew,\
            moment3, moment4, len_unique_percent, max_value_count_percent, min_max_R]
        dict_flow_data = etichetto_name(dict_flow_data,label)
        df_train = pd.DataFrame()
        for flow_id in dict_flow_data.keys():
            dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
            dict_flow_data[flow_id].set_index('timestamps', inplace = True)
            dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
            train = dict_flow_data[flow_id].resample(f"{time_aggregation}s").agg({\
                'interarrival' : ['std', 'mean', max_min_diff]+percentili, \
                'len_udp' : ['std', 'mean', 'count', kbps, max_min_diff]+percentili, \
                'interlength_udp' : ['std', 'mean', max_min_diff]+percentili,\
                'rtp_interarrival' : ['std', 'mean', zeroes_count, max_min_diff]+percentili ,\
                "inter_time_sequence": ['std', 'mean', max_min_diff]+percentili ,\
                "label": [value_label],  "label2": [value_label]\
                                                                })
            train["flow"] = str(flow_id)
            train["pcap"] = str(name)
            df_train = pd.concat([df_train, train])
            dataset_dropped = df_train.dropna()
            dataset_dropped.reset_index(inplace = True, drop = True)
        new_header = []
        for h in dataset_dropped.columns:
            new_header.append(h[0] + "_" + h[1])
        #   dataset_dropped.columns = dataset_dropped.columns.droplevel()
        dataset_dropped.columns = new_header
        return dataset_dropped
    except:
        pass


def WebexDataset(dict_flow_data, pcap_path, name, screen , quality, software, file_log, time_aggregation):
    try:
        df_train = pd.DataFrame()
        LEN_DROP = 0
        dict_flow_data, LEN_DROP = inter_statistic (dict_flow_data, LEN_DROP)
        percentili = [p10, p20, p25, p30, p40, p50, p60, p70, p75, p80, p90, p95, max_min_R, kurtosis, skew,\
            moment3, moment4, len_unique_percent, max_value_count_percent, min_max_R]
        if file_log:
            dict_flow_data_2 = {}
            for flow_id in dict_flow_data.keys():
                   dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
                   dict_flow_data[flow_id].set_index('timestamps', inplace = True)
                   dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
                   dict_flow_data_2[flow_id] = dict_flow_data[flow_id].resample(f"{time_aggregation}s").agg({
                       'interarrival' : ['std', 'mean', max_min_diff]+percentili,\
                       'len_udp' : ['std', 'mean', 'count', kbps, max_min_diff]+percentili, \
                       'interlength_udp' : ['std', 'mean', max_min_diff]+percentili,\
                       'rtp_interarrival' : ['std', 'mean', zeroes_count, max_min_diff]+percentili ,\
                       "inter_time_sequence": ['std', 'mean', max_min_diff]+percentili,
                       "rtp_marker" : [sum_check]
                                                                            })

            for flow_id in dict_flow_data_2.keys():
                dict_flow_data_2[flow_id].reset_index(inplace = True, drop = False)
                new_header = [h[0] + "_" + h[1] if h[1] else h[0] for h in dict_flow_data_2[flow_id]]
                dict_flow_data_2[flow_id].columns = new_header
            #Gestione del LOG
            #Make fec_dict: fec_key: list of keys of all streams with the same csi
            with open(file_log, "r", encoding="ISO-8859-1") as f:
            #vado linea per line cosi
                log = f.readlines()
            fec_dict = make_fec_dict(log, dict_flow_data)
            #Crea d_log - {key come in dict_flow_data : Dataframe con dati dal log}
            #ha i dati di dal log per ogni flusso non-FEC
            #per i flussi FEC ha empty DataFrame
            d_log = make_d_log(log, dict_flow_data)
            #Merge dei dati del log e dict_flow_data_2
            dict_merge, flows_not_in_log = DictMerge(dict_flow_data_2, d_log, fec_dict)
            #Per rendere il codice operabile con json2stat
            df_train = WebLogdf(dict_merge, name)
            return df_train
        else:
            dict_flow_data = etichetto(dict_flow_data, screen, quality, software)
            df_train = pd.DataFrame()
            for flow_id in dict_flow_data.keys():
                dict_flow_data[flow_id]["timestamps"] = pd.to_datetime(dict_flow_data[flow_id]["timestamps"], unit = 's')
                dict_flow_data[flow_id].set_index('timestamps', inplace = True)
                dict_flow_data[flow_id] = dict_flow_data[flow_id].dropna()
                train = dict_flow_data[flow_id].resample(f"{time_aggregation}s").agg({\
                    'interarrival' : ['std', 'mean', max_min_diff]+percentili, \
                    'len_udp' : ['std', 'mean', 'count', kbps, max_min_diff]+percentili, \
                    'interlength_udp' : ['std', 'mean', max_min_diff]+percentili,\
                    'rtp_interarrival' : ['std', 'mean', zeroes_count, max_min_diff]+percentili ,\
                    "inter_time_sequence": ['std', 'mean', max_min_diff]+percentili ,\
                    "rtp_marker" : [sum_check],
                    "label": [value_label],  "label2": [value_label]\
                                                                    })
                train["flow"] = str(flow_id)
                train["pcap"] = str(name)
                df_train = pd.concat([df_train, train])
                dataset_dropped = df_train.dropna()
                dataset_dropped.reset_index(inplace = True, drop = True)
            new_header = []
            for h in dataset_dropped.columns:
                new_header.append(h[0] + "_" + h[1])
            #   dataset_dropped.columns = dataset_dropped.columns.droplevel()
            dataset_dropped.columns = new_header
            return dataset_dropped
    except Exception as e:
        print('WebexDataset: Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        raise NameError("WebexDataset error")



def JitsiDataset(dict_flow_data, pcap_path, name, screen , quality, software, file_log):
    pass

def ZoomDataset(dict_flow_data, pcap_path, name, screen , quality, software, file_log):
    pass


#OLD LABELLING PER RIMANERE COMPATIBILE CON VECCHIO SOFTWARE

def etichetto(dict_flow_data, screen, quality, software):
    if screen is None and quality is None and software == "webex":
        dict_flow_data = labelling2(dict_flow_data, screen, quality) #etichetto audio video fec audio fec video
        for flow_id in dict_flow_data:
            dict_flow_data[flow_id]["label"] = -1
        return dict_flow_data
    elif screen is None and quality is None:
        for flow_id in dict_flow_data:
            dict_flow_data[flow_id]["label"] = -1
            dict_flow_data[flow_id]["label2"] = -1
        return dict_flow_data
    dict_flow_data = labelling (dict_flow_data, screen, quality)
    dict_flow_data = labelling2(dict_flow_data, screen, quality)
    return dict_flow_data
