# -*- coding: utf-8 -*-
"""
Created on Wed May  6 17:17:04 2020

@author: Gianl
"""
import pandas as pd

OUTDIR = "logs"
INTERNAL_MASK = "192.168."
MIN_PKT = 100
MIN_DURAT = 30
stats = []

def compute_stats(data, flow_id):
    ipg = data["timestamps"].diff()
    bitrate = data["len_frame"].sum() / (data["timestamps"].max() - data["timestamps"].min()) * 8

    data["time_sec"] = data["timestamps"].astype("int")
    rates = (data.groupby("time_sec")["len_frame"].sum()*8)
    if INTERNAL_MASK in flow_id[2]:
        direction = "S"
    elif INTERNAL_MASK in flow_id[1]:
        direction = "C"
    else:
        direction = "UNK"
    s =     pd.Series({
                        "pkt_nb": len(data["len_frame"]),
                        "pkt_avg": data["len_frame"].mean(),
                        "pkt_std": data["len_frame"].std(),
                        "ipg_avg": ipg.mean(),
                        "ipg_std": ipg.std(),
                        "bitrate": bitrate,
                        "rates_per_sec" : ":".join([ str(v) for v in rates.values ]),
                        "databyte": data["len_frame"].sum(),
                        "durat": data["timestamps"].max() - data["timestamps"].min(),
                        "direction" : direction,
                        "c_ip" : flow_id[2],
                        "s_ip" : flow_id[1],
                        "c_port" : flow_id[4],
                        "s_port" : flow_id[3],
                        "channel" : f"{flow_id[0]}_{flow_id[5]}"
    })

    if len(data["len_frame"]) >= MIN_PKT and \
        data["timestamps"].max() - data["timestamps"].min() >= MIN_DURAT:
        return s
    else:
        return None
