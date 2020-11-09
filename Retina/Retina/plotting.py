# Standard plotly imports
import plotly.graph_objs as go
import plotly.figure_factory as ff
import plotly
import plotly.express as px
import plotly.io as pio
#Python imports
import os
import pandas as pd
from Table2HTML import table
import numpy as np
import sys
from ast import literal_eval as make_tuple
import itertools
import seaborn as sns

def make_rtp_data(dict_flow_data):

    packets_per_second = {}
    kbps_series = {}
    inter_packet_gap_s = {}
    inter_rtp_timestamp_gap = {}
    len_frame = {}
    rtp_timestamp = {}

    for flow_id in dict_flow_data:
        #If the index is already datetime
        if isinstance(dict_flow_data[flow_id].index, pd.DatetimeIndex):
            inner_df = dict_flow_data[flow_id].sort_index().reset_index()
        else:
            inner_df = dict_flow_data[flow_id].sort_values('timestamps')

        # Need to define a datetime index to use resample
        datetime = pd.to_datetime(inner_df['timestamps'], unit = 's')
        inner_df = inner_df.set_index(datetime)

        packets_per_second[flow_id] = inner_df.iloc[:,0].resample('S').count()
        kbps_series[flow_id] = inner_df['len_frame'].resample('S').sum()*8/1024
        inter_packet_gap_s[flow_id] = inner_df['timestamps'].diff().dropna()
        inter_rtp_timestamp_gap[flow_id] = inner_df['rtp_timestamp'].diff().dropna()
        len_frame[flow_id] = inner_df["len_frame"].copy()
        rtp_timestamp[flow_id] = inner_df["rtp_timestamp"].copy()

    return packets_per_second, kbps_series, inter_packet_gap_s, inter_rtp_timestamp_gap, len_frame, rtp_timestamp


#Convert tuple to string for naming purposes
def tuple_to_string(tup):
    tup_string = ''
    for i in range(len(tup)):
        if i == len(tup)-1:
            tup_string += str(tup[i])
        else:
            tup_string += str(tup[i])+'_'
    tup_string = tup_string.replace('.','-')
    tup_string = tup_string.replace(':','-')
    return tup_string


def label_for_plotting(dataset_dropped):
    
    dict_label = {
    -1 : "Unknown",
    0: "Audio",
    1: "Video all qualities",
    2: "Fec-video",
    3: "ScreenSharing",
    4: "FEC-audio",
    5: "VideoHQ",
    6: "VideoLQ",
    7: "VideoMQ",
    8: "Fec-ScreenSharing"
    }
    
    #{flow tuple: label}
    flow_label = {}
    for flow in dataset_dropped["flow"].unique():
        try:
            flow_label[make_tuple(flow)] = dict_label[dataset_dropped[dataset_dropped["flow"] == flow]["label"].iloc[0]]
        except e:
            print("Error in flow_label.")
    
    return flow_label


def make_new_unique_table (dict_flow_df, flow_label):    
    unique_l = []
    for key, value in dict_flow_df.items():
        inner_list = []
        for m in key:
            inner_list.append(m)
        inner_list.append(value["rtp_csrc"].iloc[0])
        if key in flow_label.keys():
            inner_list.append(flow_label[key])
        else:
            inner_list.append("unknown")
        unique_l.append(inner_list)

    unique_df = pd.DataFrame(data=unique_l, columns=["ssrc", "source_addr", "dest_addr", "source_port", "dest_port", "rtp_p_type", "csrc", "label"])
    return unique_df

def make_dict_csrc(dict_flow_df, unique_df):
    csrcs = unique_df["csrc"].unique()
    csrc_flows = {k: [] for k in csrcs}
    for key, value in dict_flow_df.items():
        csrc_value = value["rtp_csrc"].iloc[0]
        csrc_flows[csrc_value].append(key)
        
    csrc_colour = {}
    palette = itertools.cycle(sns.color_palette("Set1", n_colors=len(csrcs)).as_hex())
    #colors = itertools.cycle(["red", "blue", "yellow", "green", "cyan", "black", "orange"])
        
    for key in csrc_flows.keys():
        csrc_colour[key] = next(palette)

    return csrc_flows, csrc_colour
    

def plot_stuff(pcap_path, dict_flow_df, df_unique, dataset_dropped):

    #print(f"Plotting information of {pcap_path}")

    #print(dict_flow_df[('0x9addd8d5', '192.168.1.105', '69.26.161.221', 64694, 5004, 108)].columns)
    print(list(dataset_dropped.columns))
    #print("Dataset dropped in plotting dynamic: \n", dataset_dropped.head(5))
    flow_label = label_for_plotting(dataset_dropped)
    #print("Flow label:\n", flow_label)

    #Saving info - FIX PATH WITH PCAP_PATH
    save_dir = os.path.join(pcap_path, "Plots_html")
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    #Take data
    packets_per_second,\
    kbps_series,\
    inter_packet_gap_s,\
    inter_rtp_timestamp_gap,\
    len_frame,\
    rtp_timestamp = \
            make_rtp_data(dict_flow_df)
    
    #Unique df that has also csrc and label
    unique_df = make_new_unique_table(dict_flow_df, flow_label)
    
    #csrc_flows - {csrc: list of flow tuples with that csrc}
    #csrc_colour - {csrc: colour}
    csrc_flows, csrc_colour = make_dict_csrc(dict_flow_df, unique_df)

    #Take keys of dict_flow_data in a list to iterate them easily
    l_keys = []
    
    for i in dict_flow_df.keys():
        l_keys.append(i)
        


    #Plot stuff

    #Speed in kbps
    data_plot = kbps_series.copy()

    title = 'Bitrate in kbps'
    fig_kbps = go.Figure()

    for i in range(len(data_plot)):
        name = "Flow " + str(i) + " " + flow_label[l_keys[i]]
        csrc = dict_flow_df[l_keys[i]]["rtp_csrc"].iloc[0]
        colour = csrc_colour[csrc]
        
        if l_keys[i][1].startswith('192.'):

            mode='lines'
            fig_kbps.add_trace(go.Scatter(
                            x=data_plot[l_keys[i]].index,
                            y=data_plot[l_keys[i]],
                            mode=mode,
                            name=name,
                            line=dict(color=colour),
                            ))
        else:
            line=dict(dash='dash', color=colour)
            fig_kbps.add_trace(go.Scatter(
                            x=data_plot[l_keys[i]].index,
                            y=data_plot[l_keys[i]],
                            line=line,
                            name=name,
                            ))

    fig_kbps.update_layout(
        template="plotly_white",
        title=dict(text=title, x=0.4),
        xaxis_title="Time",
        yaxis_title="kbps",
        font=dict(size=18, color="#7f7f7f",),
        autosize=True,
        legend=dict(
        title="<b> RTP flows </b>", \
        font=dict(size=14) \
        ),
    )


    #Packets per second
    data_plot = packets_per_second.copy()

    title = 'Packets per second'
    fig_pps = go.Figure()

    for i in range(len(data_plot)):

        name = "Flow " + str(i) + " " + flow_label[l_keys[i]]
        csrc = dict_flow_df[l_keys[i]]["rtp_csrc"].iloc[0]
        colour = csrc_colour[csrc]
        
        if l_keys[i][1].startswith('192.'):

            mode='lines'
            fig_pps.add_trace(go.Scatter(
                        x=data_plot[l_keys[i]].index,
                        y=data_plot[l_keys[i]],
                        mode=mode,
                        name=name,
                        line=dict(color=colour),
                        ))
        else:
            line=dict(dash='dash', color=colour)
            fig_pps.add_trace(go.Scatter(
                            x=data_plot[l_keys[i]].index,
                            y=data_plot[l_keys[i]],
                            line=line,
                            name=name
                            ))

    fig_pps.update_layout(
        template="plotly_white",
        title=dict(text=title, x=0.4),
        xaxis_title="Time",
        yaxis_title="Number of packets",
        font=dict(size=18, color="#7f7f7f",),
        legend=dict(
        title="<b> RTP flows </b>",
        font=dict(size=14)
        ),
    )


    html_table = table(unique_df, "Main Graph", True)

    #Save table and graphs in html
    main_html_save = os.path.join(save_dir, "main_graphs.html")
    with open(main_html_save, 'w') as f:
        #f.write("<h1 style='color:blue;font-family:Open sans;'> Main graphs and general data on pcap </h1>")
        f.write(html_table)
    with open(main_html_save, 'a') as f:
        f.write(fig_kbps.to_html(full_html=False, include_plotlyjs='cdn'))
        f.write(fig_pps.to_html(full_html=False, include_plotlyjs='cdn'))

    print("Did the main graphs successfully")

    try:
        #Plot the single graphs
        for key1 in dict_flow_df.keys():
            
            csrc1 = dict_flow_df[key1]["rtp_csrc"].iloc[0]
            label1 = flow_label[key1]

            title = "Bitrate distribution"
            fig_bit_h = px.histogram(x=kbps_series[key1] ,marginal="box", opacity = 0.6,\
                histnorm = "probability density", color_discrete_sequence=["#FFA69E"])
            fig_bit_h.update_layout(
                template="simple_white",
                title=dict(text=title, x=0.5),
                xaxis_title="Bitrate [kbps]",
                yaxis_title="Probability density function",
                font=dict(size=18, color="#7f7f7f",),
                autosize=True,

            )
            fig_bit_h.update_yaxes(showgrid=True)
            fig_bit_h.update_xaxes(showgrid=True)


            #1 Plot histogram of packet length - len_frame[key1]
            title = "Packet-length distribution"
            fig_pl_h = px.histogram(x=len_frame[key1], marginal="box", opacity = 0.6,\
                histnorm = "probability density",  color_discrete_sequence=["#FF686B"])
            fig_pl_h.update_layout(
                template="simple_white",
                #grid = {"xaxis":True,"yaxis":True},
                title=dict(text=title, x=0.5),
                xaxis_title="Packet length [Byte]",
                yaxis_title="Probability density function",
                font=dict(size=18, color="#7f7f7f",),
                autosize=True,
            )
            fig_pl_h.update_yaxes(showgrid=True)
            fig_pl_h.update_xaxes(showgrid=True)


            #2 Plot packet length in time - len_frame[key1]
            # title = "Packet length in time"
            # inside=go.Scatter(x=len_frame[key1].index, y=len_frame[key1],
            #                   mode='lines', line=dict(color='#815EA4'))
            # fig_pl_t = go.Figure(inside)
            # fig_pl_t.update_layout(
            #     title=dict(text=title, x=0.5),
            #     xaxis_title="Time",
            #     yaxis_title="Packet length [B]",
            #     font=dict(size=18, color="#7f7f7f",),
            #     autosize=True,
            # )

            #3 Plot histogram of inter-packet gap - inter_packet_gap_s
            #title = "Inter-packet gap [s] histogram"
            title="Interarrival time distribution"
            fig_ipg_h = px.histogram(x=inter_packet_gap_s[key1], marginal="box", opacity = 0.6,\
                histnorm = "probability density", color_discrete_sequence=["#A5FFD6"])
            fig_ipg_h.update_layout(
                template="simple_white",
                title=dict(text=title, x=0.5),
                xaxis_title="Interarrival [s]",
                #xaxis_type="log",
                yaxis_title="Probability density function",
                font=dict(size=18, color="#7f7f7f",),
                autosize=True,
            )
            fig_ipg_h.update_yaxes(showgrid=True)
            fig_ipg_h.update_xaxes(showgrid=True)

            #4 Plot Inter-packet gap in time - inter_packet_gap_s

            #title='Inter-packet gap in time'
            # inside=go.Scatter(x=inter_packet_gap_s[key1].index, y=inter_packet_gap_s[key1],
            #                   mode='lines', line=dict(color='red'))
            # fig_ipg_t = go.Figure(inside)
            # fig_ipg_t.update_layout(
            #     title=dict(text=title, x=0.5),
            #     xaxis_title="Time",
            #     yaxis_title="Inter-packet-gap [s]",
            #     font=dict(size=18, color="#7f7f7f",),
            #     autosize=True,
            # )

            #5 Histogram of Inter rtp timestamp gap - inter_rtp_timestamp_gap
            title="Inter-timestamp RTP distribution"
            #title = "Histogram of Inter-RTP-timestamp gap"
            fig_irtg_h = px.histogram(x= inter_rtp_timestamp_gap[key1],  marginal="box", opacity = 0.6,\
                histnorm = "probability density",  color_discrete_sequence=["#84DCC6"])
            fig_irtg_h.update_layout(
                template="simple_white",
                title=dict(text=title, x=0.5),
                xaxis_title="Inter-RTP-timestamp",
                yaxis_title="Probability density function",
                font=dict(size=18, color="#7f7f7f",),
                autosize=True,
            )
            fig_irtg_h.update_yaxes(showgrid=True)
            fig_irtg_h.update_xaxes(showgrid=True)


            #6 RTP-timestamp in time - rtp_timestamp[key1]
            # title='RTP-timestamp in time'
            # inside=go.Scatter(x=rtp_timestamp[key1].index, y=rtp_timestamp[key1],
            #                   mode='markers')
            # fig_rt_t = go.Figure(inside)
            # fig_rt_t.update_layout(
            #     title=dict(text=title, x=0.5),
            #     xaxis_title="Time",
            #     yaxis_title="RTP-timestamp",
            #     font=dict(size=18, color="#7f7f7f",),
            #     autosize=True,
            # )

            #Write to html string of flow and all associated plots
            table_list = []
            for item in key1:
                table_list.append(item)
            table_list.append(csrc1)
            table_list.append(label1)
            
            html_save = os.path.join(save_dir, tuple_to_string(key1)+'.html')
            col = ["ssrc", "source_addr", "dest_addr", "source_port", "dest_port", "rtp_p_type", "csrc", "label"]
            with open(html_save, 'w') as f:
                f.write(table( pd.DataFrame(data=[table_list], columns =col), "Flow Graph"))
            with open(html_save, 'a') as f:
                f.write(fig_bit_h.to_html(full_html=False, include_plotlyjs='cdn'))
                f.write(fig_pl_h.to_html(full_html=False, include_plotlyjs='cdn'))
                #f.write(fig_pl_t.to_html(full_html=False, include_plotlyjs='cdn'))
                f.write(fig_ipg_h.to_html(full_html=False, include_plotlyjs='cdn'))
                #f.write(fig_ipg_t.to_html(full_html=False, include_plotlyjs='cdn'))
                f.write(fig_irtg_h.to_html(full_html=False, include_plotlyjs='cdn'))
                #f.write(fig_rt_t.to_html(full_html=False, include_plotlyjs='cdn'))
    except Exception as e:
        print('Plotting: Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
