#Open Tshark and run command to turn pcap to json
import subprocess
import pandas as pd
from Decode import decode_stacked
import os
import json
import sys
from Json2List import json_to_list
from json2stat import json2stat
import time
from plotting_static import plot_stuff_static
from plotting import plot_stuff
from Martino_log import compute_stats
import copy
import sys

def pcap_to_port(source_pcap):
    try:
    # Retrive all STUN packets
        command = ['tshark', '-r', source_pcap, '-l', '-n', '-T', 'ek', '-Y (stun)']
        process = subprocess.run(command, stdout=subprocess.PIPE, encoding = 'utf-8', errors="ignore", shell=False )
        output = process.stdout
    except Exception as e:
        print ("Errore in pcap_to_json: {}".format(e))
        process.kill()
        raise e
    # I've got all STUN packets: need to find which ports are used by RTP
    used_port = set()
    for obj in decode_stacked(output):
        try:
            if 'index' in obj.keys():
                continue
            if 'stun' in obj['layers'].keys() and "0x00000101" in obj['layers']["stun"]["stun_stun_type"]:          #0x0101 means success
                used_port.add(obj['layers']["udp"]["udp_udp_srcport"])
                used_port.add(obj['layers']["udp"]["udp_udp_dstport"])
        except:
            continue
    return {"pcap" : source_pcap, "port" : list(used_port)}

def pcap_to_json(tuple_param): #source_pcap, used_port
  #  print (f"PID 2json: {os.getpid()}")
    try:
        source_pcap = tuple_param[0] # path del pcap
        used_port = tuple_param[1] #porte stun recuperate dal pcap
        screen = tuple_param[2] # old per webex, tutti i flussi video sono etichettati come SS
        quality = tuple_param[3] #old per webex, specifica qualità flussi video, (devono essere tutti uguali)
        plot = tuple_param[4] # se True crea Plot
        json_file = tuple_param[5] #salvare su file json tutti i pacchetti rtp della cattura
        software = tuple_param[6] # webex jitsi ..
        file_log = tuple_param[7] #directory padre dei file .log
        time_drop = tuple_param[8] # durata in secondi minima che deve avere un flusso
        general_log = tuple_param[9] #se c'è contiene il path dove salvare il file, altrimenti False
        time_aggregation = tuple_param[10]
        name = os.path.basename(source_pcap).split(".")[0] # nome del pcap senza estensione
        pcap_path = os.path.dirname(source_pcap) # percorso pcap senza file
        json_path = os.path.join(pcap_path,name+".json")
        command = ['tshark', '-r', source_pcap, '-l', '-n', '-T', 'ek']
        for port in used_port:
            command.append("-d udp.port==" + str(port) + ",rtp")
        with open(os.path.join(pcap_path,name+".txt") ,"w",encoding = 'utf-8') as file:
            subprocess.Popen(command,stdout = file, stderr = None ,encoding = 'utf-8').communicate()
        output = os.path.join(pcap_path,name+".txt") #direcotry file output da tshark
        dict_flow_data, df_unique_flow, unique_flow= json_to_list(output, json_path, time_drop, json_file)
        # for flow_id in dict_flow_data.keys():
        #     print(type(dict_flow_data[flow_id]["timestamps"].iloc[0]))
        if general_log: #genera log simile a tstat
            general_dict_info = {}
            for flow_id in dict_flow_data:
                s = compute_stats(copy.deepcopy(dict_flow_data[flow_id]),flow_id, name+".pcapng")
                if s is not None:
                    general_dict_info[flow_id] = s
                    general_df=pd.DataFrame.from_dict(general_dict_info, orient='index').reset_index(drop = True)
                    general_df.to_csv(os.path.join(general_log,name+"_gl.csv"))
        # dict list etc sono passate by reference, attenzione!!
        for time_agg in time_aggregation:
            dataset_dropped = json2stat(copy.deepcopy(dict_flow_data), pcap_path, name, time_agg, screen = screen, quality = quality, software = software, file_log = file_log)
        if plot == "static":
            plot_path = os.path.join(pcap_path,name)
            plot_stuff_static(plot_path, dict_flow_data, df_unique_flow)
        elif plot == "dynamic":
            plot_path = os.path.join(pcap_path,name)
            plot_stuff(plot_path, dict_flow_data, df_unique_flow, dataset_dropped)
        else:
            pass

    except Exception as e:
        print('Pcap2Json: Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
        raise NameError("Pcap2Json error")
    return
