# Retina
Real-Time Analyzer, analyze RTP flows of .pcap/.pcapng, creating statistics and plot about them

## Installazione:

La gestione dei pacchetti è fatta con Poetry. 
Per installare poetry seguire la guida al link: https://python-poetry.org/docs/#installation

Clonare la direcotory git, posizionarsi all'interno con un terminale e eseguire:
```
poetry install
poetry shell (per abilitare il virtual env)

..

cd retina/Retina
python Retina.py -h
```
## Usage: 

```
python Retina.py -d pcap_to_analyze -so webex -ta 1000 2000 3000 -log folder_log_webex -p dynamic
```

If you want analyze more than one pcap at a time, in -d parameter give the path of the folder in which are stored the pcap.
e.g python Retina.py -d /path_to_analyze/

```
pcap_to_analyze
|
|__ pcap1.pcapng
|__ pcap2.pcapng
```
    
Retina is parellel programming oriented, so, if you run the code on multiple pcap the code will uses a maximum of n_core_cpu - 1 to process all the files. You can set this parameter changing n_process in Retina.py file.

-p is a flag that provide static or dynamic plot. If dynamic is setted, the .html file is generated for each flow find in the pcap, for all pcaps.

-dp [s] serves to specify the minimum length of a flow to be considered in the analysis. e.g if -dp 5 is specified, all the flows <5s are dropped.

-ta is useful to express time aggregation to use to compute the stats. Is possibile compute stats per different time agg, e.g
-ta 1000 2000 3000 means compute stats for 1s, 2s and 3s.

-log if you are analyzing webex teams or jitsi, you can pass the path of the folder in which are stored the logs
-so really important if -log is specified, because using this flag you tell to the program how to label your data. Log file of Webex and Jitsi are different!

N.B Log and pcap must have the same name
