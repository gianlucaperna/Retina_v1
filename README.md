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
Retina.py [-h] -d DIRECTORY [-j] [-js] [-p {static,dynamic}] [-v]
                 [-so {webex,jitsi,teams,skype}] [-s] [-q {LQ,MQ,HQ}]
                 [-log LOG_DIR] [-sp SPLIT] [-dp DROP] [-gl]
                 [-ta TIME_AGGREGATION [TIME_AGGREGATION ...]]


optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Master directory
  -j, --join            Join all .csv
  -js, --json           Create Json of the pcap
  -p {static,dynamic}, --plot {static,dynamic}
                        Plot info
  -v, --verbose         verbosity output (txt, .json)
  -so {webex,jitsi,teams,skype}, --software {webex,jitsi,teams,skype}
                        Webex, Skype, M.Teams
  -s, --screen          Set True if in capture there is only video screen
                        sharing
  -q {LQ,MQ,HQ}, --quality {LQ,MQ,HQ}
                        HQ if HQ video 720p, LQ low 180p, MQ medium 360p
  -log LOG_DIR, --log_dir LOG_DIR
                        Directory logs file
  -sp SPLIT, --split SPLIT
                        Set to divide pcap
  -dp DROP, --drop DROP
                        Time drop
  -gl, --general_log    general log for flows
  -ta TIME_AGGREGATION [TIME_AGGREGATION ...], --time_aggregation TIME_AGGREGATION [TIME_AGGREGATION ...]
                        time window aggregation
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
