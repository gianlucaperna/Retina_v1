# Retina
Real-Time Analyzer

Installazione:

La gestione dei pacchetti è fatta con Poetry. 
Per installare poetry seguire la guida al link: https://python-poetry.org/docs/#installation

Clonare la direcotory git, posizionarsi all'interno con un terminale e eseguire:

# > poetry install
# > poetry shell (per abilitare il virtual env)

..

# > cd retina/Retina
# > python Retina.py -h

usage: Retina.py [-h] -d DIRECTORY [-j] [-js] [-p {static,dynamic}] [-v]
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

