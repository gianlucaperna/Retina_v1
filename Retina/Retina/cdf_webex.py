import glob
import subprocess
import pandas as pd
import argparse
import os
from collections import defaultdict
import fastplot

#Creare 3 folder nella master directory
# 1080p - 720p - 4k
#Inserire i rispettivi CSV nelle folder

parser = argparse.ArgumentParser(description = "CDF")
parser.add_argument ("-d", "--directory", help = "Master directory", required = True)
parser.add_argument ("-so", "--software", help = "Stadia, Geforce, Webex", choices=['stadia', 'geforce', 'webex'], \
                        default = None, type = str.lower, required=True)
args = parser.parse_args()

path_3gb = os.path.join(args.directory, "3gbad")
path_3g = os.path.join(args.directory, "3good")
path_4g = os.path.join(args.directory, "4good")

PLOT_ARGS_SMALL={'style': 'latex',
           'figsize': (4,3),
           'grid':True}

def quality_data(path_data):
    dfs = []
    for f in glob.glob(os.path.join(path_data,"*.csv")):
        df = pd.read_csv(f)
        dfs.append(df)
    data = pd.concat(dfs)
    try:
        data["channel"] = data["channel"].str.replace('_', '-')#latex problema con _
    except:
        pass
    return data

def samples_creation(data, software, threshold = None):
    samples = []
    for i, row in data.iterrows():
        if software == "geforce":
            samples += [ int(e)/1000000 for e in row.rates_per_sec.split(":") ]
        elif software == "stadia":
            if row.channel.split("-")[1] != "96":
                if threshold:
                    samples += [ int(e)/1000000 for e in row.rates_per_sec.split(":") if int(e)/1000000>threshold]
                else:
                    samples += [ int(e)/1000000 for e in row.rates_per_sec.split(":") if int(e)/1000000> 1]
        elif software == "webex":
            samples += [ int(e)/1000000 for e in row.rates_per_sec.split(":") ]
        else:
            print("software errato")
            pass
    return samples

data_3gb = quality_data(path_3gb)
data_3g = quality_data(path_3g)
data_4g = quality_data(path_4g)

samples_hd = samples_creation(data_3gb, args.software)
threshold = 12
samples_fhd = samples_creation(data_3g, args.software, threshold=threshold)
threshold = 32
samples_4k = samples_creation(data_4g, args.software, threshold=threshold )

samples = [("3gbad",samples_hd),("3good", samples_fhd),("4good", samples_4k)]
plot = fastplot.plot(samples, None, mode="CDF_multi",
                     xlabel = "Bitrate [Mbit/s]", legend=True,
                     **PLOT_ARGS_SMALL, legend_alpha = 0.7) #legend_loc='upper right')
plot.savefig( os.path.join(args.directory, "bitrate_multi.pdf"))
