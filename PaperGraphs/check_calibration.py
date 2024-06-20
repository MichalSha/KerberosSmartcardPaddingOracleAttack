import os
import matplotlib
from matplotlib import pyplot as plt
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['pdf.fonttype'] = 42
from matplotlib.ticker import MaxNLocator
import numpy as np

from scapy.all import *
from pdb import set_trace

delays = {'Sat_Jul__1_20_03_51_2023':0.4, 'Sat_Jul__1_21_38_24_2023': 0.3, 
          'Sat_Jul__1_22_02_31_2023':0.2, 'Sun_Jul__2_00_05_02_2023': 1.0,
           'Sat_Jul__1_19_38_21_2023': 0.4, 'Sat_Jul__1_22_25_12_2023':0.1, 
           'Sat_Jul__1_23_38_03_2023':0.8, 'Sat_Jul__1_23_12_18_2023':0.6, 
           'Sat_Jul__1_21_11_18_2023': 0.4, 'Sat_Jul__1_22_46_10_2023':0.5}

Levels = [(0,50), (50, 90), (90, 100), (100, 110), (110, 120), (120, 130)]

def count_levels(hits):
    level_counts = [0, 0, 0, 0, 0, 0]
    for hit in hits:
        for lev_num, level in enumerate(Levels):
            if hit>=level[0] and hit <= level[1]:
                level_counts[lev_num]+=1
    return level_counts
    #for level in Levels:
    #    cur_level = 0
        

def categorize_hits(counts):
    if counts[0] >= 1:#2#3: 
        # with only calibration tests both 2 and 3 have only 2 incorrect positives but with 2 there are a lot more positives
        # for a few tests included that didn't work #2 1964 correct positives, 3 1133 correct positives, 4 194 correct positives
        return True
    return False

def get_hitlist(cal):
    lines = open(FOLDER + cal, 'r').readlines()
    hits = [int(line.split(' ')[3].strip('\n#')) for line in lines[4:-1] if line.strip() != ""]
    return hits


def get_hitlist_and_times(cal, conv_func):
    lines = open(FOLDER + cal, 'r').readlines()
    hits = [int(line.split(' ')[3].strip('\n#')) for line in lines[4:-1] if line.strip() != ""]

    hit_times = [conv_func(int(line.split(' ')[1].strip('\n#'))) for line in lines[4:-1] if line.strip() != ""]
    #set_trace()
    return hits, hit_times


get_test_num = lambda x: int(x.split('_')[-1].split('.')[0])
get_test_time = lambda x: x.split('_')[3:7]
get_test_sort = lambda x: (get_test_time(x), get_test_num(x))

#19_38_21 remove 
#20_03_51 ||
#def convert_time_to_cycles()
def create_conversion_function(cal):
    lines = open(FOLDER + cal, 'r').readlines()
    time_lines = [line for line in lines if 'cycle' in line]
    first = time_lines[0].split(' ')
    last = time_lines[-1].split(' ')
    first_sec = float(first[3])
    first_cycle = int(first[5])
    last_sec = float(last[3])
    last_cycle = int(last[5])
    #set_trace()
    conv = (last_cycle-first_cycle)/(last_sec-first_sec)
    to_cycles = lambda x: first_cycle + (x-first_sec)*conv
    return to_cycles

def get_file_times(cal):
    lines = open(FOLDER + cal, 'r').readlines()
    time_lines = [line for line in lines if 'cycle' in line]
    first = time_lines[0].split(' ')
    last = time_lines[-1].split(' ')
    first_sec = float(first[3])
    last_sec = float(last[3])
    return (first_sec, last_sec)

def create_reverse_conversion_function(cal):
    lines = open(FOLDER + cal, 'r').readlines()
    time_lines = [line for line in lines if 'cycle' in line]
    first = time_lines[0].split(' ')
    last = time_lines[-1].split(' ')
    first_sec = float(first[3])
    first_cycle = int(first[5])
    last_sec = float(last[3])
    last_cycle = int(last[5])
    #set_trace()
    conv = (last_sec-first_sec)/(last_cycle-first_cycle)
    to_seconds = lambda x: first_sec + (x-first_cycle)*conv
    return to_seconds

as_rep_port_list = []
as_rep_pkt_list = []
as_rep_pkt_retransmission_list = []
as_rep_pkt_list_count = []
as_rep_ack_list = []
as_rep_finack_list = []

def get_next_after(cur, time_list):
    for val in time_list:
        if val >= cur:
            return val
    else:
        return -1

def create_pkt_ack_finack_sets():
    asrep_sets = []
    for as_rep in as_rep_pkt_list:
        next_ack = get_next_after(as_rep, as_rep_ack_list)
        next_finack = get_next_after(as_rep, as_rep_finack_list)
        asrep_sets.append((as_rep, next_ack, next_finack))
    return asrep_sets

pkt_count = 0
def handle_pkt(pkt):
    global pkt_count
    pkt_count += 1 
    #pkt time float(pkt.time)
    if pkt.sport != 88 and pkt.dport != 88:
        return
    
    if Raw in pkt:
        if pkt.sport != 88:
            return
        payload = pkt['Raw'].load
        if len(payload) < 100:
            return
        if pkt.sport == 88 and payload[0x10] == 5 and  payload[0x15] == 0xb and  payload[0x26] == 0xf:
            
           
            as_rep_port_list.append(pkt.dport)
            as_rep_pkt_list.append(float(pkt.time))
            as_rep_pkt_list_count.append(pkt_count)
            print("Found kerb 5as rep")
            return
            #set_trace()#pass #pkt['Raw'] #pkt['TCP'].flags
    else:
        #set_trace()#print(pkt.flags)
        if pkt[TCP].flags.value == 16:
            as_rep_ack_list.append(float(pkt.time))
        elif pkt[TCP].flags.value == 17:
            as_rep_finack_list.append(float(pkt.time))
        #print(pkt[TCP].flags) .value

def get_asrep(cal_ftimes, asreps):
    for asrep in asreps:
        if asrep[0]>=cal_ftimes[0] and asrep[0]<=cal_ftimes[1]+2:#+4:
            return asrep
    else:
        print("not found")
        set_trace()
        print(str(cal_ftimes))

def filter_hits(hits, hit_times, asrep_times):
    for i in range(len(hits)):
        if hit_times[i]>=asrep_times[0]:
            break
    filtered_hits = hits[i:]
    filtered_hit_times = hit_times[i:]
    return (filtered_hits, filtered_hit_times)


def filter_hitsrange(hits, hit_times, range_times):
    for i in range(len(hits)):
        if hit_times[i]>=range_times[0]:
            break
    else:
        filtered_hits = []
        filtered_hit_times =[]
        return (filtered_hits, filtered_hit_times)
    for j in range(len(hits))[::-1]:
        if hit_times[j]<=range_times[1]:
            break
    else:
        filtered_hits = []
        filtered_hit_times =[]
        return (filtered_hits, filtered_hit_times)

    filtered_hits = hits[i:j+1]
    filtered_hit_times = hit_times[i:j+1]
    return (filtered_hits, filtered_hit_times)


def filter_hits_above(hits, hit_times, val=150):
    nhits = []
    nhit_times = []
    for i, hit in enumerate(hits):
        if hit <= val:
            nhits.append(hit)
            nhit_times.append(hit_times[i])
    return (nhits, nhit_times)


def find_asrep_file(asrep):
    poss_ftimes = []
    for ftime in file_times:
        if asrep[0] >= ftime[0][0] and asrep[0] <= ftime[0][1]:
            poss_ftimes.append(ftime)

    if len(poss_ftimes) ==1:
         set_trace()
    return poss_ftimes
    
FOLDER = "calibrationtimes\\"

if __name__ == '__main__':
    calib_files_ = os.listdir(FOLDER)
    calib_files = [cal for cal in calib_files_ if ('pcap' not in cal) and ('times' not in cal)]
    calib_times = [cal for cal in calib_files_ if  ('times' in cal)][0]
    calib_times2 = [cal for cal in calib_files_ if  ('times' in cal)]
    #calib_pcap = [cal for cal in calib_files_ if  ('pcap' in cal)][0]
    calib_groups = set([cal.split("pt")[0] for cal in calib_files])
    correct_T = 0
    correct_F = 0
    incorrect_T = 0
    incorrect_F = 0


    calib_files.sort(key=get_test_sort)#get_test_num)
   

    ghits_all = []
    ghits_t_all = []
    bhits_all = []
    bhits_t_all = []
    

    ghit_times50 = []
    ghits_50 = []
    ghit_times150 = []
    ghits_150 = []
    bhit_times50 = []
    bhits_50 = []
    bhit_times150 = []
    bhits_150 = []
    bhit_times100 = []
    bhits_100 = []
    ghit_times100 = []
    ghits_100 = []
    bhit_times106 = []
    bhits_106 = []
    ghit_times106 = []
    ghits_106 = []



    gmsgs = []
    bmsgs = []
    bmsgs106 = []
    gzero = 0
    bzero = 0
    bzero106 = 0
    file_times = []

    #set_trace()
    time_lines = open(FOLDER+calib_times, 'r').readlines()[2:]
    recv_times = [(float(line.split()[3].strip(',')), float(line.split()[7].strip(','))) for line in time_lines]

    count = 0
    for cal in calib_files[:]:#1000]:
        cal_group = cal.split("pt")[0]
        test_num = get_test_num(cal) #int(cal.split('_')[-1].split('.')[0])
        is_positive = (test_num//5)%2==0 
        cal_times = get_file_times(cal)
        cur_recv_times = recv_times[test_num]
        to_cycle = create_conversion_function(cal)
        to_sec = create_reverse_conversion_function(cal)
        hits, hit_times = get_hitlist_and_times(cal, to_sec)
        if len(hits) == 0:
            if is_positive:
                gzero+=1
            else:
                bzero +=1
            continue
        filt_hits, filt_hit_times = filter_hits(hits, hit_times, cur_recv_times)
        if len(filt_hits) == 0:
            if is_positive:
                gzero+=1
            else:
                bzero +=1
            continue
        filt_hit_times_ = [hit_time - cur_recv_times[1] for hit_time in filt_hit_times]
        hits150, hit_times150 = filter_hits_above(filt_hits, filt_hit_times_)
        hits125, hit_times125 = filter_hits_above(filt_hits, filt_hit_times_, 125)
        hits100, hit_times100 = filter_hits_above(filt_hits, filt_hit_times_, 98) #101
        hits106, hit_times106 = filter_hits_above(filt_hits, filt_hit_times_, 106)
        hits111, hit_times111 = filter_hits_above(filt_hits, filt_hit_times_, 111)
        
        #95)#100)
        hits50, hit_times50 = filter_hits_above(filt_hits, filt_hit_times_, 50)
        hits90, hit_times90 = filter_hits_above(filt_hits, filt_hit_times_, 90)
        
        #hit_times50_ = [hit_time - cur_recv_times[1] for hit_time in hit_times50]
        #hit_times150_ = [hit_time - cur_recv_times[1] for hit_time in hit_times150]
        #hit_times100_ = [hit_time - cur_recv_times[1] for hit_time in hit_times100]
        
        #set_trace()
        fhits100, fhit_times100 = filter_hitsrange(hits100, hit_times100, (0.12,0.14))
        fhits106, fhit_times106 = filter_hitsrange(hits106, hit_times106, (0.12,0.14))
        #fhits100, fhit_times100 = filter_hitsrange(hits111, hit_times111, (0.12,0.14))


        if is_positive:
            ghit_times100 += hit_times100
            ghits_100 += hits100
            ghits_all += filt_hits
            ghits_t_all += filt_hit_times_

            gmsgs += [(fhits100, fhit_times100)]#(ghits_100, ghit_times100)]
            #ghit_times50 += hit_times50_
            #ghits_50 += hits50
        else:
            bhit_times100 += hit_times100
            bhits_100 += hits100
            bhit_times106 += hit_times106
            bhits_106 += hits106
            if len(fhits100) != 0:
                set_trace()

            bhits_all += filt_hits
            bhits_t_all += filt_hit_times_

            bmsgs += [(fhits100, fhit_times100)]
            bmsgs106 += [(fhits106, fhit_times106)]
            #bhit_times50 += hit_times50_
            #bhits_50 += hits50


    

    plt.plot(ghits_t_all, ghits_all, '.', label="Conforming")
    plt.plot(bhits_t_all, bhits_all, '^', label="Nonconforming")
    plt.ylim(top=110)
        #plt.xlim(right=0.3, left=0)
        #plt.xlim(right=0.27, left=0.1)
    plt.xlim(right=0.24, left=0.1)

    [i for i in range(120)]
    plt.plot([0.12 for i in range(120)], [i for i in range(120)], '--', color='black')
    plt.plot([0.141 for i in range(120)], [i for i in range(120)], '--', color='black')
    plt.xlabel("Time from FIN+ACK [sec]", fontsize=18)
    #plt.xlabel("Time After Send [sec]")
    plt.ylabel("Access Time [Cycles]", fontsize=18)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=13)
    #plt.title("Cumulative Hits around finack packet")
    plt.legend(loc='center right', prop={'size':17})#'upper right')
    plt.show()


   
    
    set_trace()

    #plt.bar(ghit_times100, 60, label="conforming")
    #plt.bar(bhit_times100, 60, label="nonconforming")
    plt.hist([ghit_times100, bhit_times100], 60, label=["conforming", "nonconforming"])
    #plt.hist(ghit_times100, 60, label="conforming")
    #plt.hist(bhit_times100, 60, label="nonconforming")
    plt.ylabel("Hit count")
    plt.xlabel("Time from FIN+ACK[sec]")
    #plt.title("Cumulative Hit Counts around finack packet")
    plt.legend()
    plt.show()
    set_trace()
    gcount = len(gmsgs) + gzero
    bcount = len(bmsgs) + bzero
    
    gcounts = [0 for i in range(6)]#20)]
    gcounts[0] = gzero
    for msg in gmsgs:
        gcounts[len(msg[0])] += 1

    bcounts = [0 for i in range(6)]#20)]
    bcounts[0] = bzero
    bcounts2 = [0 for i in range(6)]#20)]
    bcounts2[0] = bzero
    for msg in bmsgs:
        bcounts[len(msg[0])] += 1

    for msg in bmsgs106:
        bcounts2[len(msg[0])] += 1

   
    fg = plt.figure()#figure()
    ax = fg.gca()

    
    
    bar1 = ax.barh([0,1,2,3,4,5], gcounts, height=0.4, label ="conforming") #, align='center' , width=0.4
    bar2 = ax.barh([i+0.4 for i in range(6)],bcounts, height=0.4, align='center', label ="nonconforming")# , align='center' #, width=0.4,
    
    #bar3 = ax.bar([i+0.4 for i in range(6)],bcounts2, width=0.2, label ="nonconforming +$\sigma$")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    #ax.set_xlabel("Msg hit count")
    #ax.set_ylabel("Msg count")
    ax.set_ylabel("Msg hit count")
    ax.set_xlabel("Msg count")
    ax.set_xscale("log") #yscale 
   
    set_trace()
    #plt.title("Distribution of message hit counts")
    plt.legend()
    #fg.legend(loc="center right")
    fg.show()
    
    #ngcounts = [gc/gcount*100 for gc in gcounts]
    #nbcounts = [gc/bcount*100 for gc in bcounts]
    ngcounts = [gc/gcount for gc in gcounts]
    nbcounts = [gc/bcount for gc in bcounts]
    nbcounts2 = [gc/bcount*100 for gc in bcounts2]
    gmsg_lens = [len(msg[0]) for msg in gmsgs]#+ [0]*gzero
    bmsg_lens = [len(msg[0]) for msg in bmsgs]#+ [0]*bzero
    print("now")
    #set_trace()

    fg = plt.figure()#figure()
    ax = fg.gca()
    bar1 = ax.barh([0,1,2,3,4,5], ngcounts, height=0.4, label ="conforming") #, align='center' , width=0.4
    bar2 = ax.barh([i+0.4 for i in range(6)],nbcounts, height=0.4, align='center', label ="nonconforming")# , align='center' #, width=0.4,
   
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_ylabel("Message Hit Count")
    ax.set_xlabel("Message Probability")
    ax.set_xlim(right= 1.15)
    #plt.xlim(right=0.24, left=0.1)
    for p in bar1:
        width = p.get_width()
        if width == 0:
            continue
        ax.annotate('{}'.format(round(width,2)),
                    xy=(p.get_width()+ 0.05, p.get_y() + width/ 4),
                    xytext=(0, 4), # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
    i = 0    
    for p in bar2:
        width = p.get_width()
        if width == 0:
            continue
        if i == 1:
            ax.annotate('{}'.format(round(width,5)),
                    xy=(p.get_width()+ 0.058, p.get_y() + width/ 4),
                    xytext=(0, 4), # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
        else:
            ax.annotate('{}'.format(round(width,5)),
                    xy=(p.get_width()+ 0.058, p.get_y() + width/ 4-0.2),
                    xytext=(0, 4), # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

        i+=1
   
    plt.legend()
    fg.show()
    set_trace()

   