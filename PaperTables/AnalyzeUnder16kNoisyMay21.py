from pdb import set_trace
import numpy as np
import os
# NOISY_RES = [
#     #"Mon May 13 11_32_29 2024_noisy_simulation_comparison.csv",
#     "Sun May 12 22_17_55 2024_noisy_simulation_comparison.csv",
#              "Sun May 12 23_04_53 2024_noisy_simulation_comparison.csv",
#              "Sun May 12 23_05_50 2024_noisy_simulation_comparison.csv",
#              "Sun May 12 23_05_19 2024_noisy_simulation_comparison.csv",
#              "Sun May 12 23_33_23 2024_noisy_simulation_comparison.csv",
#              "Sun May 12 23_33_58 2024_noisy_simulation_comparison.csv",
#              "Mon May 13 11_32_34 2024_noisy_simulation_comparison.csv",
             
#              "Mon May 13 11_32_41 2024_noisy_simulation_comparison.csv",
#              "Mon May 13 11_32_49 2024_noisy_simulation_comparison.csv",

             
#              ]

TOTALLEN= 39801#8688

success_trios = []
msgtrios = {}
avgmsgtrios = []

#How many can finish in under 16k
#portion that has firstmultiplier
#getaverage

def analyze_file(file_lines):
    #set_trace()len(
    llen = len(file_lines)
    current_attaqandqth = []
    amountofmsgs = 0
    #set_trace()
    for mline in range(llen):
        if 'queries and first multiplier at' in file_lines[mline]:
        #if 'Found fast message' in file_lines[mline]:
            attackq, fm = [int(val) for val in file_lines[mline].split('queries and first multiplier at')]
            current_attaqandqth.append((attackq, fm))
        if 'Per:' in file_lines[mline]:
            amountofmsgs = int(file_lines[mline].split(':')[1])
    return current_attaqandqth, amountofmsgs
    #set_trace()

        #line = mline.split(',')

"""
def analyze_file(file_lines):
    #set_trace()
    for mline in file_lines:
        line = mline.split(',')
        msg = line[0]
        perfq = int(line[1])
        succ = line[3]
        extq = line[4]
        extq2 = int(extq.split('(')[0].strip())
        firstmul = int(line[10])
        if succ=='True':
            success_trios.append((msg, perfq, extq2, firstmul))
            if msg in msgtrios:
                msgtrios[msg] = [(perfq, extq2, firstmul)]+ msgtrios[msg]
            else:
                msgtrios[msg] = [(perfq, extq2, firstmul)]

"""
def analyze_file2(file_lines):
    #set_trace()
    below5k  = []
    for mline in file_lines:
        if ',' not in mline:
            continue
        line = mline.split(',')
        msg = line[0]
        if line[1] == '':
            continue
        perfq = int(line[1])
        #succ = line[3]
        ourq = int(line[2])
        firstmulreal = int(line[3])
        
        extq = line[4]
        firstmul = int(extq.split(')')[0].strip())
        if firstmulreal < 5000:
            below5k.append((msg, perfq, firstmulreal, firstmul))

    return below5k
        # = int(line[4])
        # if succ=='True':
        #     success_trios.append((msg, perfq, extq2, firstmul))
        #     if msg in msgtrios:
        #         msgtrios[msg] = [(perfq, extq2, firstmul)]+ msgtrios[msg]
        #     else:
        #         msgtrios[msg] = [(perfq, extq2, firstmul)]


if __name__ == '__main__':
    #allstats = open("outputtryallfirstmulover30ktoo.csv", 'r').readlines()
    #allmorefirstmuls = open("outputtryallfirstmulover40ktoomore.csv", 'r').readlines()
    #set_trace()

    #below5k = analyze_file2(allmorefirstmuls)
    #set_trace()
    NOISY_RES = os.listdir("simulated_experimentMay21_f//")
    attq_qth_pairs = []
    allmsgcounts = 0
    for noisyres in NOISY_RES:#[:7]+:#[:2]:
        lines = open("simulated_experimentMay21_f//"+noisyres, 'r').readlines()
        pairs, msgcount = analyze_file(lines[1:]) 
        allmsgcounts+= msgcount
        attq_qth_pairs+= pairs#analyze_file(lines[1:])
    set_trace()
    filtered = [val for val in attq_qth_pairs if val[0]-val[1]<=1000]
    not_filtered = [val for val in attq_qth_pairs if val[0]-val[1]>1000]
    fast = [val for val in not_filtered if val[0]<= 16000]
    slow = [val for val in not_filtered if val[0]> 16000]


    #fast = [val for val in attq_qth_pairs if val[0]>=5000]
    #fast = [val for val in attq_qth_pairs if val[0]>=5000 and val[0]<=17000]
    #slow = [val for val in attq_qth_pairs if val[0]<5000]

    # for msg in msgtrios:
    #     extq = [val[1] for val in msgtrios[msg]]
    #     avgext = int(np.average(extq))
    #     avgmsgtrios.append((msg, avgext, msgtrios[msg][0][2]))

    # set_trace()
    # firstmulbelow3k = [val for val in avgmsgtrios if val[2]<=3000]
    # firstmulbelow3kbuthigh = [val for val in avgmsgtrios if val[2]<=3000 and val[1]>=16000]
    # firstmulbelow600 = [val for val in avgmsgtrios if val[2]<=600]
    # firstmulbelow600buthigh = [val for val in avgmsgtrios if val[2]<=600 and val[1]>=16000]
    # alltrios = [msgtrios[val] for val in msgtrios]
    # set_trace()
    delim =' & '
    alln = 39801
    #experimentcount = #4#5#5#10
    totalruns = allmsgcounts*1.0#experimentcount*alln*1.0
    #print("qth  | p_fast(qth) | p_slow(qth) | Pr(fast|qth) | n_msgs ")
    print("qth  | p_fast(qth) | p_slow(qth) | Avgq | n_msgs |Tq \n")
    table1 = ""
    table2 = ""
    for qth in [200,300, 400, 500, 600, 700, 1000,2000, 3000, 16000]:
        fastqth = [val for val in fast if val[1]<=qth]
        slowqth = [val for val in slow if val[1]<=qth]
        avgq = int(np.average([val[0] for val in fastqth]))
        #underqth = []
        #to_add = 0
        # for val in alltrios:
        #     for subval in val:
        #         if subval[2] <= qth:
        #             underqth.append(subval)
        #     to_add += (9-len(val))
        #underqthfast = [val for val in underqth if val[1]<=16000]
        #underqthslow = [val for val in underqth if val[1]>16000]
        fastp = len(fastqth)/totalruns
        #avgq = np.average([val[1] for val in underqthfast])#+[16000]*to_add)
        #print(avgq)
        slowp = len(slowqth)/totalruns#(len(underqth)-len(underqthfast))/360000.0
        #under16k = [val for val in avgmsgtrios if val[1]<=16000]
        #under16kqth = [val for val in avgmsgtrios if val[1]<=16000 and val[2]<=i]
        #over16k = [val for val in avgmsgtrios if val[1]>16000]
        #over16kqth = [val for val in avgmsgtrios if val[1]>16000 and val[2]<=i]
        #fastp = len(under16kqth)/alln
        #slow16allqth = [val for val in below5k if val[2]<=i and val[1]>=16000]
        #s16allqth = [val for val in below5k if val[2]<=i ]
        #set_trace()
        #slowp = (len(slow16allqth)-len(under16kqth))/alln#len(over16kqth)/alln
        nmsgs = 1/(fastp)# *(1-0.07))
        #avgq = int(np.average([val[1] for val in under16kqth]))
        #table1 +="%d %s %.04f %s %.04f %s %.02f %s %.00f  \\\\\n" %(qth, delim, fastp, delim, slowp,  delim, fastp/(fastp+slowp), delim, nmsgs, )
        #perrormsgbiggerthanqth = (1-fastp-slowp)#/(1-fastp)
        #perrormsglowerthanqth = slowp#/(1-fastp)

        Tq = nmsgs*(avgq*fastp + 16000*slowp+ qth*(1-fastp-slowp))
        #ETq_qth = (nmsgs-1)*qth*perrormsgbiggerthanqth+(nmsgs-1)* perrormsglowerthanqth*16000
        #ETq_qth = (nmsgs-1)*qth+(nmsgs-1)* perrormsglowerthanqth*16000
        #ETq_qthfull = ETq_qth + avgq #+ average  
        table1 +="%d %s %0.3f %s %0.4f %s %d %s %d %s %d \\\\\n" %(qth, delim, fastp, delim, slowp, delim, avgq, delim, nmsgs, delim, Tq, )
        #table2 += "%d %s %.04f %s %.04f %s %d %s %.01f\\\\\n" %(qth, delim, perrormsgbiggerthanqth, delim, perrormsglowerthanqth, delim, ETq_qthfull, delim, ETq_qthfull/1600, )
        

    print(table1)

    #print("qth  | p_higherthanqth | p_slowlowerthanqth | E(Tq(qth)) | Attack Time[hours]")#Pr(fast|qth) | n_msgs ")
    #print(table2)
    
