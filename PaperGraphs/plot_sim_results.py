



from pdb import set_trace
import matplotlib
from matplotlib import pyplot as plt
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['pdf.fonttype'] = 42
import os

import numpy as np

simulation_folder = "g:\\clone4\\FlushAndReloadForWin\\michalinthemiddle\\simulation_under16k_full"
simulation_folder = "simulation_under16k_fulllimit10k" #"g:\\clone4\\FlushAndReloadForWin\\michalinthemiddle\\simulation_under16k_fulllimit10k"
sim_info = []

def get_success_count_under():
    success_under = []
    for msg in sim_info:
        perfectoracle = int(msg[1])
        locc = msg[4].find('(')
        oural = int(msg[4][:locc].strip())
        locc = msg[15].find('(')
        doubleal = int(msg[15][:locc].strip())
        locc = msg[22].find('(')
        majal = int(msg[22][:locc].strip())
        success_under.append((perfectoracle, oural, doubleal, majal))
    return success_under

#Extract amount of external queries for each algorithm and perfect oracle

if __name__ == "__main__":
    import seaborn as sns
    sim_files = os.listdir(simulation_folder)
    for simfile in sim_files:


        csim_lines = open(simulation_folder+'\\'+simfile, 'r').readlines()
    
        for line in csim_lines[1:]:#[:50]:
            if ',' not in line:
                continue
            sim_info.append(line.strip().split(','))#eval('('+line.strip().strip(',').replace(',,',',').replace('TRUE', 'True').replace('FALSE', 'False')+')'))

    maxmsgs = len(sim_info)*1.0#196.0#1760.0#760.0#3191.0
    print('Success rate for our algorithm: %f' %([msg[3] for msg in sim_info].count('TRUE')/maxmsgs, ))
    print('Success rate for double unanimous algorithm: %f' %([msg[14] for msg in sim_info].count('TRUE')/maxmsgs, ))
    print('Success rate for majority algorithm: %f' %([msg[21] for msg in sim_info].count('TRUE')/maxmsgs, ))

    success_under = get_success_count_under()

    table_header = range(6500,30000,500)
    sperfect = [len([val[0] for val in success_under if val[0]<=coo]) for coo in table_header]
    sour = [len([val[1] for val in success_under if val[1]<=coo]) for coo in range(6500,30000,500)]
    sdal = [len([val[2] for val in success_under if val[2]<=coo]) for coo in range(6500,30000,500)]
    smaj = [len([val[3] for val in success_under if val[3]<=coo]) for coo in range(6500,30000,500)]

    vaaaa = len([val[1] for val in success_under if val[1]<=10000])
    table_header2 = range(6500,30000,500)# np.linspace(6500,31000,20)
    sour2 = [len([val[1] for val in success_under if val[1]<=coo])/maxmsgs for coo in table_header2]
    sdal2 = [len([val[2] for val in success_under if val[2]<=coo])/maxmsgs for coo in table_header2]
    smaj2 = [len([val[3] for val in success_under if val[3]<=coo])/maxmsgs for coo in table_header2]
    sperfect2 = [len([val[0] for val in success_under if val[0]<=coo])/maxmsgs for coo in table_header2]
    

    table_header3 = [i for i in range(6500,20000,500)]+[i for i in range(20000,30000,1000)]
    sperfect3 = [len([val[0] for val in success_under if val[0]<=coo]) for coo in table_header3]
    sour3 = [len([val[1] for val in success_under if val[1]<=coo]) for coo in table_header3]
    sdal3 = [len([val[2] for val in success_under if val[2]<=coo]) for coo in table_header3]
    smaj3 = [len([val[3] for val in success_under if val[3]<=coo]) for coo in table_header3]

    
    print('Query limit\t\t'+str(table_header3))
    print('Msg count for perfect\t' + str(sperfect3))
    print('Msg count for Ours\t' + str(sour3))
    print('Msg count for Double\t' + str(sdal3))
    print('Msg count for Majority\t' + str(smaj3))
 
    #set_trace()
    sns.set()



    plt.plot([i for i in table_header2], sperfect2, label='Perfect')
    plt.plot([i for i in table_header2], sour2, label='Traceback')
    plt.plot( [i for i in table_header2], sdal2, label='Double')
    plt.plot([i for i in table_header2], smaj2, label='Majority')
    plt.xlabel("Number of Queries", fontsize=18)
    plt.ylabel("Attack Success Rate", fontsize=18)
    #plt.xticks([(10000, "10k"),(20000, "20k"),(30000, "30k")],fontsize=18)
    #plt.xticks(labels=["$1x10^4$","$2x10^4$","$3x10^4$"],fontsize=18)
    #vaaa = plt.xticks(fontsize=18)
    #vaaa[1][0].set_text('1x10^4')
    plt.xscale('log')
    plt.xticks([10000,16000, 20000,30000], labels=['$1\cdot 10^4$','$1.6\cdot 10^4$','$2\cdot 10^4$','$3\cdot10^4$'],fontsize=16)
    plt.yticks(fontsize=13)

    plt.legend(prop={'size':17})
    plt.show()
    set_trace()



