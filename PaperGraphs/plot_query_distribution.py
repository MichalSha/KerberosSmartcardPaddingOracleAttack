
from pdb import set_trace
import numpy as np
import matplotlib
from matplotlib import pyplot as plt
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['pdf.fonttype'] = 42
import seaborn as sns

def add_tophist(phist, qbetween):
    vals = set(qbetween)
    for val in vals:
        if val in phist:
            phist[val]+=qbetween.count(val)
        else:
            phist[val]=qbetween.count(val)


def Normalized(phist):
    newphist = {}
    allcounts = sum(phist.values())
    for val in phist.keys():
        #set_trace()
        newphist[val] = phist[val]/allcounts #set_trace()
    return newphist

def CombineBinsAndNormalize(phist):
    newphist = {}
    allcounts = sum(phist.values())
    #set_trace()
    for val in range(0, max(phist.keys()),10):
        new_val = 0 
        for v in [val+i for i in range(10)]:
            if v in phist:
                new_val += phist[v]
        newphist[val] = new_val/allcounts
    return newphist

if __name__ == '__main__':

    list30k = "Wed Feb  7 20_35_37 2024_simulation_perfectoracle30k.csv"
    list10k = "Wed Feb  7 20_35_37 2024_simulation_perfectoracle10k.csv"
    
    #"msg, simq count, first mul, qbetweenpositives

    lines10 = open(list10k, 'r').readlines()

    lines30 = open(list30k, 'r').readlines()

    cphist10 = {}
    cphist30 = {}
    cphist30only = {}



    curr = 0
    for line in lines10[1:]:#[:5]:
        #set_trace()
        curr +=1
        if curr%100 == 0:
            print(curr)
        #(msg, simq, fmul, qbetweenpositives) = line.split()
        qpos = line.strip('\n]').split('[')[-1]
        qbetween = eval ('['+qpos+']')
        #set_trace()
        add_tophist(cphist10, qbetween[1:])

    for line in lines30[1:]:#[:5]:
        curr +=1
        if curr%100 == 0:
            print(curr)
        #set_trace()
        #(msg, simq, fmul, qbetweenpositives) = line.split()
        qpos = line.strip('\n]').split('[')[-1]
        qbetween = eval ('['+qpos+']')
        # add_tophist(cphist30, qbetween[1:])
        # if line not in lines10:
        #     add_tophist(cphist30only,qbetween[1:])
        if line not in lines10:
            add_tophist(cphist30, qbetween[1:])
        #add_tophist(cphist30only,qbetween[1:])
        

    #normalized
    phist10 = CombineBinsAndNormalize(cphist10)
    phist30 = CombineBinsAndNormalize(cphist30)
    #phist30only = CombineBinsAndNormalize(cphist30only)

    nphist10 = Normalized(cphist10)
    nphist30 = Normalized(cphist30)
    #nphist30only = Normalized(cphist30only)

 
    set_trace()


    sns.set()
    plt.ylabel("Potential Positive Count")
    plt.xlabel("Amount of Queries between Potential Positives")
    #plt.xlim(-0.1,25)#max(phist10.keys())+1) #left=
    plt.ylim(0,max(nphist10.values())+10) #left=
    plt.yscale('log')
    #ax2 = plt.subplot(1, 2, 2)
    #ax2.set_title("Under 30k")
    plt.bar([i+0.5 for i in nphist30.keys()], nphist30.values(),label="Between 10k and 30k", width=0.20,edgecolor='b')#'orange')
    plt.bar(nphist10.keys(), nphist10.values(), label="Under 10k", width=0.22,edgecolor='orange',color='orange')#'b')
    plt.ylabel("Fraction of Positive Queries", fontsize=17)
    plt.xlabel("Number of Queries Between Positive Queries", fontsize=17)
    plt.xlim(-0.1,200)    
    #plt.xlim(-0.1,30)#max(phist30.keys())+1) #left=
    plt.yscale('log')
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.ylim(0,max(nphist30.values())+5) #left=
    plt.legend(prop={'size':17})
    #plt.legend()
    plt.show()

   


    set_trace()

    #plt.show()



