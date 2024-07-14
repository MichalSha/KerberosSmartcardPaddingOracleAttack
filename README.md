# KerberosSmartcardPaddingOracleAttack


The Kerberos protocol is used by millions of users and net-
work administrators worldwide for secure authentication, key
distribution, and access control management to enterprise networks and services. Since its initial public deployment in
1989, the protocol has undergone many revisions to incorporate new cryptographic primitives and improve security.
For example, initially based solely on users’ passwords and
symmetric cryptographic primitives, current implementations
also support smartcard-based authentication with asymmetric cryptographic primitives for improved security. However,
this iterative revision process has resulted in implementations
riddled with legacy crypto primitives and protocol designs.
In this work, we show how we can exploit this legacy crypto
to completely break the security of the enterprise network.
Firstly, while arguably more secure, smartcard-based authentication uses RSA encryption with the notorious PKCS #1 v1.5
padding scheme. Although the RSA decryption is done securely inside the smartcard, a non-constant time unpadding
code runs on the client’s CPU. This makes both Windows’s
and several Linux distributions’ implementations vulnerable
to the Bleichenbacher attack that can recover cryptographic
session tokens. Secondly, we show that the RSA smartcard based authentication does not provide forward secrecy to the
cryptographic tokens that the server provisions to the client.
Thirdly, we propose and analyze different algorithmic approaches to minimize the overhead required to handle noisy
oracles in the Bleichenbacher attack. This general Bleichenbacher attack analysis may be of independent interest.
Finally, we demonstrate microarchitectural side channel-
based end-to-end attacks on the Windows Kerberos implementation. We start by showing how to recover tokens used
to encrypt session transferred remote files by Samba. We then
show how to amplify the number of decryptions performed
with a single user’s PIN code input, allowing us to accelerate
our attack and recover users’ (and admins’) credentials before
expiration. In addition, we describe a remote attack vector
that allows us to perform the attack and generate queries.


We provide attack evaluation artifacts offering access to a network setup of our attack model, code implementing both the client side native attack code and the malicious machine-in-the-middle attacker code for our end-to-end-attack, a detailed tutorial on how to use the attack code and tools provided, code for classification and detection of messages, data from experiments performed and code generating the graphs shown in the paper. The code we provide for packet modification can additionally be utilized as a tool enhancing network security analysis.


> The paper can be found at:
https://eprint.iacr.org/2024/xxxxx

> Note: this link will be updated once the embargo has lifted.

## Attack Threat Model

Our threat model, shown in ![Threat Model](figure1_kerbattack.pdf), assumes a network with honest servers and
an honest user trying to log in using an uncompromised smartcard and client machine. A malicious MiTM is able to intercept and modify packets over the network and to communicate
with an unprivileged malicious program running on the Client.



## Tutorial On the Live Setup

Basic test: Check that Kerberos Smartcard authentication/login is working properly.
Run network tracing tool on the Client and perform a Smartcard login. Apply packet filter "kerberos.msg_type ==11". If no packets are found, the smartcard
network login isn’t being performed. This can happen when
the Client has a network issue and uses the cached credentials
to perform the local login.


For both of the experiments (E1) and (E2), bleich_client will run on the Client machine. 
On the live setup, this will be done by logging into the Client as user "cryptobob" with password "eval1!" and running:
```
python C:\studies\third_clone\FlushAndReloadForWin\michalinthemiddle\bleich_client.py --monitor_port 1960 --with_val T --is_verbose T 
```


(E1) End-to-End attack on a known "fast" message
> Note: there is an option to use a simulator of a perfect oracle for part of the End-to-End attack  

```
python F:\clone4\FlushAndReload\michalinthemiddle\bleich_meddler.py --monitor_port 1960 --is_verbose T --with_val T -at full -sb 30 -eb 36 -b135 T -b389 T -dt 0.4
```



(E2) Detection and Early Abort attack


```
python F:\clone4\FlushAndReload\michalinthemiddle\bleich_detector.py --monitor_port 1960 --is_verbose T --with_val T -at full -sb 30 -eb 36 -b135 T -b389 T -dt 0.4
```

After running the following line - press continue allowing the MiTM to connect to the Client malicious code and start performing the detection of Fast messages and the full attack. 
Continuous output including the detection of the authentication packets and the results sent by the monitor is printed. After each message, the current state is also printed and written to the output file.
 
The output file will contain current state updates similar to the one below:  
"current state: 52 not fast, fast 1, fp 10"

The interpretation of the line above is that 63 messages were checked. 62 of the messages weren't fast and one message was fast and the attack was performed on it. In 10 cases, there was an initial false positive in the first multiplier and after repetition of this query, the messages were found to be false positives.

The attack can take several hours and in some cases the computers can go to sleep. 


## Dependencies

Several python libraries and tools are used including:
> pyasn1  
> pydivert  
> numpy  
> matplotlib  
> pycryptodome  
> consol_ctrl  

Tools:  
> windivert  
> tshark  



## Flush Reload Monitor

A tool to implement Flush and Reload cache attack on Windows. Uses memaccesstime from the Mastik repository (https://github.com/0xADE1A1DE/Mastik/)
The targets can be either a dll or an exe.  
> Note, the dll must be the same dll used by an executable - this may not work based on deduplication.  Works on both Native and VMs.

Steps:

> Identify target binaries and offsets. 
> Identify the delta threshold - cache L3 upper bound in cycles for memaccess time 
> Compile and run the monitor 

Can monitor between 1 and 3 target binary files each at a given offset.  The output is buffered and output to a file every few seconds. 


Compiles with codeblocks:
```
"C:\Program Files\CodeBlocks\MinGW\bin\gcc" flush_reload_monitor.c -o flush_reload_monitor.exe

```

Usage: 
```
flush_reload_monitor.exe [arguments]
argument list:
    --target1 [target1 path]
    --target2 [target2 path]
    --target3 [target3 path]
    --offset1 [offset1]
    --offset2 [offset2]
    --offset3 [offset3]
	--addrcount [addrcount]
Additional optional arguments:
    --output [output_file_path]
    --probe_time [probe_time]
    --flush_interval [flush_interval]
    --program_length [program_length in seconds]
    --delta [delta threshold]
```

---

## Bleich Client

Rus the native code that monitors the cache on the Client and connects to the MiTM.


The malicious code running on the client. 
The client malicious code returns the number of hits for each attempt. Up to 3 addresses can be monitored. 



Requires: 
tshark
python package console_ctrl
```
pip install console_ctrl
```

Usage:

```
bleich_client.py [-h] [-ug USE_GUI] [-p USE_PIV_TOOL] [-c COUNT]
                        [-mp {..\flush_reload_monitor.exe}] [-a ADDRCOUNT]
                        [--monitor_ip MONITOR_IP] [--monitor_port MONITOR_PORT] [-b1 FIRST_BIN] [-o1 FIRST_OFFSET]
                        [-b2 SECOND_BIN] [-o2 SECOND_OFFSET] [-b3 THIRD_BIN] [-o3 THIRD_OFFSET] [-fi FLUSH_INTERVAL]
                        [-ml MONITOR_LENGTH] [-pt PROBE_TIME] [-d DELTA] [--is_verbose IS_VERBOSE]
                        [--with_val WITH_VAL] [--on_win11 ON_WIN11]


optional arguments:
  -h, --help            show this help message and exit
  -ug USE_GUI, --use_gui USE_GUI
  -p USE_PIV_TOOL, --use_piv-tool USE_PIV_TOOL
  -c COUNT, --count COUNT
  -mp {..\frwindb.exe,..\frwindb_double.exe,..\flush_reload_monitor.exe}, --monitor_program {..\frwindb.exe,..\frwindb_double.exe,..\flush_reload_monitor.exe}
  -a ADDRCOUNT, --addrcount ADDRCOUNT
  --monitor_ip MONITOR_IP
  --monitor_port MONITOR_PORT
  -b1 FIRST_BIN, --first_bin FIRST_BIN
  -o1 FIRST_OFFSET, --first_offset FIRST_OFFSET
  -b2 SECOND_BIN, --second_bin SECOND_BIN
  -o2 SECOND_OFFSET, --second_offset SECOND_OFFSET
  -b3 THIRD_BIN, --third_bin THIRD_BIN
  -o3 THIRD_OFFSET, --third_offset THIRD_OFFSET
  -fi FLUSH_INTERVAL, --flush_interval FLUSH_INTERVAL
  -ml MONITOR_LENGTH, --monitor_length MONITOR_LENGTH
  -pt PROBE_TIME, --probe_time PROBE_TIME
  -d DELTA, --delta DELTA
  --is_verbose IS_VERBOSE
  --with_val WITH_VAL
  --on_win11 ON_WIN11
```


## Graphs

The code and data for the graphs shown in the paper can be found under the PaperGraphs folder. Note the data files need to be extracted.

In order to generate Figure 2:

```
python check_calibration.py 
```

In order to generate Figure 3:

```
python plot_query_distribution.py 
```


In order to generate Figure 4:

```
python plot_sim_results.py 
```


## Tables

The code and data for the tables shown in the paper can be found under the PaperTables folder. Note the data files need to be extracted.

In order to generate Table 5:

```
python AnalyzeUnder16kNoisyMay21.py
```

Tables 6 and 7 were generated manually from the experiment files under the PaperExperiment\\DetectAndEarlyAbort.7z and the PaperExperiment\\KnownMessageAttacks.7z respectively.


## Remote Vector Sites

Examples of loading remote files and generating queries consistently using the browsers can be found here.




