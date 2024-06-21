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

## Attack Threat Model

Our threat model, shown in ![Threat Model](figure1_kerbattack.pdf), assumes a network with honest servers and
an honest user trying to log in using an uncompromised smartcard and client machine. A malicious MiTM is able to intercept and modify packets over the network and to communicate
with an unprivileged malicious program running on the Client.



## Dependencies

Several python libraries and tools are used including:
> pyasn1  
> pydivert  
> numpy  
> matplotlib  
> pycryptodome  
> pyconsol_ctrl  

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




