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


