import random
import Crypto  #Crypto on py2
from Crypto.PublicKey import RSA

from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP, DES3
from Crypto.Util.number import bytes_to_long, long_to_bytes


bladecoded_privatekey1 = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsJhjro9n0Hz8nqSjJQstbR1gq5OW5XEX9melI3fVnYMKcpKj
1umZhkEAEtECb7bfQAcCAr/5SeZc+w8KTn5Uexm6+eieNO8C9wEa4EV5/bmuBave
e0yeiaf5LLSxoB67R8bFXSXbc73/XAL4HLWBwzxcklSL/FuTFssRdkUwz+qY2JFd
tf/TEsWlxeJIhX9gvsx3iwkcF/xvM/5mOY2jSiIYAMzhpAI9oBswYwKMl69y5aec
Z2aD6+mH48GzDf8ZqPhUo68zx9FLMldTvSeKvbeK9SDo3+XWLV9piTRAZsPp00xy
eJ34ZRdh9SM9PASjkmcQE+9WTWVzWMdk49UyeQIDAQABAoIBAHYlnhs9alE8La7d
qyCvd7bWvsRLu9rJbSS3du5h0BLPhv/cR60TIFmHx0rPdvfSu04U4i2AzoG4k2CM
UXLuZgrtzgBAtwfnGG602IxPLyynO1wj/nczbaXfMX/NbEEaDmYZABYvq8ClzuB6
RBDBBo3eJnjoA7fUdHX9ajNcWyneRo3lZ1rDsOVfTzQcIXkTQKHtzAq1mOy+/WwP
4RocH3RA4T4v4KB2suvz4CPH0gJuvXn9KQg26bM1iHJkk2tKN3c/SKYNxiLmkt+i
heplYWwMzfQvO4OmFHc7PVdu5hRKbNJ/Ekmuq5wWmynTx9i9cOmrb7DKpUn06BMV
DSFXCrkCgYEA6hX/gRRBtdbQ8MZE2hCcXytyb6AU6WK0YD4afF9zUmmZeWM3JDKX
M0PHCFB5vQhw3i4sVdi4kEhoYIVcxGjCcYqJ3NG0N/wcgAjlXxPYzL5e08EAlQee
yyrDkR2LDvnnW2/ZCaXOgu8olFW9RbXlvWswiyqHGnm4awRzv5IiCUcCgYEAwSCY
WNpt87Qo/ouMEeJVTfwJG51Ecjf2PytvOk7kLsz76W/ipzgiMJaO9mk/8jFX68oj
Vw+YsxwNlhHAJ+ZT9caOUvuAju/F5u3cF7wBx1G3aAO3m5uj12CitVCadZEO2vBl
SYAwOHRR8oItJbpJfOlVUNd1EQa6RjsBATd4xj8CgYEAzDfq01qvxQsm95eRw8jQ
EzsdOAMpmz6wbHJhuvWu70wPR9Zl6d91B5Vu03MZ8e+mQD96EF7lDYMOBH70oqle
UZ3yjkIo/tqkppKcQSlYb675nbV4Y4vlXgvt1/E1OxiMXbojWAZeNt6cwWRXnrSF
PI6CKDcu7MsaN8sHjC7aIMsCgYEAnlxG8Bz0KfCh6M+upH+N6WtwYHddx7bBsdzA
0PQdwY6ORkVbejjaODNMuRtmtwblDFBtGBeO49duAI8/nLgOQqt0yvC14v8TrR9/
6OpeHv2PwbfCl9NQzuvLn5efgCXZI4gZ1eJKKBChnZRGxvfxCH8gWTDDKpn0pl/9
m+zLmOsCgYACipzf+Wrf+sLSCsTxXTr9Ms9QvIchxIwTBI0VfP1FuMM+Bn7gEYeH
UaYURU5+VnFGRLC5xdWpm2/SP0ifLIsaWr2EzaMmMAu1WjsiGiQBd4tP1GemPxby
lnHr3MofiX4k2XeyNL2fhcyHzUfYwMk+ZVt/r8ehLjhS3Sckfuk20g==
-----END RSA PRIVATE KEY-----"""

bladecoded_privatekey2 = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7zU7+DnY9yIrm
4nYzuMrRMTVhwjHHYkvw2X3lLxt9G6MnJndQoO7wfkJiauXSX9cP9sZFayOV2DLa
93Ug93pmaTi+37b3wMR1r23GNyG6XYhxRaOhtGCvUtojCH1J4M1lAFeNjQ9Qm8V/
8yvPcvxKuvJ1J0AZPzBKjj5UcI6BdqM1RAT06ge3TwavxomV0xwecch8/8UMNDG5
xSWbkTSm1GRL5+LQR0w1d+kHfu+7eMCuMS+SQHX8GSwF277VWSL5PW33sOfOK7tm
TMZE6jGsORcvO07wrEVKMY0eLlhit8EHDOxPoC4N60uYbgIQsY/xXTkNNeuA8RC3
RIRD43Y9AgMBAAECggEASeXTu2x9YnpTDd72nAuO4xn1423CoK4xK6ipPVF4A5ao
cHNWZ8ervb4w6QEfRdSoj4OPKSmrav8To83TrRE0fK/SwGjPWlXj+Fr7Ww++mdLM
KaY5aRvNH6/+XeKtSjDHIYMs8GodKJ7i7CIHjy2z0MQXO7oiIs0Wd3/ZTuirao1T
wRg8cO6axSNVdeVKf+cjjBytkmou5pzSO2mxAB6arHEj1QpfYEl6Qvc+n847qPqW
KYEZYHtKfzX6vb5ehUd2VD1jlfwRmnelXRmKLUIx2DDf40xIW1JvIfkRXdfsO7rt
RPmxBvhNCWgl91V1S8nZXeeKXejHzK3yJMR0mH2uEQKBgQDd4tqZkllwiFrUorIg
aUk17y5weD9SuPSsjV0XQ54Yqk6ZuBFj/sHbB10vO7xY5f6d1wBC/rJ4/sg+x8eo
5Jcq82fcGZNuqNaJ7teIpavd1DyhCiL+Kjc3dToBZ1u8AoQLKs7TPTldulCFZ0iX
8bP11rwc+lyT3r1r/Im1HVCqEwKBgQDYrPJwGUXIbKPMyFEzUUrZAkVugKT0j5Fj
+ZSa0FlzJ+LTSqxSKOk0OSsHtpZHqcaLJ1R5aAcRu29nROW0JGYMPMD2frME5OnS
y19ohN+XmixFBh7pGbzctWWVkpiJW+HSXzYOlRGZeOswnZhxiL4YxrdsT1VVrGOz
yqqsjiZobwKBgFxeHYYkqFrySG2QNPrNGY78PKbRR/sVx7U1O/V9TokSDJptR8AK
w4R8ckxBX8zaIb5vTEqXYJCB77ZC0Fj8n/lfTnMPqpI8cuMErHDUFtHHkl2vrJWF
2WqawETpVATWP0Wu0l6ZdBISh4ahUlT+Z14FwFWH25Yq+UvE20asJ3JFAoGBAIFf
ioZqYKNSUt9kQC+u+0zlsUVQpK2tx3b1P8jMXIyIpUPZ01hfOxdGhy3c1JBHi9fs
jODMv2PUEamMlsbf8Nqfr+u+LO/gKskFS5thswuXL5WrGOu/xWfXG6eaV1+0r/pn
hSRh15dWfr+RacNojXDHvh96ow47l3Bzs0LCwaYbAoGATXv4g7LWY5taAelBlzP4
6xfZi+ljAIsEungUGFzScJF7q92MAYjPsVqI+xelFkZ7yNys820STP5bqVCYX5NK
dvPPLuF2hkOGRF9PCfSSt6mOqacjS4KpK6OihDvgHZdgaSAvVzXStThmTb4lebn9
HD1t3IY+tW/9ko5eEwiuK1Q=
-----END PRIVATE KEY-----"""


bladecoded_privatekey3 = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu81O/g52PciK5uJ2M7jK0TE1YcIxx2JL8Nl95S8bfRujJyZ3
UKDu8H5CYmrl0l/XD/bGRWsjldgy2vd1IPd6Zmk4vt+298DEda9txjchul2IcUWj
obRgr1LaIwh9SeDNZQBXjY0PUJvFf/Mrz3L8SrrydSdAGT8wSo4+VHCOgXajNUQE
9OoHt08Gr8aJldMcHnHIfP/FDDQxucUlm5E0ptRkS+fi0EdMNXfpB37vu3jArjEv
kkB1/BksBdu+1Vki+T1t97Dnziu7ZkzGROoxrDkXLztO8KxFSjGNHi5YYrfBBwzs
T6AuDetLmG4CELGP8V05DTXrgPEQt0SEQ+N2PQIDAQABAoIBAEnl07tsfWJ6Uw3e
9pwLjuMZ9eNtwqCuMSuoqT1ReAOWqHBzVmfHq72+MOkBH0XUqI+Djykpq2r/E6PN
060RNHyv0sBoz1pV4/ha+1sPvpnSzCmmOWkbzR+v/l3irUowxyGDLPBqHSie4uwi
B48ts9DEFzu6IiLNFnd/2U7oq2qNU8EYPHDumsUjVXXlSn/nI4wcrZJqLuac0jtp
sQAemqxxI9UKX2BJekL3Pp/OO6j6limBGWB7Sn81+r2+XoVHdlQ9Y5X8EZp3pV0Z
ii1CMdgw3+NMSFtSbyH5EV3X7Du67UT5sQb4TQloJfdVdUvJ2V3nil3ox8yt8iTE
dJh9rhECgYEA3eLamZJZcIha1KKyIGlJNe8ucHg/Urj0rI1dF0OeGKpOmbgRY/7B
2wddLzu8WOX+ndcAQv6yeP7IPsfHqOSXKvNn3BmTbqjWie7XiKWr3dQ8oQoi/io3
N3U6AWdbvAKECyrO0z05XbpQhWdIl/Gz9da8HPpck969a/yJtR1QqhMCgYEA2Kzy
cBlFyGyjzMhRM1FK2QJFboCk9I+RY/mUmtBZcyfi00qsUijpNDkrB7aWR6nGiydU
eWgHEbtvZ0TltCRmDDzA9n6zBOTp0stfaITfl5osRQYe6Rm83LVllZKYiVvh0l82
DpURmXjrMJ2YcYi+GMa3bE9VVaxjs8qqrI4maG8CgYBcXh2GJKha8khtkDT6zRmO
/Dym0Uf7Fce1NTv1fU6JEgyabUfACsOEfHJMQV/M2iG+b0xKl2CQge+2QtBY/J/5
X05zD6qSPHLjBKxw1BbRx5Jdr6yVhdlqmsBE6VQE1j9FrtJemXQSEoeGoVJU/mde
BcBVh9uWKvlLxNtGrCdyRQKBgQCBX4qGamCjUlLfZEAvrvtM5bFFUKStrcd29T/I
zFyMiKVD2dNYXzsXRoct3NSQR4vX7IzgzL9j1BGpjJbG3/Dan6/rvizv4CrJBUub
YbMLly+Vqxjrv8Vn1xunmldftK/6Z4UkYdeXVn6/kWnDaI1wx74feqMOO5dwc7NC
wsGmGwKBgE17+IOy1mObWgHpQZcz+OsX2YvpYwCLBLp4FBhc0nCRe6vdjAGIz7Fa
iPsXpRZGe8jcrPNtEkz+W6lQmF+TSnbzzy7hdoZDhkRfTwn0krepjqmnI0uCqSuj
ooQ74B2XYGkgL1c10rU4Zk2+JXm5/Rw9bdyGPrVv/ZKOXhMIritU
-----END RSA PRIVATE KEY-----"""

bladecoded_privatekey= bladecoded_privatekey3

BLA_DECODED_PRIVK  = bladecoded_privatekey

lalaencoded_privatekey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwLb6qefZaXFGQQoWqjVHBgKL3gRLDOIPYvTruOFYgCNGq6UW
0qmxnu37qaoQHy4TSscOoKwEtX3wpNQj/w/AwFDQ0FUSd40FNiqAMHWyMku1N7A9
AYmRsBnEHVHGLQgwo2Yk3K5g+0rocYz+X3ayhPX0EhD1dK8KvRTIT4I+GZl2ltqO
UiycChTHPgEWed23TJZmg4yxjYX0ri8fkhsGfKRY96dY7nG/u0H3Ur2Ue2aySbHr
MH6xgR2yzDaQScmOi6JOLnvLQrX24CXvE53MFbMtXYssO6xakepKBxuS80sZS9sj
vgXqyqwmHe+G1I3uWZM/NJxNAAb6+wZjJAI4LQIDAQABAoIBAAj+wXZ6xvAgBGp2
wRYSxIzoQ4UKaEJirtssmXAYvJvGib7rRsRwfUTw0MVblcMO0IG2Bt3DCbk69qeK
6181agbP/t8qiWEhKPQdSbx5Ueb9F6lQxZgzxqQUn83KiliBwFtwIhpW3Vn9Zhoe
vaTREoYYQNszBXH71aF7vdnQN3vUVCp5ptPg9Jq9zeC65ap1oW6dqQ/ZwZ5bo8L+
6PPmyyPyDEhhnrm3mnaavKDhrGCixO0B7NMrdMI9Cp1M4953oI6qOKQoEvW6qGaP
IKBqPW+3NXnl5SelHUVzmnppOXaJzpkYoUMfzHBPm1ExnnbIUQEqlGfACbZmTaCv
a4ooDxUCgYEA0YTG9zf6vS6TsldAy+T95FNLzS9iUFQdImp/bezP61YFN+RmGTcV
RDNxFpqqnRswasI6oCJGqs+OtDecpPyB9e4WQ1jYWdvb3ma2Es+4pAnWFtmgHefc
vJlyXIWb0Y/Chj+4dUHDkQv6mf4U7omTwQ4r7LV6hyFBPMeg8a0x0mMCgYEA63fb
E2rjP1/dFgc9nz5RD/YagW9hEnb7WR2NYulaP/7FRYbrSvxgO75HnGDYsrnpqIqo
mWELwu6qyn+Nr8UpjN/uA8Xt1NbGKsilEfJ6d6MIbAjzQL7okB1il+RxSbxNpaJV
3kqgnobexQxxmIKl1nhg6gbra8kuA+nUuo8IiC8CgYEAhB7VlOnRDOFFM+3/p1PE
oum/4CjkN0GDicNcjgYKax24drFpjLcGixZhVt67fgy6MGhAreBPbcEq/QwglI3C
qkGz+k4ZSDjzYkCkyiIBDjhBr/EWHiWrNacRzbRXOQQNp7ig6hhJabsDEX5+1pkc
+l2kZ0Vdeb8Hs3szS5Nq2n8CgYEAwDeATBKWXbao6QGSKTuautfg/UZpzMP6HN5F
+7eYZ+NXMJGZ5AWvnTWQibR5UTT47A/83/BbxI5GN7X2eMUPTSPDzaq2omeNL4HJ
VqRFmwIoruCDipgNiw+h23KtlE62Z/7j7+mlwqNAmUS2OpR0QmbUXla1ubBp8uHg
OUbn5RsCgYAQNQaj+F1PR2xO9u0vcg31tlWpjMvP1/kOmb5cZqMF2UwZsrGIgfAw
6YeAJ/PlR7ArUB5b+3d4AYt2DX3U/EE6YXO/Iu6VTy+hjTcZS8l8QRZcZqjytELn
sZ9EwQ9Mg1PJM3c8UgGdR8Bvz+T5Plzbsnbd9yBrtQ2PCco5feVnhw==
-----END RSA PRIVATE KEY-----"""





def partial_encrypt(cipher, msg):
    m_int = bytes_to_long(msg)
    e_int= cipher._key._encrypt(m_int)
    return long_to_bytes(e_int)

#rsa_cipher = PKCS1_v1_5.new(RSA.importKey(BLA_DECODED_PRIVK))
    
def create_rsa_cipher(private_key):
    cipher = PKCS1_v1_5.new(RSA.importKey(private_key))
    return cipher
    
    
bla_enc_key = b"\x82\xab\x21\xc6\xe4\x45\xd6\xd0\xc8\x4c\x51\x83\x41\xe9\x38\x39\xf2\x8f\x80\x83\x51\xe6\x91\x77\x62\xc4\x71\x4b\xe3\xd4\xf9\x48\x5e\x0e\x80\x91\x46\x84\x78\x57\xce\x0f\xaa\x6b\x3e\xc3\x93\x19\x61\x14\x18\x21\xcf\x6f\x24\xdc\x35\x53\x9b\x33\x6c\x5d\x4b\xb1\x7b\x30\x0c\x98\xe7\xfd\xfe\xf8\xa8\xff\xee\x7d\x9e\xe3\xf5\xbc\x74\x8b\x70\x31\x8e\xc0\x18\xa0\x3a\x16\x28\xaf\xff\xaf\x78\xaa\x6e\x35\x84\xa6\x79\xd2\xc9\xc7\x3f\xc1\xbe\xe3\xfe\x98\xe8\x2e\xfb\x89\x5c\xef\x3b\x0f\xb0\x1e\xd0\xf0\xac\xd0\xe7\x0c\xa9\x47\xb9\x2e\xd2\x9f\xee\xaf\xd6\x6f\x5b\xe3\xe6\x51\x62\x27\xec\x37\x94\xea\x0d\xdc\xcc\xfa\xe8\x82\x2e\x20\xf7\x98\x5e\x0e\x08\xba\x0a\x59\x06\xfe\xff\x9e\x99\xbd\x2e\x6b\x06\x94\x6a\x18\x96\x25\x78\x38\x5e\x8d\xd9\xde\x77\xf6\xa4\x5d\x24\x40\x68\x60\xef\x95\xec\xd8\xef\xc2\x05\x94\x33\x05\x83\xf0\x6e\x82\xab\x43\xdc\xec\x93\x10\xa6\x1e\xb8\xab\xb3\x1a\x26\x20\x20\x46\x3c\xbd\xfb\x38\x53\x1f\xbe\x13\x39\x77\xfe\xdd\xff\x8e\xaa\x0c\xc1\x34\xff\x0c\x0d\x9c\x88\xb7\x0b\xc0\xf5\x3e\x46\xbb\xe8\x74\x56\x43\xac\x40"
bla_enc_key_modified = b"\x80\xab\x21\xc6\xe4\x45\xd6\xd0\xc9\x4c\x51\x83\x41\xe9\x38\x39\xf2\x8f\x80\x83\x51\xe6\x91\x77\x62\xc4\x71\x4b\xe3\xd4\xf9\x48\x5e\x0e\x80\x91\x46\x84\x78\x57\xce\x0f\xaa\x6b\x3e\xc3\x93\x19\x61\x14\x18\x21\xcf\x6f\x24\xdc\x35\x53\x9b\x33\x6c\x5d\x4b\xb1\x7b\x30\x0c\x98\xe7\xfd\xfe\xf8\xa8\xff\xee\x7d\x9e\xe3\xf5\xbc\x74\x8b\x70\x31\x8e\xc0\x18\xa0\x3a\x16\x28\xaf\xff\xaf\x78\xaa\x6e\x35\x84\xa6\x79\xd2\xc9\xc7\x3f\xc1\xbe\xe3\xfe\x98\xe8\x2e\xfb\x89\x5c\xef\x3b\x0f\xb0\x1e\xd0\xf0\xac\xd0\xe7\x0c\xa9\x47\xb9\x2e\xd2\x9f\xee\xaf\xd6\x6f\x5b\xe3\xe6\x51\x62\x27\xec\x37\x94\xea\x0d\xdc\xcc\xfa\xe8\x82\x2e\x20\xf7\x98\x5e\x0e\x08\xba\x0a\x59\x06\xfe\xff\x9e\x99\xbd\x2e\x6b\x06\x94\x6a\x18\x96\x25\x78\x38\x5e\x8d\xd9\xde\x77\xf6\xa4\x5d\x24\x40\x68\x60\xef\x95\xec\xd8\xef\xc2\x05\x94\x33\x05\x83\xf0\x6e\x82\xab\x43\xdc\xec\x93\x10\xa6\x1e\xb8\xab\xb3\x1a\x26\x20\x20\x46\x3c\xbd\xfb\x38\x53\x1f\xbe\x13\x39\x77\xfe\xdd\xff\x8e\xaa\x0c\xc1\x34\xff\x0c\x0d\x9c\x88\xb7\x0b\xc0\xf5\x3e\x46\xbb\xe8\x74\x56\x43\xac\x40"
#bla_enc_key_nozeros=  "\xbf\xf5\x11\x3a\x8b\x78\x79\x82\x15\x35\x3e\x2d\x52\xc0\x55\x03\x85\xdf\x3f\x2f\x98\x0e\x6a\x80\x14\xcb\xc7\x02\x77\x80\xa0\x07\x70\x4d\x60\xdd\x3a\x9b\xb8\xbc\xff\xe7\x5e\x5d\xca\x52\x5e\x6b\x92\xd2\xfd\x1b\x84\x55\xd9\x62\xa7\x2f\x91\x09\x3a\x62\xca\x2a\x2f\x53\x43\x83\xb6\x82\x23\xcf\xb9\x7c\x59\x48\x13\x0f\x0e\xd9\x18\x87\x52\xe1\x7a\x04\xef\x95\x42\xd7\xe2\xc6\xbe\x88\x53\x3b\x57\xcc\xee\xed\xd6\xdc\x96\x6d\x3f\xde\x5b\xfa\x80\x7a\x94\x8f\x07\xd7\xc9\x0f\xc5\x22\x02\x3b\x70\x00\xb4\x26\x8c\xfe\x25\x56\x52\xe9\xcd\x86\xb1\x6c\x63\x8b\x60\x40\xd6\xaf\x37\x77\x45\x0b\x79\x6a\x4f\x13\xd8\xe4\x74\xf5\xc9\x10\xbb\x2f\x5f\xaf\xe8\x64\x75\x94\x97\x5b\x8c\x47\x47\xc4\x58\x2c\xa2\xc7\xce\x7d\xbd\x0c\x32\xef\xd0\x53\x87\x39\x46\x08\x9d\x83\x5d\xb9\x54\x5f\xcd\xe8\x18\x14\xa5\xff\x53\xb9\x11\x5f\x4d\x49\xbf\x0d\x9f\x81\x53\x20\xe0\xff\xeb\x33\x8a\x35\xa8\x27\xdd\x64\x38\x6f\x13\x30\x78\x6e\xbd\x9a\xb1\x96\x22\x45\x79\xa3\x08\xf5\x86\x01\x80\x84\xb0\x52\x65\xf3\x3a\x27\x3a\x1a\xb4\x41\xf8\xc3\x0f\x03\x35\xd0\x52\xd5"
blaencodedwithpaddingbutnozeros = b'y\'\xcd5\x11yU\xd2\xa0\xb9fQ\xf1\xa0*\xc1t\xa9\x99r\xa8\xc6{r<\x9b\xc86\xd6\xe9`\xe8\x0c\x10\xde\x8dR\x00\r\xdccG\xec\xeb\x1a\x97\xdd\x13\xe3%\x9efM\xd3\xa9\xfaD\xa0\xe3\xaf\xf1\xdcVqR\xb9\x10a\x0f\x977>7\xcb\x92\x81oQ\xb6b\xa5\xd4\x95\x89\x96\xc7\x15\xdd\x10=?\xa1\xe3gzCg\x87\xa5_\xefJ\x14\xf2\xe0\xdd\t\xcag\xd82%w"e0\xba\x90TX\x04\xaf\xc5\xaf\xddg\x0f\xb6X.\x10\xe3 "Qt\xea\xc8\x91E\xe1Q\x82\xca+\x1a\xad\xe0\x06\xe1\x8fF\xa0\x0e{mq~2\xee\x10q\xb9K(\xee\xfb\x83\xff)\n\x9a\xa0\x07\xf7:FRkD;A\x01\xb5\xb2gB2.\xdc\x07\xab\xcf\xd8\xbf\x88\xf3\xd5\nF+\xf2!\xfb\xdbx\xe0%2\xc8l\x8dN\x91\xa1\x13?\x90\xfe8\xbe\xd6\xb7\x1b\x9d\n\xd6\x86i\xed<\xbc\x053\xd6C\x99\x81\xbe:%,\xd8\x07\xc6\x02|\x84\xcc\x0b,\xfe7\x84\xd3P'


bla_enc_good_key = bla_enc_key

enc_no_zero_beginning = b'k\x08~\xc9\xf8\xec0\xb5\x9e\xb0a\xf3"P/\x99I6\xe9\xeeN\x16EH\xf0\x11\xabX\xa9\xad\xc27\xf6\xc1\x18\xfc\xcf\x00\xcd\xcf\xe3\xc1g\xc4\x8c\xc8\xdb09z\x89h\xfa\xb2vM\xebv\xa5\x12\xe9\x13V\xa6\x95\x9c[\x94\xd2E,\x06\xb3\xe7&\xef\xe5\xa2\xd0\xdcniB\x10\xdf\xe3H\x96\xed\xba\xb7s\x912K\xc6\'Uu\x82\x16\x15/\x8f\xb5-\xdd\nd\x95\xf8\xc3\xc8\xc4\xac\xb1..4.\x83\xbc\x85\xef\xb8\x1be\xb3\xf6\x11\xe3\x07cE\xf5\x01t\xf4jlb\xf1\x90\xc76\xb5E\xc9\x1cZ\xe1\nrwG\xe6\xdd\x12\x93\xb6l\xb0\xd6\xfa\xfb\x19\x1b\xcb\xd3\x96\xb7\x92\xa6#j\xe8&\xef\xabT\x02w{\x99\x07\xd8\xc0SN\x80\x1ea\xd4\x9c\x15\xdc\x91\xe8s\x16-`\x9f\xd1_k\xcdY\xe8C\x01\xd0\x91UU\xcb\xb0%\x02\x14\xdc\ntc\xaaj\xab(\xc6\xa9\x0e~\xbee\xea6\xec\x0f \xbe\xe6\'\xcd\x81\x87\x85\xe9\x8a\x93.\x91{Q\xcd\x02\xa4'

#b"\xa4\x85\xbaS\xac\x1a\xc7\xd7\x9f\xff\xd2\xb2\x17\xcc\x9f\xc4\xb8R\xa7\xb4F\x1d9\xfdf\xf6:\xceFA\xf6\x13\xae\xd2\rIbk}b\xe6.\xf8\\+7\xe0B.\xc7\x04\x9c\xc7M3\xdf\x93\xb3\xc7\x9a\xc1N_\x04\t\x05\x8fRI,\x0e\xa5\x87\xf4\xfb\x8f\x03x\xcc\xf8\xc7v:\x97\xdae\xa2\x90\xf3\xc1\x87\xf3vD\n\xc0D~\xd9\x15#\xf1\x9dYi9\x842\x14\x12\x05\x8f\x80\xff\x91\x07-\\HD\xfd\xcb*J\x9e\x8b\x0fj\x99m\xd9\x92\xa9\xfe\xb7\xc5\xfe%\xf6\xfe\x19\r\xfb\n\xfcy\x99'5G\xc8\xe7V\xe8\xb8\xc8O\xf4e\\\xde\n\xe2V\xd7\x8c&\x05Xz\xc8\xa3\xc8;\x05(2.P\xf4\xf4\t\xdfus\xca:\xea\xc0\xe9\x8c \xec\x96L|\xe2\xc9-\x91P<e\x0c5\xc7Js\xd3\xf3\xf3q\x8d\x9c\xd2U\xe0/\xf6\xf3\x99\xbc\x80nH_\xe2\x94,\xae1C\xe0\xb7\x82\x93*^\xd4\x121\xecy1\xfa\xff\xa0O\xb0#PIea\xf4t"
enc_no_02_beginning = b'\x1cr\xe6k\xc8"2I\\s\xc0:\xa9\xfa\xee\x03\xde\x93\x82\xa0\x0bK,d\xc4\xd5\xd7\xc57\x8c/\x89\x1cN\xe1~\xd0\xdaI{M\xea\xf2\xbepRL\x0c\x8f\xfd\xa5"e\xc1\xe5\x1e\x9c\xf1\x07\xf2k\r\xea$\x80\xd3\x12Y\xdfr^\xa1\x17\x07\x96\xd9\xa2\xf40!#b%\xe5\xe6\xce\xc7\x884\x10*p#z\x9e[\xda\xf5d7H\xc9wv{\r\x86\xf4\xc1\xc9ca\xca\x83a\x08!\x9e\xb0=\x8e`\x9fn\xb4Z\xcc<\\\xb7\xdf\x85.\xd6%\xc8\x8fI\xf0\xdf\x8b\xd0\x1b\xa0niC\xbdq\x84x\x95\xf3+\xfeM\x01\xe2\x1f\xae\xba\x11\x92\xae-\xf5Y\xf7p\x1d\x1c@\x13G\x9d\x93\x81\xa6b^\xe7O\xda,\x05\xa1\xa3\xe7\x17\xa6>0\x90\xd2\xba\x12:A\xedW\xbd\x0e\xc6\x9cpu\xbf\x17\xd1\xd3\x92+j\xb2 \x15\xb12\xbe`\x1b\x1c\'\x90Z\x0f\x1c\xbe\x8fZf\x0b\xda\xed\xc0\xe8\xd3\x8dn;\x01\xc3\xf9}2\xf0:\xad\x0b\x06\xe1\rf\xcc$\xb7'
#b'=\x0c_2\xed2\x0e\xdd\xd3\xbf\xddH\x7f`\x97\n,\x03\xac;/U5\xca\xdb\xe9\x87\x14\x97\xfe-\xc7y0\xdf\x0c\x93\xda\xed\x16O\xa8\xbe\x14\xb9!\x03\xeb=\x92\x86\x1b2\t\xb6\xea\xd3>$\xcc\x9d?\xae\xbf\xf5,\xa7\xae{\x1d\x10\xcf\x80\xd6\xc7\x97L\x96\x8f\x1e|\xf5\x97\xb7\xe4%\x8a\xcf\x16\x07\xf4\xee5)2;\x99\x8a\xf03\n\xd9\xbfZ\x87\x90\x12\xd7\xea,\x14h\r\n\xcc\xa0J\xe8\xa8s\xa8\xb9\x9a\xaeM\x01\xd6\x1e\xe1\x99\x1e\x99G\xae\x9a1\x90b\x05\x1c+\xec>\xa1|$o\x80d/\xf6\x05\xd5)\xb2\x88\xcc\x0f\xf4!b+"A\x0cP\x16[\xb7\x84\xc9\x81\x81\xe6F\xc7\xe5\x92\x92\xd7\x04\xfc\xd61\xc3\xf6\xc8M\xba\xc0\x03\x97\xd7c\x86\xb9+\xbf\xb0\x84\x02\x12<\xc3\x93\x13\xda.\xe7\xe3\x8e\x85\xc9\xae\xe4\xc0g\x03\x1e\x12x\x80\xa4>M\x8cp\xb0n\xfb\xfcI\x16\x04\x88y\xd5_\x9e\xc0\x93u\xdb\xbdZb\xc9W(\x96\xcf\xe15\x18\xf2\xb5'

with02_correct = bla_enc_key
with02_nozero = b')7\xc5\x8b\xa01S\x17x\xe68\xc3\x80\x94\x08c\x99\xdbS\n\xe7\xde\x90\xef(\x96\x19\xde\x95\xf7\xcb\x08\xe1\xb4\xda\xf0\xfa"_\xa9I\xe1\xe6\xab\xd0dU\xd5\x8f\x8b\xa9~/\x07n\xfe@+{O0\xe5@\xbd6h0P\x12*.\xd0\xb875\xf6\xfc\x9e\xdb\x8f|s\xa6\n\x81\xd3)\x11"\xa9-\\\x88\x04\x03\x83\xbdFt~\xe2P\n\xb0\x01\xed\xf8\xb05\xc3-d\xba\'.\xc2\x0e\xfa\xce\xa8t\xb3\xfd\x05\xe6\xa3\xf1i\x1ci\xb2\xe5,\xde\xef}\x1c\xb9b\xe6\xa5\x97~>\xc1\xef(voEsT\xaa\x19c\xc4j\xce\xef\xd4=v\xde\x9c\xc5QE\xcc\xc5\x1b\xab\x9a\x14o9\x15D_\x16eK\xd2\x84\xdf\xc2\x95w#\x86\x93Qq\x9a\xcd\x94\x18)\xfe|\x94:MI\xb7S\xb0\xbaPG{\x86\xfe\xbdR\x9b]\x16`\xb4z\xf1\xb8r0\x8fx\xde4\xbc\xceJ\xafE\x95C\x98\xae\xba\x80\xde\xbe\xd2\xd0\x01\x0b\xcey\x91\xf6y\x80\xfe\x15<\xca\x93'
with02_zeroaddbefore = b'\x9a\xa0\xb9\xf5\xbbN$\x91D\xa91 Nv\x06d[\xce\xce+\xbf\xfbI$\x0c\xd0\xcd-g\xe3\x04@\xea0\xd9*\xa9$!GsO\xbc\x15r\xc1\xc0\x8f\'\xb8\xda\x81\xe87\x8f\xf7\t\xd5x\x17\x13\x96.\x97QFEY;\xd6\xd2\xab\x02\x02\xfe\x03\x1ca#p\x1dD\x7f\xa7\xdf\xef\x93\xd99\xa8-\nQ#;\x87X\x07\x18\xbd<\xbe)\x02\xfdP\x05f\xb7\xa7$\xa7\xa8\xc2\xa5\xf5\x83z/]\x0f\xf2\x14\xdd\xc0\x08\xfb\xdb?b%\x88\xb36\\r\x92\x8d\xa2#\xc0fb\xd0\x1c\xf9\x7f/FU\xd3\xee\xaaK\x94\xe7\x0e\xea.\x05Ax\xad\xb0\xc31\xee\x85\x0c"\xae\xd0{B\xb5O4\x82S7\xf4h,x\xf1dI\x9d|\xba\x83\xdf\xc7\xd7"\xff\xbf!>\x0cB]\x84\x9fu\xe6\x03\x97\xf51\x05hq<\xd9\xdf\xd8]\x10\x0f\xd6\x11\xb5\x1a\xf5ej\xa5AM\xba."\x85$$\x9b/m,\x93t\xc1\x19\x84\x8e\x85\xe9\tO\xc9@\x8f\xfc}4'

with02_zeroshortktri = b'\x99\xab\xcd`%\x80\xf3W\xf9\xd8V\x02\x8dl)\xf0<\xa4m\xd8\x90vZvH\xe3O\x02\xea\x14\xe0\xcbT\x95(\x88\xa4;\xad\x16\x16]H\xba\xa9\x15"\x0c<:a\x95`\x17\x063\xfc\xa2\xc0\xa7\xdf2\xf3\xa0\xcc\xc8u\x06\xef\xaf\xcf\x8d\xdc\x9b\xd8\x15\xac5\xb0\x8a\xb6\xf4\xf8\xcc9y\xc3I\xd8H\xfd[\xf1\xdf!\x16\xc3\x83\x16\x97\xc1\x16\xb0#\x85\x949\xee\x98\xdb\xfa\x15\x8a;\xe4\x03\xab\xb2\xbd>K\xe7\xcb\xee\xe1-\x1e\x98\x8c\'\x19o\xc3\x1d\x81>\x95\xec\x85\xe85\xf9\x94\x95\xafaE\xf217\xcf\xa1\x88\xda\xd9\xb7\x97OrY\xdf\xa5\xe2\x9b\x0b\xbf\x16hkU\xc6r\xbb`\x84\x87\xc8\xcf\x02\xc9\x01\xd4\x8a\xe2\xa8\x12\xe3\xc3\x92P\x1d\xbdk\x0bni\xc8\xe8I?\xf2J\xa7\xf45\x91N\x19\xce\x86\xcc\xa8F\x03=\x9a\xf8\x08\x9a\xe8\x1cm/\xa2l\t/\xd2.\x87\x83}\xfe+u\x85w\xf3\xdb\xa02d\xfb\x14\xc5V\x08J\xf2\xd2N\x85T\x9a\xe4 '

withall = range(0,256)
withallnozero = range(1,256)
withallnotwo = [i for i in range(0,256) if i!=2] #[0,1]+range(3,256)

def generate_random(random_set, length):
    cur_length = length
    generated_hex = ""
    while( cur_length >0):
        cur_length-=1
        val = random.choice(random_set)
        generated_hex += "%02x" %(val, )
    return b''.fromhex(generated_hex)

def generate_random_with_a_zero(random_set, length):
    b_generated = generate_random(random_set, length)
    newlen = random.randint(0, length-1)
    n_generated = b_generated[:newlen] + b'\x00'+ b_generated[newlen+1:]
    return n_generated


def create_0002RRRR00RRRR(cipher):
    msg = b'\x00\x02' +generate_random(withall, 229)+ b'\x00'+generate_random(withall, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPP00PPPP(cipher):
    msg = b'\x00\x02' +generate_random(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPP00ANYLEN(cipher):

    msg = b'\x00\x02' +generate_random_with_a_zero(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPP00LONGLEN(cipher):

    msg = b'\x00\x02' +generate_random(withallnozero, 50)+ b'\x00'+generate_random(withallnozero, 179)+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPP00MEDLEN(cipher):

    msg = b'\x00\x02' +generate_random(withallnozero, 100)+ b'\x00'+generate_random(withallnozero, 129)+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg


def create_PP02PPPP00PPPP(cipher):
    #msg = generate_random(withallnozero, 1) + b'\x02' +generate_random(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    msg =  b'\x04\x02' +generate_random(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PP0P00PPPP(cipher):
    msg = b'\x00\x02' +generate_random(withallnozero, 100)+b'\x00'+generate_random(withallnozero, 128)+ b'\x00'+generate_random(withallnozero, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002RR0R00RRRR(cipher):
    msg = b'\x00\x02' +generate_random(withall, 100)+b'\x00'+generate_random(withall, 128)+ b'\x00'+generate_random(withall, 24)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg


def create_0002PPPP00P0PP(cipher):
    msg = b'\x00\x02' +generate_random(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 14)+ b'\x00'+generate_random(withallnozero, 9)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002RRRR00R0RR(cipher):
    msg = b'\x00\x02' +generate_random(withall, 229)+ b'\x00'+generate_random(withall, 14)+ b'\x00'+generate_random(withall, 9)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPPPPPPPP(cipher):
    msg = b'\x00\x02' +generate_random(withallnozero, 254)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

def create_0002PPPPPPPP0P(cipher):
    msg = b'\x00\x02' +generate_random(withallnozero, 244) + b'\x00'+generate_random(withall, 9)
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg


def create_00NNRRRRRRRRRR(cipher):
    msg = b'\x00'+generate_random(withallnotwo, 1) +generate_random(withall, 254) 
    enc_msg = partial_encrypt(cipher,msg)
    return enc_msg

"""
create_0002RRRR00RRRR
create_0002PPPP00PPPP
create_PP02PPPP00PPPP
create_0002PP0P00PPPP 
create_0002RR0R00RRRR
create_0002PPPP00P0PP
create_0002RRRR00R0RR  
create_0002PPPPPPPPPP
create_0002PPPPPPPP0P
create_00NNRRRRRRRRRR
create_0002PPPP00ANYLEN
create_0002PPPP00LONGLEN
create_0002PPPP00MEDLEN
"""
msg_type_conversion = {
                        'correct_padding_length':create_0002RRRR00RRRR,
                        'correct_padding_length_pos':create_0002PPPP00PPPP,
                        'PP02correct_length':create_PP02PPPP00PPPP,
                        'correct_padding_longerlength':create_0002PP0P00PPPP,
                        'correct_padding_longerlengthr':create_0002RR0R00RRRR,
                        'correct_padding_addzerotoktri':create_0002PPPP00P0PP,
                        'correct_padding_addzerotoktrir':create_0002RRRR00R0RR,
                        'correct_padding_nozero':create_0002PPPPPPPPPP,
                        'correct_padding_shorterlength':create_0002PPPPPPPP0P,
                        'bad_padding_00NN':create_00NNRRRRRRRRRR,
                        'correct_padding_anymsglen':create_0002PPPP00ANYLEN,
                        'correct_padding_verylongmsglen': create_0002PPPP00LONGLEN,
                        'correct_padding_medmsglen': create_0002PPPP00MEDLEN,
                        }
                        
msg_type_list = msg_type_conversion.keys()

# def generate_by_type(msg_type):
#     pass