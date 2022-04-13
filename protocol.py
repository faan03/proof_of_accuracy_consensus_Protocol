#!pip install p2pnetwork
import gensafeprime as gen
import random as random
import hashlib as hashlib
import random
from base64 import b64encode, b64decode
import hashlib as hashlib
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
import copy
from Zq import Zq as Zq
from Zq import Generator as Generator
from myRsa import myRsa as myRsa
from participant import participant as participant
from myRsa import myRsa
from Crypto.PublicKey import RSA
import time

p= gen.generate(100)
q=((p-1)//2)
G=Zq(p)
zq=Zq(q)
g=Generator(G,q)

t= 20
n= 30
prob=0.99
host="127.0.0.1"
participants =[]

print("::::::::::::::::::::: Instanciate the participants :::::::::::::::::::::::::::::::::::::")
for i in range(1,t):  
  participants.append(participant(G,q,g.get_g(),i,n,t,host,(8000+i),i))

print("::::::::::::::::::::: Start the participants :::::::::::::::::::::::::::::::::::::")
for pi in  participants:
    pi.start()

print("::::::::::::::::::::: Connect  the participants :::::::::::::::::::::::::::::::::::::")
porti=8002
portf=porti+t
for po in  participants:        
    for port in  range((porti),(portf)):
        po.connect_with_node('127.0.0.1', port)
    porti+=1    

print(":::::: Each participant shares its long-term public key with other participants::::::::::")
for pi in  participants:
    pi.share_long_term_public_keys()
time.sleep(10)  


print(":::::::::::::::::: Protocol :::::::::::::::::::::::::::::")
print(":::::: Each participant  generates n+1  ephemeral key pair and senda  the public keys to other participants ::::::::::")

for pi in  participants:
    pi.share_PublicEpheremalKeys() 
time.sleep(10)       

print(":::::::::::::: Each participant compute R ::::::::::::::::::::::")
for pi in participants:
    pi.computeR()

print (":::::::::::::::::: Select a random participant for the miner :::::::::::::::::::::::")
xminer=random.randint(1,t-1)
 
print(f"::: Participant {xminer} takes the role of the miner, then  asks the other the participants for Ci; each of the participants computes Ci and sigma_i and sends it to the miner:::")
time.sleep(10)
for pi in  participants:
    (Ci,sigmai)= pi.computeCi(prob)      
    pi.send_to_some_nodes(dict(tipo="Ci_sigmai",valor=(Ci,sigmai.decode())),[str(xminer)])

time.sleep(10)    

print(f" ::: Participant {xminer} (miner) performs the mining process ::: ")
(m_id,sigma_m_id) = participants[xminer-1].mining() # mid = (id, j1, j2, . . . , jt ,(C1, σ1),(C2, σ2), . . .(Ct−1, σt−1)),

print (":::::::::::::::::: Select a random participant to take the role of validator, it then checks the  answer from the miner participant :::::::::::::::::::::::")
xCheck=random.randint(1,t-1)
print(f"::: Participant {xCheck} chechs the answer from the miner participant :::")

#participants[xCheck-1].addBlock()
participants[xminer-1].send_to_some_nodes(dict(tipo="solve",valor=(m_id,sigma_m_id)),[str(xCheck)])
time.sleep(20)    

if participants[xCheck-1].getanswerCheck():
    print("::: The answer of the miner participant is correct ::: ")
else:
    print("::: The answer of the miner participant is wrong::: ")

for pi in  participants:
    pi.stop()

print(":: END:: ")



