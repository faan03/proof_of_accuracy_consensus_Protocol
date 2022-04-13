from rsa import PublicKey as PublicKey 
from myRsa import myRsa
from Crypto.PublicKey import RSA
#from Crypto import PublicKey
#import gensafeprime as gen
from Crypto.PublicKey import RSA
from  Crypto.PublicKey.RSA import RsaKey as construct

keysize = 2048
(vk, sk) = myRsa.newkeys(keysize)

print(f"{type(vk)}")
listVks = [vk]*(5)

s= vk.export_key()
print(f"s = {s}")
s=s.decode()
#print(s)
#sb.encode('utf-8')
newpublic= RSA.import_key(str.encode(s))

r= newpublic.export_key()
print(f"r = {r}")

if (s==r):
    print("iguales")
#listVks[2]=newpublic

print(vk)
print(newpublic)

if (vk==newpublic):
    print("iguales")
#print((listVks[0]))
#print((listVks[2]))

'''
listVks = [None]*(5)

listVks[0]="asd"
listVks[1]=45
print(listVks)
'''
'''
public, private=  myRsa.newkeys(1024)

print(f"{public.n} - {public.e}")

newpublic= PublicKey(public.n, public.e)

print(f"{newpublic.n} - {newpublic.e}")
#print(private)


'''