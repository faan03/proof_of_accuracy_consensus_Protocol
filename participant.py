import random as random
import copy
from Zq import Zq as Zq
from Zq import Generator as Generator
from myRsa import myRsa as myRsa
from base64 import b64encode, b64decode
from p2pnetwork.node import Node
from Crypto.PublicKey import RSA
#from Crypto import PublicKey
from rsa import PublicKey as PublicKey
from myRsa import myRsa
from Crypto.PublicKey import RSA
"""-------------------------------------------------------------------------------
                                    participant
-------------------------------------------------------------------------------"""
class participant(Node):
    def __init__(self, G, q, g, i, n, t, host, port, callback=None, max_connections=0):
        self.G = G
        self.q = q
        self.zq = Zq(q)
        self.g = g
        self.__listEphemeralPublicKeys = [None]*(t-1)
        keysize = 2048                
        (self.__vk, self.__sk) = myRsa.newkeys(keysize)      # public, private
        self.__listVks = [None]*(t-1) 
        self.i = i
        self.n = n
        self.t = t
        self.__Cis = [None]*(t-1)
        self.__A = []
        self.__answerCheck=False        
        self.__Bl = 1        
        super(participant, self).__init__(host, port, i, callback, max_connections)
        print(f"::: Participant {i} instantiated::: ")

    def getVk(self):        
        self.__listVks[self.i-1]=self.__vk
        return self.__vk    

    def __generateEphemeralKeyPairs(self):
        self.__ephemeralSecretKeys = [self.zq.getRandomNotZeroElement() for j in range(0, self.n + 1)]
        self.__ephemeralPublicKeys = [self.G.potencia(self.g, sk) for sk in self.__ephemeralSecretKeys]

    def getPublicEphemeralKeys(self):
        self.__generateEphemeralKeyPairs()
        self.__listEphemeralPublicKeys[self.i-1]=self.__ephemeralPublicKeys
        return self.__ephemeralPublicKeys
        
    def sMetod(self, j):
        if self.i > j:
            return 1
        elif self.i < j:
            return self.q - 1
    
    def __computeRp_product(self, z):
        rpi = 1
        for j in range(0, self.t - 1):
            if self.i != (j + 1):
                rpi = self.G.producto(
                    rpi,
                    self.G.potencia(
                        self.__listEphemeralPublicKeys[j][z],
                        self.zq.producto(
                            self.sMetod(j + 1), self.__ephemeralSecretKeys[z]
                        ),
                    ),
                )
        return rpi

    def computeR(self):
        print(f":::::::: Participant {self.i} Compute R :::::::::::")
        self.__Ris = []
        for z in range(0, self.n + 1):
            self.__Ris.append(self.__computeRp_product(z))
        self.__get_si_ci()

    def __get_si_ci(self):
        self.c = self.zq.getRandomNotZeroElement()
        self.s = self.zq.getRandomElement()

    def computeCi(self, prob=1):
        CI = []    
        CI.append(self.G.producto(self.G.potencia(self.g, self.s), self.__Ris[0]))
        for j in range(1, self.n + 1):
            CI.append(
                self.G.producto(
                    self.G.potencia(self.g, self.__e(j, prob)), self.__Ris[j]
                )
            )  # 1...n
        CIBL = copy.copy(CI)  # se adiciona el Bl(id ultimo bloque de la cadena)
        CIBL.append(self.__Bl)
        hashCiBL = myRsa.H1(str(CIBL))
        sigma = b64encode(myRsa.sign(self.__sk, hashCiBL))  #        
        self.__Cis[self.i-1]=(CI, sigma)
        return (CI, sigma)

    def __e(self, j, prob):
        rn = random.random()        
        if rn <= prob:
            return self.zq.suma(
                self.zq.producto(self.c, self.zq.potencia(j, self.i)), self.s
            )  # cx_i+s
        else:
            return self.zq.getRandomElement()

    def mining(self):
        self.computeAs()        
        u = self.__A[0]  # u = g^s
        u_p = 1
        veces = 0
        while u_p != u: 
            (u_p, js) = self.recovery_u()            
            veces = veces + 1
        print(f" Attempts = {veces}")
        m_id = (self.i, js, self.__Cis)
        hash_m_id = myRsa.H1(str(m_id))
        sigma_m_id = b64encode(myRsa.sign(self.__sk, hash_m_id))  #
        #------------------------------------
        ci_sigma=[]
        for c_s in m_id[2]:
            ci_sigma.append((c_s[0],c_s[1].decode()))
        m_id_1=(m_id[0],m_id[1],ci_sigma)
        sigma_m_id=sigma_m_id.decode()
        return (m_id_1, sigma_m_id)
    
    def recovery_u(self):
        js = []
        js = sorted(random.sample(range(1, self.n + 1), self.t))
        w = 1
        for i in js:
            coef = 1
            for j in js:
                if j != i:
                    nu = self.zq.resta(0, j)
                    den = self.zq.resta(i, j)
                    coef = self.zq.producto(coef, self.zq.division(nu, den))
            w = self.G.producto(w, self.G.potencia(self.__A[i], coef))
        return (w, js)
    
    def check(self, m_id, sigma_m_id):
        self.__answerCheck = False
        print(f":::::::: Participant {self.i} is checking mining answer ::::::::")        
        hash_m_id = myRsa.H1(str(m_id))        
        bo = myRsa.verify(self.__listVks[m_id[0] - 1], hash_m_id, b64decode(sigma_m_id))        
        id = m_id[0]
        js = m_id[1]
        Cs_Sigmas = m_id[2]
        if bo == True:
            for i in range(0, self.t - 1):
                CIBL = []
                Ci = Cs_Sigmas[i][0]
                CIBL = copy.copy(Ci)  # se adiciona el Bl(id ultimo bloque de la cadena)
                CIBL.append(self.__Bl)
                hashCiBL = myRsa.H1(str(CIBL))
                sigmai = Cs_Sigmas[i][1]
                v = myRsa.verify(self.__listVks[i], hashCiBL, b64decode(sigmai))                
                if v == False:                    
                    return False            
            for index in range(len(Cs_Sigmas)):
                self.__Cis[index]=Cs_Sigmas[index]                                
            self.computeAs()            
            u = self.__A[0]  # u = g^s
            w = 1
            for i in js:
                coef = 1
                for j in js:
                    if j != i:
                        nu = self.zq.resta(0, j)
                        den = self.zq.resta(i, j)
                        coef = self.zq.producto(coef, self.zq.division(nu, den))
                w = self.G.producto(w, self.G.potencia(self.__A[i], coef))
            if u == w:
                #print("u==w")
                self.__answerCheck = True

    def getanswerCheck(self):
        return(self.__answerCheck)    

    def __compute_A(self, i_):
        A = 1
        for i in range(0, self.t - 1):            
            A = self.G.producto(A, self.__Cis[i][0][i_])
        return A

    def computeAs(self):
        for i_ in range(0, self.n + 1):  # n Ci cada uno de tamaño t-1
            self.__A.append(self.__compute_A(i_))

    def addBlock(self):
        self.__Bl += 1

    # all the methods below are called when things happen in the network.
    # implement your network node behavior to create the required functionality.

    def outbound_node_connected(self, node):
        print("outbound participant " + self.id + "connected to -> " + node.id)
        
    def inbound_node_connected(self, node):
        print("inbound participant: " + self.id + "connected to -> " + node.id)

    def inbound_node_disconnected(self, node):
        print("inbound_node_disconnected: (" + self.id + "): " + node.id)

    def outbound_node_disconnected(self, node):
        print("outbound_node_disconnected: (" + self.id + "): " + node.id)
    
    def node_disconnect_with_outbound_node(self, node):
        print("node wants to disconnect with oher outbound node: (" + self.id + "): " + node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop (" + self.id + "): ")    

    def node_message(self, node, data): #data -> (tipo, data)                
        if data.get('tipo')=="vk_i":   
            print(f"Participant {self.id} receives long.term public key from participant {node.id} ")
            valor=data.get('valor')                        
            newpublic= RSA.import_key(str.encode(valor))           
            self.__listVks[int(node.id)-1]=newpublic
        elif data.get('tipo')=='pk_i':
           print(f"participant {self.id} receives ephemeral public keys from participant {node.id} ")
           self.__listEphemeralPublicKeys[int(node.id)-1]=data.get('valor')           
        elif  data.get('tipo')=='Ci_sigmai':
            print(f"participant {self.id} receives Ci and sigma_i from participant {node.id} ")
            CI =data.get('valor')[0]
            sigma=str.encode(data.get('valor')[1])
            self.__Cis[int(node.id)-1]=(CI, sigma)            
        elif data.get('tipo')=='solve':            
            print(f"participant {self.id} receives solve from participant {node.id} ")
            m_id= data.get('valor')[0]
            sigma_m_id= data.get('valor')[1]
            ci_sigma=[]
            for c_s in m_id[2]:
                ci_sigma.append((c_s[0],str.encode(c_s[1])))
            m_id_1=(m_id[0],m_id[1],ci_sigma)            
            sigma_m_id=str.encode(sigma_m_id)            
            self.check(m_id_1,sigma_m_id)
            
    def share_long_term_public_keys(self):
        vk_i= self.getVk() # llave publica long-term  - vk_i    
        self.send_to_nodes(dict(tipo='vk_i', valor=vk_i.export_key().decode()))    
    
    def share_PublicEpheremalKeys(self): 
        pk_i= self.getPublicEphemeralKeys()  ## llaves efimeras  
        self.send_to_nodes(dict(tipo='pk_i', valor=(pk_i)))   