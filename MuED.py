
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import time
BS=16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]
iv ='This is an IV456'

class MuED:
    def __init__(self, groupObj):
        global group
        group = groupObj


    def setup(self):
        g = group.random(G1)
        x = group.random(ZR)
        msk = x
        return (g, msk)

    def keygen(self,g,msk):
        uk = group.random(ZR)
        #uk=msk
        ck=g**(msk/uk)
        return (uk,ck)

    def enc(self,g,uk,ck,w,msg):

        hash256 = SHA256.new()
        padmsg=pad(msg)

        r = group.random(ZR)
        #r=uk
        sigma= group.hash(w, G1)**r
        #print'sigma', sigma
        #print group.hash(w,ZR)
        #print sigma
        e=pair(sigma, ck)
        #print e
        ee=e**(uk/r)
        #print ee
        #print pair(group.hash(w,ZR)**r,ck)**(uk/r)

        hash256.update(str(ee))
        kstr=hash256.digest()
        #print base64.b64encode(kstr)
        #kstr='This is a key123'
        #print len(kstr)
        cipher = AES.new(kstr, AES.MODE_CBC, iv)
        ciphertext=cipher.encrypt(padmsg)
        return (base64.b64encode(ciphertext))



    def trap(self,uk,w):
        t = group.hash(w, G1) **uk
        #print group.hash(w, ZR)
        #print 't',t
        return t

    def retrap(self,ck,t):
        #print 't', t
        tt=pair(t, ck)

        #print tt
        return tt

    def match(self,cc,tt,msg):
        flag=False
        hash256 = SHA256.new()
        hash256.update(str(tt))
        kstr = hash256.digest()
        #print base64.b64encode(kstr)
        #kstr = 'This is a key123'
        cipher = AES.new(kstr, AES.MODE_CBC, iv)
        ciphertext = base64.b64decode(cc)
        recovermsg=unpad(cipher.decrypt(ciphertext))
        #print recovermsg
        if recovermsg==msg:
            flag=True
        else:
            flag=False
        return flag

    def retrap1(self,ck,t):
        #print 't', t
        tt=pair(t, ck)
        hash256 = SHA256.new()
        hash256.update(str(tt))
        kstr = hash256.digest()
        return kstr

    def match1(self,cc,kstr,msg):
        flag=False
        cipher = AES.new(kstr, AES.MODE_CBC, iv)
        ciphertext = base64.b64decode(cc)
        recovermsg=unpad(cipher.decrypt(ciphertext))

        if recovermsg==msg:
            flag=True
        else:
            flag=False
        return flag

def main():
    params = ('SS512', 'SS1024')
    keyword='cityu'
    keyword1='nuist'
    msg = 'computerscience'

    mgp=PairingGroup(params[0])
    mued=MuED(mgp)

    (g, msk)=mued.setup()
    (uk,ck)=mued.keygen(g,msk)

    c=mued.enc(g,uk,ck,keyword,msg)

    t=mued.trap(uk,keyword)
    tt=mued.retrap(ck,t)
    kstr = mued.retrap1(ck, t)

    flag=mued.match(c,tt,msg)
    #print flag
    userNum = 10000
    '''
    elapsed_timeStart = '';
    for n in range(1000, userNum + 1, 1000):
        start_Setup = time.clock()
        (g, msk) = mued.setup()
        for i in range(n):
            (uk, ck) = mued.keygen(g, msk)
        elapsed_Setup = time.clock() - start_Setup
        print(n, elapsed_Setup)
        elapsed_timeStart += str(elapsed_Setup) + '\t'

    print elapsed_timeStart
    '''

    '''
    elapsed_time = ''

    for j in range(10,100+1,10):
        start = time.clock()
        for k in range(10):
            for i in range(j):
                #(g, msk) = mued.setup()
                #(uk, ck) = mued.keygen(g, msk)
                #c = mued.enc(g, uk, ck, keyword, msg)
                #t = mued.trap(uk, keyword)
                #tt = mued.retrap(ck, t)
                kstr=mued.retrap1(ck, t)

                #flag = mued.match(c, tt, msg)
        elapsed_Alg = (time.clock() - start)/(10)
        elapsed_time += str(elapsed_Alg) + '\t'
    print 'time elapsed:' + elapsed_time
    '''
    '''
    for i in range(10):
        elapsed_timeMatch = ''
        for j in range(10):
            start_Match = time.clock()
            for k in range(100):
                for ii in range(i + 1):
                    kstr = mued.retrap1(ck, t)
                for jj in range((i+1)*(j + 1)):
                    flag = mued.match1(c, kstr, msg)
            elapsed_Match = (time.clock() - start_Match) / 100
            # print ii,jj,elapsed_Match
            elapsed_timeMatch += str(elapsed_Match) + '\t'
        print elapsed_timeMatch
    '''
    elapsed_MatchTotal = ''
    for i in range(10, 50 + 1, 10):
        elapsed_timeMatch = ''
        for j in range(10, 50 + 1, 10):
            start_Match = time.clock()
            for k in range(100):
                for jj in range(i * j):
                    flag = mued.match1(c, kstr, msg)
            elapsed_Match = (time.clock() - start_Match) / 100
            #print i, j, elapsed_Match
            elapsed_timeMatch += str(elapsed_Match) + '\t'
        print elapsed_timeMatch
        # elapsed_MatchTotal+=elapsed_timeMatch+'\n'
    # print elapsed_MatchTotal



if __name__ == '__main__':
    main()



