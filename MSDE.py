from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from Crypto.Hash import SHA256
import time
class MSDE:
    def __init__(self, groupObj):
        global group
        group = groupObj


    def setup(self):
        g = group.random(G1)
        x = group.random(ZR)
        h = g ** x
        pk = {'g': g, 'h': h}
        msk = x
        #hash = SHA256.new()
        return (pk, msk)

    def keygen(self,msk):
        x1 = group.random(ZR)
        x2=msk-x1
        return (x1,x2)

    def enc(self,pk,x1,w):
        r = group.random(ZR)
        sigma= group.hash(w, ZR)
        c1=pk['g']**(r+sigma)
        c2=c1**x1
        # c3=group.hash((1,pk['h']**r),ZR)
        hash256 = SHA256.new()
        hash256.update(str(pk['h']**r))
        c3= hash256.digest()
        c={'c1':c1,'c2':c2,'c3':c3}
        return c

    def reenc(self,x2,c):
        cc1=(c['c1']**x2)*c['c2']
        cc2=c['c3']
        cc={'cc1':cc1,'cc2':cc2}
        return cc

    def trap(self,pk,x1,w):
        r=group.random(ZR)
        sigma = group.hash(w, ZR)
        t1=(pk['g']**(-r))*(pk['g']**sigma)
        t2=(pk['h']**r)*(pk['g']**(-x1*r))*(pk['g']**(x1*sigma))
        t={'t1':t1,'t2':t2}
        return t

    def retrap(self,x2,t):
        tt=t['t1']**x2*t['t2']
        #return tt
        return tt ** (-1)

    def match(self,cc,tt):
        flag=False

        hash256 = SHA256.new()
        #hash256.update(str(cc['cc1']/tt))
        hash256.update(str(cc['cc1']*tt))
        right = hash256.digest()

        if cc['cc2']==right:
            flag=True
        else:
            flag=False
        return flag

def main():
    params = ('SS512', 'SS1024')
    keyword='cityu'
    keyword1 = 'cityu1'
    mgp=PairingGroup(params[0])
    msde=MSDE(mgp)
    (pk, msk)=msde.setup()
    (x1,x2)=msde.keygen(msk)
    c=msde.enc(pk,x1,keyword)
    cc=msde.reenc(x2,c)

    t=msde.trap(pk,x1,keyword)

    tt=msde.retrap(x2,t)

    flag=msde.match(cc,tt)
    #print flag
    userNum=10000


    '''
    elapsed_timeStart = '';
    for n in range(1000,userNum+1,1000):
        start_Setup = time.clock()
        (pk, msk) = msde.setup()
        for i in range(n):
            (x1, x2) = msde.keygen(msk)
        elapsed_Setup = time.clock() - start_Setup
        print(n, elapsed_Setup)
        elapsed_timeStart+=str(elapsed_Setup)+'\t'

    print elapsed_timeStart
    '''

    '''
    elapsed_time=''

    for j in range(10,100+1,10):
        start = time.clock()
        for k in range(10):
            for i in range(j):
                #(x1, x2) = msde.keygen(msk)
                #c = msde.enc(pk, x1, keyword)
                #cc = msde.reenc(x2, c)

                #t = msde.trap(pk, x1, keyword)
                tt = msde.retrap(x2, t)

                #flag = msde.match(cc, tt)
        elapsed_Alg=(time.clock()-start)/(10)
        elapsed_time += str(elapsed_Alg) + '\t'
    print 'time elapsed:'+elapsed_time
    '''
    '''
    elapsed_MatchTotal = ''
    for i in range(10,50+1,10):
        elapsed_timeMatch = ''
        for j in range(10,50+1,10):
            start_Match = time.clock()
            for k in range(100):
                for jj in range(i*j):
                    flag = msde.match(cc, tt)
            elapsed_Match = (time.clock() - start_Match) / 100
            #print i,j,elapsed_Match
            elapsed_timeMatch += str(elapsed_Match) + '\t'
        print elapsed_timeMatch
        # elapsed_MatchTotal+=elapsed_timeMatch+'\n'
    # print elapsed_MatchTotal
    '''
if __name__ == '__main__':
    main()



