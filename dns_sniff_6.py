#! python3.8

import dpkt, dpkt.dns
import sys,csv,os,time
import socket
import pcap

base=os.path.basename(__file__)
os.path.splitext(base)
scriptName=os.path.splitext(base)[0]

dts0=time.strftime('%Y%m%d_%H%M%S', time.localtime(time.time()))


output1FN=f'{scriptName}_output1-{dts0}.csv'

output1FH=open(output1FN,'w',newline='',encoding='utf-8')
writer1=csv.writer(output1FH, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
header1List=['dts','ts','srcip','srcport','dstip','dstport','pktNum','dnsId','dnsQName','dnsQType','dnsQTypeStr','dns.qr','dnsRcode','dnsAnLen','A_name','A_ipV4','NS_str','CNAME_name','SOA_str','PTR_name','HINFO_str','MX_str','TXT_str','AAAA_name','AAAA_ipV6','SRV_name','SRV_priority','SRV_weight','SRV_port','ANY_str','dnsAn']

writer1.writerow(header1List)

output2FN=f'{scriptName}_output2-{dts0}.txt'
output2FH=open(output2FN,'w+')
output2FH.write('poop'+'\n')
#sys.exit()

qTypeDict = {
    1:"A",        # IP v4 address, RFC 1035
    2:"NS",       # Authoritative name server, RFC 1035
    5:"CNAME",    # Canonical name for an alias, RFC 1035
    6:"SOA",      # Marks the start of a zone of authority, RFC 1035
    12:"PTR",      # Domain name pointer, RFC 1035
    13:"HINFO",    # Host information, RFC 1035
    15:"MX",       # Mail exchange, RFC 1035
    28:"AAAA",     # IP v6 address, RFC 3596
    16:"TXT",      # 
    33:"SRV",     # RFC 2782
    255:"ANY"     # all cached reco
                }


def main():
    pc = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
    pc.setfilter('port 53')
    i=0

    for ts, pkt in pc:
        i+=1
        pktNum=i
        output2FH.write('***************************************************************'+'\n')
        
        #print(f'ts={ts},pkt={pkt}')
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        udp = ip.data
        
        try:
            output2FH.write(f'*****start udp data***********\n')
            output2FH.write(str(udp.data))
            output2FH.write('\n')
            output2FH.write('*****end udp data**************\n')
            
            dns = dpkt.dns.DNS(udp.data)
        except:
            next
        
        dtsx=time.strftime('%Y%m%d_%H%M%S', time.localtime(ts))
        #dts=ts
        
        srcip=inet_to_str(ip.src)
        srcport=udp.sport
        dstip=inet_to_str(ip.dst)
        dstport=udp.dport
        dnsId=dns.id
        
        record2list=[srcip,str(srcport),dstip,str(dstport),str(dnsId)]
        record2str=','.join(record2list)
        output2FH.write(record2str+'\n')
        output2FH.write(str(dns))
        #print(dns)
        output2FH.write('\n')
        
        try:
            dnsQName=dns.qd[0].name
        except:
            output2FH.write('!!!Failed!!!-dnsQName=dns.qd[0].name\n')
            next
        try:
            dnsQType=dns.qd[0].type
        except:
            output2FH.write('!!!Failed!!!-dnsQType=dns.qd[0].type\n')
            next
            #sys.exit()
        dnsQTypeStr=qTypeDict[dnsQType]
        
        recordxList=[dtsx,ts,srcip,srcport,dstip,dstport,pktNum,dnsId,dnsQName,dnsQType,dnsQTypeStr,dns.qr]
                     
        
        if dns.qr==0: #Query
            dnsAn=''
            dnsNS=''
            dnsAR=''
            dnsAnLen=''
            dnsRcode=''
            rrType=''
            rrData=''
            
            A_name=''
            A_ipV4=''
            NS_str=''
            CNAME_name=''
            SOA_str=''
            PTR_name=''
            HINFO_str=''
            MX_str=''
            TXT_str=''
            AAAA_name=''
            AAAA_ipV6=''
            SRV_name=''
            SRV_priority=''
            SRV_weight=''
            SRV_port=''
            ANY_str=''
            
            recordyList=[dnsRcode,A_name,A_ipV4,NS_str,CNAME_name,SOA_str,PTR_name,HINFO_str,MX_str,TXT_str,AAAA_name,AAAA_ipV6,SRV_name,SRV_priority,SRV_weight,SRV_port,ANY_str,dnsAn]
            
            recordzList=recordxList+recordyList
            writer1.writerow(recordzList)
            
        elif dns.qr==1: #Response
            dnsAn=dns.an
            dnsNS=dns.ns
            dnsAR=dns.ar
            dnsAnLen=len(dns.an)
            dnsNSLen=len(dns.ns)
            dnsArLen=len(dns.ar)
            dnsRcode=dns.rcode
            recordyList=[dnsRcode]
            
            if dnsAnLen > 0: #There are RRs in the answer.
                dnsRRList=decode_an(dnsAn)
                for recordDict in dnsRRList:
                    A_name=recordDict['A_name']
                    A_ipV4=recordDict['A_ipV4']
                    NS_str=recordDict['NS_str']
                    CNAME_name=recordDict['CNAME_name']
                    SOA_str=recordDict['SOA_str']
                    PTR_name=recordDict['PTR_name']
                    HINFO_str=recordDict['HINFO_str']
                    MX_str=recordDict['MX_str']
                    TXT_str=recordDict['TXT_str']
                    AAAA_name=recordDict['AAAA_name']
                    AAAA_ipV6=recordDict['AAAA_ipV6']
                    SRV_name=recordDict['SRV_name']
                    SRV_priority=recordDict['SRV_priority']
                    SRV_weight=recordDict['SRV_weight']
                    SRV_port=recordDict['SRV_port']
                    ANY_str=recordDict['ANY_str']
                    recordyList=[dnsRcode,dnsAnLen,A_name,A_ipV4,NS_str,CNAME_name,SOA_str,PTR_name,HINFO_str,MX_str,TXT_str,AAAA_name,AAAA_ipV6,SRV_name,SRV_priority,SRV_weight,SRV_port,ANY_str,dnsAn]
                    recordzList=recordxList+recordyList
                    writer1.writerow(recordzList)
                    print(recordzList)
            else: #The answer is empty.
                A_name=''
                A_ipV4=''
                NS_str=''
                CNAME_name=''
                SOA_str=''
                PTR_name=''
                HINFO_str=''
                MX_str=''
                TXT_str=''
                AAAA_name=''
                AAAA_ipV6=''
                SRV_name=''
                SRV_priority=''
                SRV_weight=''
                SRV_port=''
                ANY_str=''
                
                recordyList=[dnsRcode,dnsAnLen,A_name,A_ipV4,NS_str,CNAME_name,SOA_str,PTR_name,HINFO_str,MX_str,TXT_str,AAAA_name,AAAA_ipV6,SRV_name,SRV_priority,SRV_weight,SRV_port,ANY_str,dnsAn]
                recordzList=recordxList+recordyList
                writer1.writerow(recordzList)
                print(recordzList)
                
            if dnsNSLen > 0:
                pass
            if dnsArLen > 0:
                pass
                
            #rrType=rr.type
            #rrData=rr.data
            rrType='null'
            rrData='null'
            
            #Decode response
            # Decode the RR records in the NS section
            
        else:
            print('!!!ERROR!!!-dns.qr not a 0 or 1')
            sys.exit()
            
        #print(ts,inet_to_str(ip.src), udp.sport, inet_to_str(ip.dst), udp.dport)
        #print(f'dns.opcode={dns.opcode},dns.id={dns.id},dns.qr={dns.qr},dns.an={dns.an}')
        #print(f'dns.qd[0].name={dns.qd[0].name},dns.qd[0].type={dns.qd[0].type}')
        
        
        #recordxList=[dtsx,srcip,srcport,dstip,dstport,dnsId,dnsQName,dnsQType,dnsQTypeStr,dns.qr,dnsRcode,dnsAnLen]
        #print(','.join(recordxList))
        #print(str(recordxList))
        #writer1.writerow(recordxList)
        
        output2FH.write('***************************************************************'+'\n')
        
def decode_an(dnsAn):
    output2FH.write('***************************************top'+'\n')
    output2FH.write(f'dnsAnLen={len(dnsAn)}'+'\n')
    output2FH.write(str(dnsAn)+'\n')
    
    dnsAnList=[]
    
    i=0
    
    for rr in dnsAn:
        i+=1
        
        A_name=''
        A_ipV4=''
        NS_str=''
        CNAME_name=''
        SOA_str=''
        PTR_name=''
        HINFO_str=''
        MX_str=''
        TXT_str=''
        AAAA_name=''
        AAAA_ipV6=''
        SRV_name=''
        SRV_priority=''
        SRV_weight=''
        SRV_port=''
        ANY_str=''
        
        output2FH.write(f'rr={i}'+'\n')

        rr_type=rr.type
        rr_data=rr.rdata
        output2FH.write(f'rtype={rr_type}'+'\n')
        output2FH.write(f'rdata={rr_data}'+'\n')
        output2FH.write(f'rtype={rr_type}'+'\n')
        output2FH.write(f'rdata={rr_data}'+'\n')

        if not rr.type:
            print('record type does not exist so assume it to be 1')
            ipV4=socket.inet_ntoa(rr.ip)
            print(f'ipV4={ipV4}')
            sys.exit()
        elif rr.type==1:
            output2FH.write(f'processing ipV4'+'\n')
            A_name=rr.name
            A_ipV4=socket.inet_ntoa(rr.ip)
            output2FH.write(f'A_name={A_name},A_ipV4={A_ipV4}'+'\n')
            #sys.exit()
        elif rr.type==2:
            output2FH.write(f'processing NS'+'\n')
            nsname='tbd'
        elif rr.type==5:
            output2FH.write(f'processing CNAME'+'\n')
            CNAME_name=rr.cname
            output2FH.write(f'CNAME_name={CNAME_name}'+'\n')
        elif rr.type==6:
            output2FH.write(f'processing SOA'+'\n')
            soa='tbd'
        elif rr.type==12:
            output2FH.write(f'processing PTR'+'\n')
            PTR_name=rr.ptrname
            output2FH.write(f'PTR_name={PTR_name}'+'\n')
        elif rr.type==13:
            output2FH.write(f'processing HINFO'+'\n')
            hinfo='tbd'
        elif rr.type==15:
            output2FH.write(f'processing MX'+'\n')
            mx='tbd'
        elif rr.type==16:
            output2FH.write(f'processing TXT'+'\n')
            txt='tbd'
        elif rr.type==28:
            output2FH.write(f'processing AAAA'+'\n')
            AAAA_name=rr.name
            AAAA_ipV6=socket.inet_ntop(socket.AF_INET6,rr.rdata)
            output2FH.write(f'AAAA_name={AAAA_name},AAAA_ipV6={AAAA_ipV6}'+'\n')
        elif rr.type==33:
            SRV_name=rr.name
            SRV_priority=rr.priority
            SRV_weight=rr.weight
            SRV_port=rr.port
            output2FH.write(f'processing SRV'+'\n')
            output2FH.write(f'SRV_name={SRV_name},SRV_priority={SRV_priority},SRV_weight={SRV_weight},SRV_port={SRV_port}'+'\n')
        elif rr.type==255:
            output2FH.write(f'processing ANT'+'\n')
            any0='tbd'
        else:
            print(f'!!!ERROR!!!-Could not determine recordtype {rr}')
            sys.exit()

        rrDict={'A_name':A_name,'A_ipV4':A_ipV4,'NS_str':NS_str,'CNAME_name':CNAME_name,'SOA_str':SOA_str,'PTR_name':PTR_name,'HINFO_str':HINFO_str,'MX_str':MX_str,'TXT_str':TXT_str,'AAAA_name':AAAA_name,'AAAA_ipV6':AAAA_ipV6,'SRV_name':SRV_name,'SRV_priority':SRV_priority,'SRV_weight':SRV_weight,'SRV_port':SRV_port,'ANY_str':ANY_str}
        
        dnsAnList.append(rrDict)
        output2FH.write(f'{str(rrDict)}'+'\n')

    return dnsAnList
        
def decode_ns(dnsNS):
    dnsNSList=[]
    print('***************************************up')
    for rr in dnsNS:
        dnsNSList.append(rr.rname)
    return dnsNSList
    
def decode_ar(dnsAR):
    print('***************************************up')
    for rr in dnsNS:
        print(f'rr.rname={rr.rname}')
    print('***************************************down')
    
        
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
        
main()