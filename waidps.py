#! /usr/bin/python
##
## This was written for educational purpose only. Use it at your own risk.
## Author will be not responsible for any damage!
## Written By SY Chua, syworks@gmail.com
##
## Current - WiFi Harvester & WIDS / IPS
##
#############
## MODULES ##
#############
IMPORT_ERRMSG=""
import __builtin__
import os,sys,subprocess,getopt
import time,datetime
import tty,termios,curses
import select
import signal
import random
import urllib
import shutil
import readline
from subprocess import Popen, call, PIPE
from math import floor
try:
  import hashlib
except:
  IMPORT_ERRMSG=IMPORT_ERRMSG + "      Error importing 'hashlib'\n"
try:
   from Crypto.Cipher import AES
except:
  IMPORT_ERRMSG=IMPORT_ERRMSG + "      Error importing 'AES'\n"
try:
  import base64
except:
  IMPORT_ERRMSG=IMPORT_ERRMSG + "      Error importing 'base64'\n"
appver="1.0, R.1"
apptitle="WAIDPS"
appDesc="- The Wireless Auditing, Intrusion Detection & Prevention System"
appcreated="28 Feb 2014"
appupdated="25 Apr 2014"
appnote="Written By SY Chua, " + appcreated + ", Updated " + appupdated
appdescription="Wiresless IDS-2 is a whole new application which is design to harvest all WiFi information (AP / Station details) in your surrounding and store as a database for reference. With the stored data, user can further lookup for specific MAC or names for detailed information of it relation to other MAC addresses. It primarily purpose is to detect wireless attacks in WEP/WPA/WPS encryption. It also comes with an analyzer and viewer which allow user to further probe and investigation on the intrusion/suspicious packets captured. Additional features such as blacklisting which allow user to monitor specific MACs/Names's activities. All information captured can also be saved into pcap files for further investigation."
class fcolor:
    CReset='\033[0m'
    CBold='\033[1m'
    CDim='\033[2m'
    CUnderline='\033[4m'
    CBlink='\033[5m'
    CInvert='\033[7m'
    CHidden='\033[8m'
    CDebugB='\033[1;90m'
    CDebug='\033[0;90m'
    Black='\033[30m'
    Red='\033[31m'
    Green='\033[32m'
    Yellow='\033[33m'
    Blue='\033[34m'
    Pink='\033[35m'
    Cyan='\033[36m'
    White='\033[37m'
    SBlack=CReset + '\033[0;30m'
    SRed=CReset + '\033[0;31m'
    SGreen=CReset + '\033[0;32m'
    SYellow=CReset + '\033[0;33m'
    SBlue=CReset + '\033[0;34m'
    SPink=CReset + '\033[0;35m'
    SCyan=CReset + '\033[0;36m'
    SWhite=CReset + '\033[0;37m'
    BBlack='\033[1;30m'
    BRed='\033[1;31m'
    BBlue='\033[1;34m'
    BYellow='\033[1;33m'
    BGreen='\033[1;32m'
    BPink='\033[1;35m'
    BCyan='\033[1;36m'
    BWhite='\033[1;37m'
    UBlack='\033[4;30m'
    URed='\033[4;31m'
    UGreen='\033[4;32m'
    UYellow='\033[4;33m'
    UBlue='\033[4;34m'
    UPink='\033[4;35m'
    UCyan='\033[4;36m'
    UWhite='\033[4;37m'
    BUBlack=CBold + '\033[4;30m'
    BURed=CBold + '\033[4;31m'
    BUGreen=CBold + '\033[4;32m'
    BUYellow=CBold + '\033[4;33m'
    BUBlue=CBold + '\033[4;34m'
    BUPink=CBold + '\033[4;35m'
    BUCyan=CBold + '\033[4;36m'
    BUWhite=CBold + '\033[4;37m'
    IGray='\033[0;90m'
    IRed='\033[0;91m'
    IGreen='\033[0;92m'
    IYellow='\033[0;93m'
    IBlue='\033[0;94m'
    IPink='\033[0;95m'
    ICyan='\033[0;96m'
    IWhite='\033[0;97m'
    BIGray='\033[1;90m'
    BIRed='\033[1;91m'
    BIGreen='\033[1;92m'
    BIYellow='\033[1;93m'
    BIBlue='\033[1;94m'
    BIPink='\033[1;95m'
    BICyan='\033[1;96m'
    BIWhite='\033[1;97m'
    BGBlack='\033[40m'
    BGRed='\033[41m'
    BGGreen='\033[42m'
    BGYellow='\033[43m'
    BGBlue='\033[44m'
    BGPink='\033[45m'
    BGCyan='\033[46m'
    BGWhite='\033[47m'
    BGIBlack='\033[100m'
    BGIRed='\033[101m'
    BGIGreen='\033[102m'
    BGIYellow='\033[103m'
    BGIBlue='\033[104m'
    BGIPink='\033[105m'
    BGICyan='\033[106m'
    BGIWhite='\033[107m'

def RemoveColor(InText):
    if InText!="":
        InText=InText.replace('\033[0m','')
        InText=InText.replace('\033[1m','')
        InText=InText.replace('\033[2m','')
        InText=InText.replace('\033[4m','')
        InText=InText.replace('\033[5m','')
        InText=InText.replace('\033[7m','')
        InText=InText.replace('\033[8m','')
        InText=InText.replace('\033[1;90m','')
        InText=InText.replace('\033[0;90m','')
        InText=InText.replace('\033[30m','')
        InText=InText.replace('\033[31m','')
        InText=InText.replace('\033[32m','')
        InText=InText.replace('\033[33m','')
        InText=InText.replace('\033[34m','')
        InText=InText.replace('\033[35m','')
        InText=InText.replace('\033[36m','')
        InText=InText.replace('\033[37m','')
        InText=InText.replace('\033[0;30m','')
        InText=InText.replace('\033[0;31m','')
        InText=InText.replace('\033[0;32m','')
        InText=InText.replace('\033[0;33m','')
        InText=InText.replace('\033[0;34m','')
        InText=InText.replace('\033[0;35m','')
        InText=InText.replace('\033[0;36m','')
        InText=InText.replace('\033[0;37m','')
        InText=InText.replace('\033[1;30m','')
        InText=InText.replace('\033[1;31m','')
        InText=InText.replace('\033[1;34m','')
        InText=InText.replace('\033[1;33m','')
        InText=InText.replace('\033[1;32m','')
        InText=InText.replace('\033[1;35m','')
        InText=InText.replace('\033[1;36m','')
        InText=InText.replace('\033[1;37m','')
        InText=InText.replace('\033[4;30m','')
        InText=InText.replace('\033[4;31m','')
        InText=InText.replace('\033[4;32m','')
        InText=InText.replace('\033[4;33m','')
        InText=InText.replace('\033[4;34m','')
        InText=InText.replace('\033[4;35m','')
        InText=InText.replace('\033[4;36m','')
        InText=InText.replace('\033[4;37m','')
        InText=InText.replace('\033[0;90m','')
        InText=InText.replace('\033[0;91m','')
        InText=InText.replace('\033[0;92m','')
        InText=InText.replace('\033[0;93m','')
        InText=InText.replace('\033[0;94m','')
        InText=InText.replace('\033[0;95m','')
        InText=InText.replace('\033[0;96m','')
        InText=InText.replace('\033[0;97m','')
        InText=InText.replace('\033[1;90m','')
        InText=InText.replace('\033[1;91m','')
        InText=InText.replace('\033[1;92m','')
        InText=InText.replace('\033[1;93m','')
        InText=InText.replace('\033[1;94m','')
        InText=InText.replace('\033[1;95m','')
        InText=InText.replace('\033[1;96m','')
        InText=InText.replace('\033[1;97m','')
        InText=InText.replace('\033[40m','')
        InText=InText.replace('\033[41m','')
        InText=InText.replace('\033[42m','')
        InText=InText.replace('\033[43m','')
        InText=InText.replace('\033[44m','')
        InText=InText.replace('\033[45m','')
        InText=InText.replace('\033[46m','')
        InText=InText.replace('\033[47m','')
        InText=InText.replace('\033[100m','')
        InText=InText.replace('\033[101m','')
        InText=InText.replace('\033[102m','')
        InText=InText.replace('\033[103m','')
        InText=InText.replace('\033[104m','')
        InText=InText.replace('\033[105m','')
        InText=InText.replace('\033[106m','')
        InText=InText.replace('\033[107m','')
    return InText;

def BeepSound():
    if __builtin__.ALERTSOUND=="Yes":
        sys.stdout.write("\a\r")
        sys.stdout.flush()

def read_a_key():
    stdinFileDesc = sys.stdin.fileno()
    oldStdinTtyAttr = termios.tcgetattr(stdinFileDesc)
    try:
        tty.setraw(stdinFileDesc)
        sys.stdin.read(1)
    finally:
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)

def CheckAdmin():
    if os.getuid() != 0:
        printc ("!!!",fcolor.BGreen + apptitle + " required administrator rights in order to run properly !","")
        printc ("!!!",fcolor.SGreen + "Log in as '" + fcolor.BRed + "root" + fcolor.SGreen + "' user or run '" + fcolor.BRed + "sudo ./" + __builtin__.ScriptName + fcolor.SGreen + "'","")
        exit_gracefully(1)
##--DropFile--##
##--FileName:Stn.DeAuth.py
###! /usr/bin/python
###############################################
#### This script is use as part of WAIDPS
#### Written By SY Chua, syworks@gmail.com
#### Written 15/04/2014 - Updated 25/04/2014
##import sys,os
##import time
##from datetime import datetime
##import termios,curses
##from math import floor
##import logging
##logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
##from scapy.all import *
##from waidps import *
##import __builtin__
##from waidps import AskQuestion
##__builtin__.Multicast=""
##__builtin__.DEAUTH=0
##__builtin__.DISASSOC=0
##__builtin__.ACK=0
##__builtin__.AUTH=0
##__builtin__.AUTH_BSSID=[]
##import subprocess, signal
##timefmt="%Y-%m-%d %H:%M:%S"
##__builtin__.DumpProc=""
##appdir="/SYWorks/WAIDPS/"
##tmpdir=appdir + "tmp/"
##__builtin__.Client_CSV=tmpdir + "Dumps-Client.csv"
##title=fcolor.BGreen + "Stn.DeAuth - V1.0, Written by SYChua (25/04/2014)"
##
##def TerminatingProc(ProcName):
##    pstr="kill $(ps aux | grep '" + str(ProcName) + "' | awk '{print $2}')"
##    ps=subprocess.Popen(pstr, shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
##
##def MonitoringPacket():
##    TerminatingProc(ProcTitle)
##    cmdLine="xterm -geometry 100x5-0-0 -iconic -bg black -fg white -fn 5x8 -title '" + str(ProcTitle) + "' -e 'tshark -i " + str(conf.iface) + " -a duration:60 -R 'wlan.addr==" + str(client) + "' -o column.format:'SA','%Cus:wlan.sa','DA','%Cus:wlan.da','BSSID','%Cus:wlan.bssid','TA','%Cus:wlan.ta','RA','%Cus:wlan.ra','FCSub','%Cus:wlan.fc.type_subtype' -n -l > " + str(tmpfile) + "'"
##    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
##    __builtin__.DumpProc=ps.pid
##    cttime=0
##
##def CheckProcess():
##    cmdLine="ps -eo pid | grep '" + str(__builtin__.DumpProc) + "'"
##    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
##    readout=str(ps.stdout.read().replace("\n",""))
##    readout=str(readout).lstrip().rstrip()
##    __builtin__.DumpProc=str(__builtin__.DumpProc)
##    if str(readout)!=str(__builtin__.DumpProc):
##        MonitoringPacket()
##
##def Percent(val, digits):
##    val *= 10 ** (digits + 2)
##    return '{1:.{0}f} %'.format(digits, floor(val) / 10 ** digits)
##
##def GiveClientResult(MACAddr):
##    if os.path.isfile(__builtin__.Client_CSV)==True:
##        with open(__builtin__.Client_CSV,"r") as f:
##            for line in f:
##                line=line.replace("\n","").replace("\00","").replace("\r","")
##                if len(line)>=94:
##                    line=line + ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
##                    st = list(line)
##                    st[18]=";";st[39]=";";st[60]=";";st[65]=";";st[75]=";";st[94]=";";lp="".join(st)
##                    lp=lp.replace(",;","; ")
##                    LineList=lp.split(";")
##                    STATION=LineList[0]
##                    cBSSID=LineList[5]
##                    if len(STATION)==17 and len(cBSSID)==17:
##                        if STATION==str(MACAddr) and CheckMAC(cBSSID!=""):
##                            BSSIDList.append (cBSSID)
##                        if cBSSID==str(MACAddr) and CheckMAC(STATION!=""):
##                            BSSIDList.append (STATION)
##                    if len(STATION)==17 and MACAddr==STATION and str(line).find("(not associated)")!=-1:
##                        BSSIDList=[]
##                        print fcolor.SGreen + str(time.strftime(timefmt)) + " - " + fcolor.BBlue + "Detected [ " + fcolor.BRed + str(STATION) + fcolor.BBlue + " ] ==> Not Associated"
##
##def ReadCaptured():
##    if os.path.isfile(tmpfile)==True:
##        with open(tmpfile,"r") as f:
##            for line in f:
##                line=line.replace("\n","").upper().replace("\x00","")
##                lines=line.split(" ")
##                x=0
##                if len(lines)>5 and str(lines[5]).find("PROBE")==-1:
##                    if str(lines[5]).find("DEAUTHENTICATION")!=-1:
##                        __builtin__.DEAUTH=__builtin__.DEAUTH+1
##                    if str(lines[5]).find("DISASSOCIATE")!=-1:
##                        __builtin__.DISASSOC=__builtin__.DISASSOC+1
##                    if str(lines[5]).find("ACKNOWLEDGEMENT")!=-1 and str(lines[4]).find(client)!=-1:
##                        __builtin__.ACK=__builtin__.ACK+1
##                    if str(lines[5])=="AUTHENTICATION" or str(lines[5])=="ASSOCIATION":
##                        __builtin__.AUTH=__builtin__.AUTH+1
##                        if lines[2]!="" and len(lines[2])==17 and str(__builtin__.AUTH_BSSID).find(lines[2])==-1 and CheckMAC(lines[2])!="" and lines[2]!=client:
##                            __builtin__.AUTH_BSSID.append (str(lines[2]))
##                    while x<5:
##                        lines[x]=str(lines[x]).replace("\x00","")
##                        if len(lines[x])==17 and str(BSSIDList).find(lines[x])==-1 and lines[x]!=client:
##                            if str(lines[x])[:6]=="33:33:"  or str(lines[x])[:9]=="01:00:5E:":
##                                __builtin__.Multicast="   [ Multicast Detected ]"
##                            elif str(lines[x])[:6]=="FF:FF:" and x!=2:
##                                __builtin__.Multicast="   [ Broadcast Detected ]"
##                            else:
##                                if CheckMAC(lines[x])!="":
##                                    if str(lines[5]).find("DEAUTHENTICATION")==-1 and str(lines[5]).find("DISASSOCIATE")==-1 and str(lines[5]).find("ACKNOWLEDGEMENT")==-1:
##                                        BSSIDList.append (lines[x])
##                        x += 1
##        open(tmpfile,"w").write("")
##    GiveClientResult(client)
##    x=0
##if len(sys.argv) !=5:
##    print title
##    print fcolor.SWhite + "Not for External use\n"
##    print "Usage\t: ./" + os.path.basename(__file__) + '<conf.iface> <stn_mac> <loopcount> <sleeptime>'
##    print "Example\t: ./" + os.path.basename(__file__) + 'mon0 00:11:22:33:44:55 99999 2\n'
##    sys.exit(1)
##else:
##    conf.iface = sys.argv[1] 
##    client = str(sys.argv[2]).upper()
##    count = sys.argv[3]
##    sleeptime = int(sys.argv[4])
##    bssid=""
##ProcTitle="WIPS - Monitoring MAC " + str(client)
##conf.verb = 0
##tmpdir="/SYWorks/WAIDPS/tmp/"
##tmpfile=tmpdir + "StnDeauth_" + str(client).replace(":","")
##TerminatingProc(ProcTitle)
##print title
##BSSIDList=[]
##
##def CheckMAC(MACAddr):
##    MACAddr=str(MACAddr).upper().lstrip().rstrip()
##    rMAC=MACAddr
##    if len(MACAddr)==17:
##        if MACAddr[:6]=="FF:FF:":
##            rMAC=""
##        if MACAddr[:6]=="33:33:":
##            rMAC=""
##        if MACAddr[:9]=="01:80:C2:":
##            rMAC=""
##        if MACAddr[:9]=="01:00:5E:":
##            rMAC=""
##        if str(BSSIDList).find(MACAddr)!=-1:
##            rMAC=""
##    return rMAC
##
##def printl (DisplayText,ContinueBack,PrevIconCount):
##    icolor=fcolor.BGreen
##    bcolor=fcolor.SWhite
##    if ContinueBack=="0":
##        curses.setupterm()
##        TWidth=curses.tigetnum('cols')
##        TWidth=TWidth-1
##        sys.stdout.write("\r")
##        sys.stdout.flush()
##        sys.stdout.write (" " * TWidth + "\r")
##        sys.stdout.flush()
##        sys.stdout.write(DisplayText)
##        sys.stdout.flush()
##    return str(PrevIconCount);
##if os.path.isfile(tmpfile)==True:
##    os.remove(tmpfile)
##MonitoringPacket()
##cttime=0
##print ""
##for n in range(int(count)):
##    client=str(client).upper().lstrip().rstrip()
##    bssid=str(bssid).upper().lstrip().rstrip()
##    __builtin__.Multicast="";__builtin__.DEAUTH=0;__builtin__.DISASSOC=0;__builtin__.ACK=0;__builtin__.AUTH=0;__builtin__.AUTH_BSSID=[]
##    ReadCaptured()
##    if len(BSSIDList)==0:
##        timenow=fcolor.SGreen + str(time.strftime(timefmt))
##        y=0
##        while y<30:
##            printl (timenow  + " - Monitoring... wait for " + str(30-int(y)) +" seconds..","0","")
##            time.sleep(1)
##            cttime=int(cttime) + 1
##            CheckProcess()
##            statinfo = os.stat(tmpfile)
##            if statinfo.st_size!=0:
##                y=30
##                printl ("","0","")
##                ReadCaptured()
##            y += 1
##    if int(__builtin__.AUTH)>0:
##        y=0;AuthBSSID=""
##        while y<len(__builtin__.AUTH_BSSID):
##            AuthBSSID=AuthBSSID + __builtin__.AUTH_BSSID[y] + " / "
##            y += 1
##        AuthBSSID=str(AuthBSSID[:-3]).replace("/",fcolor.SWhite + "/" + fcolor.BRed)
##        print fcolor.SGreen + str(time.strftime(timefmt)) + " - " + fcolor.BBlue + "Authenticating/Associating Found- BSSID [ " + fcolor.BYellow + str(AuthBSSID) + fcolor.BBlue + " ] "
##        __builtin__.AUTH_BSSID=[]
##    x=0
##    while x<len(BSSIDList):
##        bssid=BSSIDList[x]
##        SUCCESSRESULT1="Deauth/Disassoc : " + str(__builtin__.DEAUTH) + " / " + str(__builtin__.DISASSOC)
##        SUCCESSRESULT=SUCCESSRESULT1.ljust(36) + "Ack : " + fcolor.SCyan + str(__builtin__.ACK).ljust(28)
##        SUCCESSRESULT=str(SUCCESSRESULT).replace(" / ", fcolor.SWhite + " / " + fcolor.SRed).replace("Ack",fcolor.SWhite + "Ack").replace(":",":" + fcolor.SRed)
##        print fcolor.SGreen + str(time.strftime(timefmt)) + " - Disassociating/Deauthenticating Station [ " + fcolor.BRed + str(client) + fcolor.SGreen + " ] from BSSID [ " + fcolor.BYellow + bssid + fcolor.SGreen + "  ]"
##        print "\t\t      " + fcolor.SWhite + str(SUCCESSRESULT) + "" + fcolor.SWhite + str(__builtin__.Multicast) + ""
##        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
##        packet2 = RadioTap()/Dot11(addr1=bssid,addr2=client,addr3=client)/Dot11Deauth(reason=3)
##        packet3 = RadioTap()/Dot11(addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=3)
##        packet4 = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Disas(reason=7)
##        packet5 = RadioTap()/Dot11(addr1=bssid,addr2=client,addr3=client)/Dot11Disas(reason=7)
##        packet6 = RadioTap()/Dot11(addr1=client,addr2=bssid,addr3=bssid)/Dot11Disas(reason=3)
##        y=0
##        TerminatingProc('Deauth with Aireplay-NG')
##        cmdLine="xterm -geometry 100x5-0-0 -iconic -bg black -fg white -fn 5x8 -title 'Deauth with Aireplay-NG' -e 'aireplay-ng -0 10 " + str(conf.iface) + " -a " + str(bssid) + " -c " + str(client) + "'"
##        ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
##        while y<30:
##            completed=Percent(float(y)/30,2)
##            printl ("\t\t      " + fcolor.SRed + "Sending Deauth/Disassoc - " + fcolor.SRed + str(completed) + fcolor.SRed + "" ,"0","")
##            sendp(packet,verbose=0)
##            sendp(packet2,verbose=0)
##            sendp(packet3,verbose=0)
##            sendp(packet4,verbose=0)
##            sendp(packet5,verbose=0)
##            sendp(packet6,verbose=0)
##            time.sleep(0.1)
##            y=y+1
##        printl ("" ,"0","")
##        print ""
##        cttime=int(cttime) + int(sleeptime)
##        time.sleep(sleeptime)
##        __builtin__.Multicast="";__builtin__.DEAUTH=0;__builtin__.DISASSOC=0;__builtin__.ACK=0;__builtin__.AUTH=0;__builtin__.AUTH_BSSID=[]
##        x += 1
##    if int(cttime)>=20:
##        MonitoringPacket()
##exit(0)
##--EndFile--##
##--StopRead--##

def DropFiles():
    with open(__builtin__.ScriptFullPath,"r") as f:
        READSTATUS=""
        for line in f:
            line=line.replace("\n","")
            if line!="":
                if line=="##--DropFile--##":
                    READSTATUS="START"
                if line=="##--EndFile--##":
                    READSTATUS=""
                    shutil.copy2(appdir + DropFileName, "/usr/sbin/" + str(DropFileName))
                    result=os.system("chmod +x /usr/sbin/" + DropFileName + " > /dev/null 2>&1")
                    result=os.system("chmod +x " + appdir + DropFileName + " > /dev/null 2>&1")
                if line=="##--StopRead--##":
                    return;
                if READSTATUS=="WRITE":
                    open(appdir + DropFileName,"a+b").write(line[2:] + "\n")
                if READSTATUS=="START" and len(line)>15 and str(line)[:13]=="##--FileName:":
                    DropFileName=str(line)[13:]
                    DropFileName=DropFileName
                    open(appdir + DropFileName,"w").write("")
                    READSTATUS="WRITE"

def AboutApplication():
    os.system('clear')
    WordColor=fcolor.BCyan
    print fcolor.BGreen + "db   d8b   db  .d8b.  d888888b d8888b. d8888b. .d8888." 
    print fcolor.BGreen + "88   I8I   88 d8' `8b   `88'   88  `8D 88  `8D 88'  YP" 
    print fcolor.BGreen + "88   I8I   88 88ooo88    88    88   88 88oodD' `8bo.  " 
    print fcolor.BGreen + "Y8   I8I   88 88~~~88    88    88   88 88~~~     `Y8b." 
    print fcolor.BGreen + "`8b d8'8b d8' 88   88   .88.   88  .8D 88      db   8D" 
    print fcolor.BGreen + " `8b8' `8d8'  YP   YP Y888888P Y8888D' 88      `8888Y'"
    ShowSYWorks()
    print "";print ""
    print fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc
    print fcolor.CReset + fcolor.White + appnote
    print ""
    DisplayDescription()
    print ""
    print fcolor.BWhite + "Fans Page - " + fcolor.BBlue + "https://www.facebook.com/syworks" +fcolor.BWhite + " (SYWorks-Programming)"
    print fcolor.BWhite + "Tutorial  - " + fcolor.BBlue + "https://syworks.blogspot.com/" +fcolor.BWhite + ""
    print "";print ""
    printc ("x",fcolor.BRed + "Press a key to continue...","")
    LineBreak()

def LineBreak():
    DrawLine("_",fcolor.CReset + fcolor.Black,"","");print "";

def OptDisplayLogs():
    printc ("+", fcolor.BBlue + "Displaying Active Logs History","")
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "C" + StdColor + " - Association/" + SelColor + "C" + StdColor + "onnection Alert Log\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - Display " + SelColor + "S" + StdColor + "uspicious Activity Listing\n"
    Option3 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - Display " + SelColor + "A" + StdColor + "ttacks Log\n"
    Option4 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "L" + StdColor + " - Display Combination " + SelColor + "L" + StdColor + "ogs\n"
    OptionA=Option1 + Option2 + Option3 + Option4  
    print OptionA
    usr_resp=AskQuestion("Select a type of log / " + STxt + "R" + NTxt + "eturn","","U","RETURN","1")
    if usr_resp=="C" or usr_resp=="1":
        if __builtin__.MSG_HistoryConnection!="":
            print ""
            printc ("i", "Connection Cautious Information History", "")
            print __builtin__.MSG_HistoryConnection
            LineBreak()
            printc ("x","","")
        else:
            print ""
            printc ("!!!", "Connection Cautious Information History Not Found", "")
            printc ("x","","")
    if usr_resp=="S" or usr_resp=="2":
        if __builtin__.MSG_SuspiciousListing!="":
            print ""
            printc ("i", "Suspicious Listing Information History", "")
            print __builtin__.MSG_SuspiciousListing
            LineBreak()
            printc ("x","","")
        else:
            print ""
            printc ("!!!", "Suspicious Listing Information History Not Found", "")
            printc ("x","","")
    if usr_resp=="A" or usr_resp=="3":
        if __builtin__.MSG_AttacksLogging!="":
            print ""
            printc ("i", "Attacks Information History", "")
            print __builtin__.MSG_AttacksLogging
            LineBreak()
            printc ("x","","")
        else:
            print ""
            printc ("!!!", "Attacks Information History Not Found", "")
            printc ("x","","")
    if usr_resp=="L" or usr_resp=="4":
        if __builtin__.MSG_CombinationLogs!="":
            print ""
            printc ("i", "Combination Log History", "")
            print __builtin__.MSG_CombinationLogs
            LineBreak()
            printc ("x","","")
        else:
            print ""
            printc ("!!!", "Combination Log History Not Found", "")
            printc ("x","","")

def GetOptionCommands(HeaderLine):
    RefreshAutoComplete("")
    if HeaderLine!="":
        LineBreak()
    printc ("+", fcolor.BBlue + "Command Selection Menu ","")
    __builtin__.CURRENT_LOC="MENU"
    Option1 = SelBColor + "B" + StdColor + " - A" + SelColor + "b" + StdColor + "out Application\t\t"
    Option2 = SelBColor + "C" + StdColor + " - Application " + SelColor + "C" + StdColor + "onfiguation\t\t    "
    Option3 = SelBColor + "D" + StdColor + " - Output " + SelColor + "D" + StdColor + "isplay\t\t\t\t"
    Option4 = SelBColor + "F" + StdColor + " - " + SelColor + "F" + StdColor + "ilter Network Display\t\t"
    OptionA=Option1 + Option2 + Option3 + Option4
    Option1 = SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "istory Logs\t\t\t"
    Option2 = SelBColor + "L" + StdColor + " - " + SelColor + "L" + StdColor + "ookup MAC/Name Detail\t\t    "
    Option3 = SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "onitor MAC Addr / Names\t\t"
    Option4 = SelBColor + "O" + StdColor + " - " + SelColor + "O" + StdColor + "peration Options\t\t\t"
    OptionB=Option1 + Option2 + Option3 + Option4
    Option1 = SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "uditing Network\t\t"
    Option2 = SelBColor + "I" + StdColor + " - " + SelColor + "I" + StdColor + "nteractive Mode (Packet Analysis)\t    "
    Option3 = SelBColor + "P" + StdColor + " - Intrusion " + SelColor + "P" + StdColor + "revention\t\t\t"
    Option4 = SelBColor + "X" + StdColor + " - E" + SelColor + "x" + StdColor + "it Application\t"
    OptionC=Option1 + Option2 + Option3 + Option4
    printc (" ", fcolor.BYellow + OptionA,"")
    printc (" ", fcolor.BYellow + OptionB,"")
    printc (" ", fcolor.BYellow + OptionC,"")
    print ""
    usr_resp=AskQuestion("Enter your option : ",fcolor.SWhite + "<default = return>","U","RETURN","1")
    LineBreak()
    if usr_resp=="RETURN":
        return;
    if usr_resp=="RESET":
        ResetInterface("1")
        LineBreak()
        return;
    if usr_resp=="MYMAC":
        DisplayMyMAC()
        LineBreak()
        return;
    if usr_resp=="A":
        printc ("+", fcolor.BBlue + "Wireless Auditing Menu","")
        print tabspacefull + StdColor + "This option will be included in future release.";print ""
        LineBreak()
        return
    if usr_resp=="X":
        usr_resp=AskQuestion(fcolor.SRed + "Are you sure you want to exit" + fcolor.BGreen,"y/N","U","N","1")
        LineBreak()
        if usr_resp=="Y":
            exit_gracefully(0)
        return;
    if usr_resp=="B":
        AboutApplication()
        DisplayPanel()
        return
    if usr_resp=="I":
        PacketAnalysis()
        return
    if usr_resp=="P":
        ShowIntrusionPrevention("1")
        LineBreak()
        return
    if usr_resp=="O":
        RR=OptControls("")
        LineBreak()
        if RR=="TIME0":
            return RR
    if usr_resp=="D":
        OptOutputDisplay("")
        SaveConfig("")
        GetOptionCommands("")
        return;
    if usr_resp=="F":
        OptFilterDisplay("");LineBreak();return;
    if usr_resp=="C":
        OptConfiguration("")
        SaveConfig("");LineBreak();return;
    if usr_resp=="M":
        OptMonitorMAC("");LineBreak();return;
    if usr_resp=="L":
        OptInfoDisplay("","1");LineBreak();return;
    if usr_resp=="H":
        OptDisplayLogs();LineBreak();return;
    return;

def WaitingCommands(Timer=0, ShowDisplay=1):
    usr_resp=""
    if Timer==0:
        if ShowDisplay==1:
            printl(fcolor.SGreen + "Press " + fcolor.BGreen + "Ctrl+C" + fcolor.SGreen + " to break..","0","")
        stdinFileDesc = sys.stdin.fileno()
        oldStdinTtyAttr = termios.tcgetattr(stdinFileDesc)
        tty.setraw(stdinFileDesc)
        usr_resp=sys.stdin.read(1)
        termios.tcsetattr(stdinFileDesc, termios.TCSADRAIN, oldStdinTtyAttr)
        if usr_resp=="\x03":
            printc (" ", fcolor.BRed + "\nInterrupted !!","")
            Result=AskQuestion("Yes or No, Null as 'N' (Lower casing)","y/N","U","N","1")
            if Result=="Y":
                return "Break"
            return ""
        if usr_resp=="\x0d":
            printc (" ", fcolor.BRed + "\nInterrupted - Enter Command !!","")
            return "";
 
        if usr_resp=="a":
            printc(" ","A pressed","")
        else:
            return ""
    else:
        try:
            t=int(Timer)
            bcolor=fcolor.SWhite
            pcolor=fcolor.BGreen
            tcolor=fcolor.SGreen
            PrintText2=""
            if __builtin__.LOAD_IWLIST=="Yes":
                RunIWList()
            PrintText="Refreshing in " + str(Timer) + " seconds... Press " + fcolor.BYellow + "[Enter]" + fcolor.SGreen + " to input command... "
            while t!=0:
                FS=""
                if IsFileDirExist(__builtin__.PacketDumpFile)=="F":
                    GetFileDetail(__builtin__.PacketDumpFile)
                    FS=fcolor.SWhite + " Pkt Size : " + str(__builtin__.FileSize) 
                
                s=bcolor + "[" + pcolor + str(t) + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + str(FS) + "\r"
                s=s.replace("%s",pcolor+str(PrintText2)+tcolor)
                sl=len(s)
                print s,
                sys.stdout.flush()
                time.sleep(1)
                s=""
                ss="\r"
                print "" + s.ljust(sl+2) + ss,
                sys.stdout.flush()
                t=t-1
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    usr_resp = sys.stdin.readline()
                    if usr_resp:
                        RR=GetOptionCommands("1")
                        if RR=="TIME0":
                            t=0
                c1=bcolor + "[" + pcolor + "-" + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
                c1=c1.replace("%s",pcolor+str(PrintText2)+tcolor)
                print c1,
                sys.stdout.flush()
        except KeyboardInterrupt:
            printc (" ", fcolor.BRed + "\nInterrupted !!","")
            Result=AskQuestion(fcolor.SRed + "Are you sure you want to exit"+ fcolor.BGreen,"y/N","U","N","1")
            if Result=="Y":
                exit_gracefully(0)
            else:
                return "";

def DisplayClientDetail(DisplayTitle,DataList):
    tmpList = []
    CenterText(fcolor.BBlue, DisplayTitle + "     ")
    DrawLine("~",fcolor.CReset + fcolor.Black,"",""); print ""
    tmpList=DataList
    x=0
    RecordNum=0
    StnColor=fcolor.SGreen
    while x<len(DataList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        n=int(DataList[x])
        StnMAC=ListInfo_STATION[n]
        DataValue0 = StnColor + "Client Number   : " + fcolor.SRed + str(RecordNum)  + "\n"
        DataValue1= StnColor + "STATION MAC ID  : " + fcolor.SYellow + str(StnMAC).ljust(40) + StnColor + "Vendor      : " + fcolor.SCyan + str(__builtin__.ListInfo_COUI[n]) + "\n"    
        SignalRange=str(ListInfo_CBestQuality[n]) + " dBm" + StnColor + fcolor.CBold + " ["  + str(ListInfo_CQualityRange[n])  + StnColor + fcolor.CBold + "]" 
        DataValue2 = StnColor + "Power/Range     : " + StdColor + str(SignalRange) + "\t\t\t  " + StnColor + "Packets     : " + StdColor + str(ListInfo_CPackets[n]).ljust(41) + StnColor + "Standard    : " + StdColor + str(ListInfo_STNStandard[n])  + "\n"
        DataValue3 = StnColor + "First Time Seen : " + StdColor + str(ListInfo_CFirstSeen[n]).ljust(40) + StnColor + "Last Seen   : " + StdColor + str(ListInfo_CLastSeen[n]).ljust(41) + StnColor + "Duration    : " + StdColor + str(ListInfo_CElapse[n]) +"\n"
        if str(ListInfo_PROBE[n])!="":
            Probes=ListInfo_PROBE[n]
            Probes=str(Probes).replace(" / ",StnColor + " | " + StdColor)
            DataValue4 = StnColor + "Probes          : " + fcolor.SBlue + str(Probes) +"\n"
        AssocHistory=str(ListInfo_CBSSIDPrevList[n])
        AssocHistory=str(AssocHistory).replace("| Not Associated | ","").replace("Not Associated | ","").replace("  "," ").replace("|",StnColor + "|" + StdColor)
        DataValue5 = StnColor + "ESSID Connected : " + StdColor + str(ListInfo_CESSID[n]).ljust(40) + StnColor + "Last Active : " + StdColor + str(ListInfo_CTimeGapFull[n]) + StnColor + " - [ " + StdColor + str(ListInfo_CTimeGap[n]) + StnColor + " min ago ]" + "\n"
        DataValue6 = StnColor + "Connect History : " + StdColor + str(AssocHistory) +"\n"
        DataValue7=""
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  
        print DataValue
        DisplayMACDetailFromFiles(StnMAC)
        x += 1

def RemoveUnwantMAC(MACAddr):
    sMAC=[]
    sMAC=MACAddr.split("/")
    ax=0
    lsMAC=len(sMAC)
    while ax<lsMAC:
        MAC_ADR=sMAC[ax]
        MAC_ADR=MAC_ADR.lstrip().rstrip()
        sMAC[ax]=MAC_ADR
        if MAC_ADR[:17]=="XX:XX:XX:XX:XX:XX":
            sMAC[ax]=""
        if MAC_ADR[:12]=="FF:FF:FF:FF:":
            sMAC[ax]=""
        if MAC_ADR[:6]=="33:33:":
            sMAC[ax]=""
        if MAC_ADR[:9]=="01:80:C2:":
            sMAC[ax]=""
        if MAC_ADR[:9]=="01:00:5E:":
            sMAC[ax]=""
        if MAC_ADR[:3]=="FF:":
            sMAC[ax]=""
        if MAC_ADR==str(__builtin__.SELECTED_MON_MAC):
            sMAC[ax]=""
        if MAC_ADR==str(__builtin__.SELECTED_MANIFACE_MAC):
            sMAC[ax]=""
        if MAC_ADR==str(__builtin__.SELECTED_IFACE_MAC):
            sMAC[ax]=""
        ax=ax+1
    ax=0
    NewMAC=""
    while ax<len(sMAC):
        if sMAC[ax]!="":
            NewMAC=NewMAC + str(sMAC[ax]) + " / "
        ax=ax+1
    if NewMAC[-3:]==" / ":
        NewMAC=NewMAC[:-3]
    return NewMAC

def DisplayBSSIDDetail():
    CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED ACCESS POINT LISTING [ " + str(len(__builtin__.ShowBSSIDList)) + " ]")
    RecordNum=0
    i=0
    while i < len(__builtin__.ShowBSSIDList):
        RecordNum += 1
        n=__builtin__.ShowBSSIDList[i]
        ESSID=str(ListInfo_ESSID[n])
        BSSID=str(ListInfo_BSSID[n])
        DBSSID=str(BSSID).ljust(40)
        DESSID=str(ESSID).ljust(95)
        if ESSID=="":
            DESSID=fcolor.SBlack + "<<NO NAME>>" + str(DESSID)[11:]
        DataValue1= lblColor + "AP MAC  [BSSID] : " + fcolor.BYellow + str(DBSSID) + lblColor + "Vendor      : " + VendorColor + str(ListInfo_BSSID_OUI[n]) + "\n"
        QualityRange=str(ListInfo_Quality[n])
        if QualityRange!="-":
            QualityRange=lblColor + " - " + StdColor + str(QualityRange)
        else:
            QualityRange=""
        SignalRange=str(ListInfo_BestQuality[n]) + " dBm" + lblColor + fcolor.CBold + " ["  + str(ListInfo_QualityRange[n])  + lblColor + "]"  + str(QualityRange)
        DataValue2 = lblColor + "AP Name [ESSID] : " + fcolor.BPink + str(DESSID) + lblColor + "Power       : " + StdColor + str(SignalRange) + "\n"                 # + lblColor + "Signal  : " + StdColor + str(ListInfo_BestSignal[n]).ljust(15) + lblColor + "Noise  : " + StdColor + str(ListInfo_BestNoise[n]) + "\n"
        Privacy=str(ListInfo_Privacy[n]) + " / " + str(ListInfo_Cipher[n]) + " / " + str(ListInfo_Auth[n])
        DataValue3 = lblColor + "Encryption Type : " + StdColor + Privacy.ljust(40) + lblColor + "Beacon      : " + StdColor + str(ListInfo_Beacon[n]).ljust(15) + lblColor + "Data     : " + StdColor + str(ListInfo_Data[n]).ljust(15) + lblColor + "Total Data  : " + StdColor + str(ListInfo_Total[n]) + "\n"
        MaxRate=str(ListInfo_MaxRate[n]) + " Mb/s"
        ChannelFreq=str(ListInfo_Channel[n]) + " / " + str(ListInfo_Freq[n]) + " GHz"
        LastBeacon=str(ListInfo_LastBeacon[n])
        if LastBeacon!="-" and LastBeacon!="":
            LastBeacon = LastBeacon + " ago"
        LastBeacon=str(LastBeacon).ljust(41)
        DataValue4 = lblColor + "Channel / Freq. : " + StdColor + str(ChannelFreq).ljust(40) + lblColor + "Max. Rate   : " + StdColor + str(MaxRate).ljust(15) + lblColor + "Cloaked? : " + StdColor + str(ListInfo_Cloaked[n]).ljust(15) + lblColor  + "Mode        : " + StdColor + str(ListInfo_Mode[n]) + "\n"
        GPSLoc=str(ListInfo_GPSBestLat[n]) + " / " + str(ListInfo_GPSBestLon[n])
        BitRate=ListInfo_BitRate[n].replace("|",lblColor + "|" + StdColor)
        DataValue5 = lblColor + "Bit Rates       : " + StdColor + str(BitRate) + "\n"
        DataValue6 = lblColor + "Extended S.Set  : " + StdColor + str(ListInfo_ESS[n]) + "\t\t\t\t\t  " + lblColor + "Standard    : " + StdColor + str(ListInfo_APStandard[n]) + "\n"
        DataValue7 = lblColor + "GPS Lat/Long    : " + StdColor + GPSLoc.ljust(40) + lblColor + "Last Beacon : " + StdColor + str(LastBeacon) + lblColor + "Last Active : " + StdColor + str(ListInfo_SSIDTimeGapFull[n]) + lblColor + " - [ " + StdColor + str(ListInfo_SSIDTimeGap[n]) + lblColor + " min ago ]" + "\n"
        DataValue8 = lblColor + "First Time Seen : " + StdColor + str(ListInfo_FirstSeen[n]).ljust(40) + lblColor + "Last Seen   : " + StdColor + str(ListInfo_LastSeen[n]).ljust(41) + lblColor + "Duration    : " + StdColor + str(ListInfo_SSIDElapse[n]) +"\n"
        Cipher=""
        if __builtin__.ListInfo_PairwiseCipher[n]!="-":
            Cipher=Cipher + __builtin__.ListInfo_PairwiseCipher[n] + " (Pairwise) / "
        if __builtin__.ListInfo_GroupCipher[n]!="-":
            Cipher=Cipher + __builtin__.ListInfo_GroupCipher[n] + " (Group) / "
        if Cipher=="":
            Cipher="-"
        else:
            if Cipher[-3:]==" / ":
                Cipher=Cipher[:-3]
        Cipher=str(str(Cipher).ljust(41)).replace("/",lblColor + "/" + StdColor)
        DataValue9=""
        if str(ListInfo_Privacy[n]).find("WPA")!=-1:
            if str(ListInfo_WPAVer[n])!="-" or str(ListInfo_AuthSuite[n])!="-" or str(ListInfo_PairwiseCipher[n])!="-" or str(ListInfo_GroupCipher[n])!="-":
                DataValue9 = lblColor + "WPA Information : " + StdColor + str(ListInfo_WPAVer[n]).ljust(40) + lblColor + "Cipher      : " + StdColor + str(Cipher) + lblColor + "Auth        : " + StdColor + str(ListInfo_AuthSuite[n]) + "\n"
        if ListInfo_ConnectedClient[n]=="" or ListInfo_ConnectedClient[n]=="0":
            ClientText="No client associated"
        else:
            ClientText=ListInfo_ConnectedClient[n]
        WPSInfo="Not Enabled"
        if ListInfo_WPS[n]!="-":
            WPSLock=""
            if ListInfo_WPSLock[n]!="No":
                WPSLock=lblColor + " / " + StdColor + "Locked"
            WPSInfo=ListInfo_WPS[n] + lblColor + " / Ver : " + StdColor + ListInfo_WPSVer[n] + WPSLock
        DataValue10 = lblColor + "Connected Client: " + StdColor + str(ClientText).ljust(40) + lblColor + "WPS Enabled : " + StdColor + str(WPSInfo) + "\n"
        k=0
        ConnectedClient= []
        PrevConnectedClient= []
        UnassociatedClient= []
        while k < len(__builtin__.ListInfo_STATION):
            if __builtin__.ListInfo_CBSSID[k]==BSSID:
                ConnectedClient.append (str(k))
            if str(__builtin__.ListInfo_CBSSIDPrevList[k]).find(BSSID)!=-1 and str(__builtin__.ListInfo_CBSSID[k])!=BSSID:
                if __builtin__.ListInfo_CBSSID[k]!=BSSID:
                    PrevConnectedClient.append (str(k))
            if ESSID!="" and __builtin__.ListInfo_PROBE[k].find(ESSID)!=-1 and __builtin__.ListInfo_CBSSID[k]!=BSSID:
                UnassociatedClient.append (str(k))
            k += 1
        DataValue11=""
        DataValue12=""
        if len(UnassociatedClient)>0:
            DataValue11 = lblColor + "Unassociated    : " + StdColor + str(len(UnassociatedClient)) + " station which is not associated with Access Point but probing for " + fcolor.BPink + str(ESSID) + "\n"
        if len(PrevConnectedClient)>0:
            DataValue12 = lblColor + "Prev. Connection: " + StdColor + str(len(PrevConnectedClient)) + "\n"
        RecNo=str(RecordNum)
        if str(ListInfo_Enriched[n])!="":
            RecNo=RecNo + " *"
        RecNo=str(str(RecNo).ljust(40)).replace(" *",fcolor.SCyan + " *")
        RecType=""
        if str(__builtin__.ListInfo_STATION).find(BSSID)!=-1:
            RecType=fcolor.BRed + "The MAC Address is detected to be both an Access Point & Station"
        CenterText(fcolor.BBlack + fcolor.BGWhite, "MAC ADDRESS [ " + str(BSSID) + "] DETAILED INFORMATION - RECORD " + str(RecordNum) + "/" + str(len(__builtin__.ShowBSSIDList)))
        print ""
        DataValue0 = lblColor + "Access Point No.: " + fcolor.BRed + str(RecNo) + str(RecType) + "\n"
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8 + DataValue9 + DataValue10 + DataValue11 + DataValue11
        print DataValue
        DisplayMACDetailFromFiles(BSSID)
        if len(ConnectedClient)>0:
            DisplayClientDetail("Associated Client",ConnectedClient)
        if len(PrevConnectedClient)>0:
            DisplayClientDetail("Clients Previously Connected To Access Point",PrevConnectedClient)
        if len(UnassociatedClient)>0:
            DisplayClientDetail("Unassociated Client Probing For SSID [" + str(ESSID) + "]",UnassociatedClient)
        i += 1
    return

def DisplayConnectedBSSID(DisplayTitle,DataList):
    CenterText(fcolor.BPink, DisplayTitle + "     ")
    DrawLine("~",fcolor.CReset + fcolor.Black,"",""); print ""
    tmpList=DataList
    x=0
    RecordNum=0
    APColor=fcolor.SGreen
    while x<len(DataList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        APMAC=DataList[x]
        if len(APMAC)==17:
            APLoc=str(ListInfo_BSSID).find(str(APMAC))
            n=int(APLoc) -2
            n=n/21
            ESSID=str(ListInfo_ESSID[n])
            BSSID=str(ListInfo_BSSID[n])
            DBSSID=str(BSSID).ljust(40)
            DESSID=str(ESSID).ljust(95)
            if ESSID=="":
                DESSID=fcolor.SBlack + "<<NO NAME>>" + str(DESSID)[11:]
            DataValue1= APColor + "AP MAC  [BSSID] : " + fcolor.SYellow + str(DBSSID) + APColor + "Vendor      : " + fcolor.SCyan + str(ListInfo_BSSID_OUI[n]) + "\n"
            QualityRange=str(ListInfo_Quality[n])
            if QualityRange!="-":
                QualityRange=APColor + " - " + StdColor + str(QualityRange)
            else:
                QualityRange=""
            SignalRange=str(ListInfo_BestQuality[n]) + " dBm" + APColor + " ["  + str(ListInfo_QualityRange[n])  + APColor + "]"  + str(QualityRange)
            DataValue2 = APColor + "AP Name [ESSID] : " + fcolor.SPink + str(DESSID) + APColor + "Power       : " + StdColor + str(SignalRange) + "\n"                 # + APColor + "Signal  : " + StdColor + str(ListInfo_BestSignal[n]).ljust(15) + APColor + "Noise  : " + StdColor + str(ListInfo_BestNoise[n]) + "\n"
            Privacy=str(ListInfo_Privacy[n]) + " / " + str(ListInfo_Cipher[n]) + " / " + str(ListInfo_Auth[n])
            DataValue3 = APColor + "Encryption Type : " + StdColor + Privacy.ljust(40) + APColor + "Beacon      : " + StdColor + str(ListInfo_Beacon[n]).ljust(15) + APColor + "Data     : " + StdColor + str(ListInfo_Data[n]).ljust(15) + APColor + "Total Data  : " + StdColor + str(ListInfo_Total[n]) + "\n"
            MaxRate=str(ListInfo_MaxRate[n]) + " Mb/s"
            ChannelFreq=str(ListInfo_Channel[n]) + " / " + str(ListInfo_Freq[n]) + " GHz"
            LastBeacon=str(ListInfo_LastBeacon[n])
            if LastBeacon!="-" and LastBeacon!="":
                LastBeacon = LastBeacon +  " ago"
            LastBeacon=str(LastBeacon).ljust(40)
            DataValue4 = APColor + "Channel / Freq. : " + StdColor + str(ChannelFreq).ljust(40) + APColor + "Max. Rate   : " + StdColor + str(MaxRate).ljust(15) + APColor + "Cloaked? : " + StdColor + str(ListInfo_Cloaked[n]).ljust(15) + APColor  + "Mode        : " + StdColor + str(ListInfo_Mode[n]) + "\n"
            GPSLoc=str(ListInfo_GPSBestLat[n]) + " / " + str(ListInfo_GPSBestLon[n])
            BitRate=ListInfo_BitRate[n].replace("|",APColor + "|" + StdColor)
            DataValue5 = APColor + "Bit Rates       : " + StdColor + str(BitRate) + "\n"
            DataValue6 = APColor + "Extended S.Set  : " + StdColor + str(ListInfo_ESS[n]).ljust(40) + APColor + "Standard    : "  + StdColor + str(ListInfo_APStandard[n]) + "\n"
            DataValue7 = APColor + "GPS Lat/Long    : " + StdColor + GPSLoc.ljust(40) + APColor + "Last Beacon : " + StdColor + str(LastBeacon) + APColor + " Last Active : " + StdColor + str(ListInfo_SSIDTimeGapFull[n]) + APColor + " - [ " + StdColor + str(ListInfo_SSIDTimeGap[n]) + APColor + " min ago ]" + "\n"
            DataValue8 = APColor + "First Time Seen : " + StdColor + str(ListInfo_FirstSeen[n]).ljust(40) + APColor + "Last Seen   : " + StdColor + str(ListInfo_LastSeen[n]).ljust(40) + APColor + " Duration    : " + StdColor + str(ListInfo_SSIDElapse[n]) +"\n"
            Cipher=""
            if __builtin__.ListInfo_PairwiseCipher[n]!="-":
                Cipher=Cipher + __builtin__.ListInfo_PairwiseCipher[n] + " (Pairwise) / "
            if __builtin__.ListInfo_GroupCipher[n]!="-":
                Cipher=Cipher + __builtin__.ListInfo_GroupCipher[n] + " (Group) / "
            if Cipher=="":
                Cipher="-"
            else:
                if Cipher[-3:]==" / ":
                    Cipher=Cipher[:-3]
            Cipher=str(str(Cipher).ljust(41)).replace("/",APColor + "/" + StdColor)
            DataValue9=""
            if str(ListInfo_Privacy[n]).find("WPA")!=-1:
                if str(ListInfo_WPAVer[n])!="-" or str(ListInfo_AuthSuite[n])!="-" or str(ListInfo_PairwiseCipher[n])!="-" or str(ListInfo_GroupCipher[n])!="-":
                    DataValue9 = APColor + "WPA Information : " + StdColor + str(ListInfo_WPAVer[n]).ljust(40) + APColor + "Cipher      : " + StdColor + str(Cipher) + APColor + "Auth        : " + StdColor + str(ListInfo_AuthSuite[n]) + "\n"
            if ListInfo_ConnectedClient[n]=="" or ListInfo_ConnectedClient[n]=="0":
                ClientText="No client associated"
            else:
                ClientText=ListInfo_ConnectedClient[n]
            WPSInfo="Not Enabled"
            if ListInfo_WPS[n]!="-":
                WPSLock=""
                if ListInfo_WPSLock[n]!="No":
                    WPSLock=APColor + " / " + StdColor + "Locked"
                WPSInfo=ListInfo_WPS[n] + APColor + " / Ver : " + StdColor + ListInfo_WPSVer[n] + WPSLock
            DataValue10 = APColor + "Connected Client: " + StdColor + str(ClientText).ljust(40) + APColor + "WPS Enabled : " + StdColor + str(WPSInfo) + "\n"
            k=0
            ConnectedClient= []
            PrevConnectedClient= []
            UnassociatedClient= []
            while k < len(__builtin__.ListInfo_STATION):
                if __builtin__.ListInfo_CBSSID[k]==BSSID:
                    ConnectedClient.append (str(k))
                if str(__builtin__.ListInfo_CBSSIDPrevList[k]).find(BSSID)!=-1 and str(__builtin__.ListInfo_CBSSID[k])!=BSSID:
                    if __builtin__.ListInfo_CBSSID[k]!=BSSID:
                        PrevConnectedClient.append (str(k))
                if ESSID!="" and __builtin__.ListInfo_PROBE[k].find(ESSID)!=-1 and __builtin__.ListInfo_CBSSID[k]!=BSSID:
                    UnassociatedClient.append (str(k))
                k += 1
            DataValue11=""
            DataValue12=""
            if len(UnassociatedClient)>0:
                DataValue11 = APColor + "Unassociated    : " + StdColor + str(len(UnassociatedClient)) + " station which is not associated with Access Point but probing for " + fcolor.BPink + str(ESSID) + "\n"
            if len(PrevConnectedClient)>0:
                DataValue12 = APColor + "Prev. Connection: " + StdColor + str(len(PrevConnectedClient)) + "\n"
            RecNo=str(RecordNum)
            if str(ListInfo_Enriched[n])!="":
                RecNo=RecNo + " *"
            RecNo=str(str(RecNo).ljust(40)).replace(" *",fcolor.SCyan + " *")
            RecType=""
            if str(__builtin__.ListInfo_STATION).find(BSSID)!=-1:
                RecType=fcolor.BRed + "The MAC Address is detected to be both an Access Point & Station"
            DataValue0 = APColor + "Access Point No.: " + fcolor.SRed + str(RecNo) + str(RecType) + "\n"
            DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8 + DataValue9 + DataValue10 + DataValue11 + DataValue12
            print DataValue
            DisplayMACDetailFromFiles(BSSID)
        x += 1

def DisplayStationDetail():
    CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED STATIONS LISTING [ " + str(len(__builtin__.ShowStationList)) + " ]")
    x=0
    StnColor=fcolor.SGreen
    RecordNum=0
    while x < len(__builtin__.ShowStationList):
        RecordNum += 1
        DataValue0="";DataValue1="";DataValue2="";DataValue3="";DataValue4="";DataValue5="";DataValue6="";DataValue7="";DataValue8=""
        n=int(__builtin__.ShowStationList[x])
        StnMAC=ListInfo_STATION[n]
        CBSSID=ListInfo_CBSSID[n]
        OUITxt=Check_OUI(ListInfo_CBSSID[x],"")
        DataValue0 = lblColor + "Client Number   : " + fcolor.BRed + str(RecordNum)  + "\n"
        DataValue1= lblColor + "STATION MAC ID  : " + fcolor.BYellow + str(StnMAC).ljust(40) + lblColor + "Vendor      : " + fcolor.BCyan + str(__builtin__.ListInfo_COUI[n]) + "\n"    
        SignalRange=str(ListInfo_CBestQuality[n]) + " dBm" + lblColor + fcolor.CBold + " ["  + str(ListInfo_CQualityRange[n])  + lblColor + fcolor.CBold + "]" 
        DataValue2 = lblColor + "Power/Range     : " + StdColor + str(SignalRange) + "\t\t\t  " + lblColor + "Packets     : " + StdColor + str(ListInfo_CPackets[n]).ljust(41) + lblColor + "Standard    : " + StdColor + str(ListInfo_STNStandard[n])  + "\n" 
        DataValue3 = lblColor + "First Time Seen : " + StdColor + str(ListInfo_CFirstSeen[n]).ljust(40) + lblColor + "Last Seen   : " + StdColor + str(ListInfo_CLastSeen[n]).ljust(41) + lblColor + "Duration    : " + StdColor + str(ListInfo_CElapse[n]) +"\n"
        CntBSSID=CBSSID
        if str(CntBSSID).find("Not Associated")!=-1:
            CntBSSID="<Not Associated>"
            CntBSSID=fcolor.SBlack + str(CntBSSID).ljust(40)
        else:
            CntBSSID=fcolor.BWhite+ str(CntBSSID).ljust(40)
        DataValue4= lblColor + "Connected BSSID : " + str(CntBSSID) + lblColor + "Vendor      : " + fcolor.SCyan + str(OUITxt) + "\n"    
        CntESSID=ListInfo_CESSID[n]
        if CntESSID=="" and str(CntBSSID).find("Not Associated")==-1:
            CntESSID=fcolor.SBlack + "<<NO NAME>>".ljust(40)
        else:
            CntESSID=fcolor.BPink + ListInfo_CESSID[n].ljust(40)
        DataValue5 = lblColor + "ESSID Connected : " + StdColor + str(CntESSID) + lblColor + "Last Active : " + StdColor + str(ListInfo_CTimeGapFull[n]) + lblColor + " - [ " + StdColor + str(ListInfo_CTimeGap[n]) + lblColor + " min ago ]" + "\n"
        if str(ListInfo_PROBE[n])!="":
            Probes=ListInfo_PROBE[n]
            Probes=str(Probes).replace(" / ",lblColor + " | " + fcolor.SBlue)
            DataValue6 = lblColor + "Probes          : " + fcolor.SBlue + str(Probes) +"\n"
        AssocHistory=str(ListInfo_CBSSIDPrevList[n])
        AssocHistory=str(AssocHistory).replace("| Not Associated) | ","").replace("Not Associated | ","").replace("  "," ").replace("|",lblColor + "|" + StdColor)
        DataValue7 = lblColor + "Connect History : " + StdColor + str(AssocHistory) +"\n"
        DataValue8=""
        CenterText(fcolor.BBlack + fcolor.BGWhite, "STATION MAC ADDRESS [ " + str(StnMAC) + "] DETAILED INFORMATION - RECORD " + str(RecordNum) + "/" + str(len(__builtin__.ShowStationList)))
        print ""
        DataValue= DataValue0 + DataValue1 + DataValue2 + DataValue3 + DataValue4 + DataValue5 + DataValue6 + DataValue7  + DataValue8
        print DataValue
        DisplayMACDetailFromFiles(StnMAC)
        AssocHistory=RemoveColor(AssocHistory)
        ConnectedBSSID = []
        ConnectedBSSID= str(AssocHistory).replace(" ","").split('|')
        if len(ConnectedBSSID)>1:
            DisplayConnectedBSSID("Related Access Point Information",ConnectedBSSID)
        LineBreak()
        x += 1
    return

def DisplayMyMAC():
    print fcolor.BWhite + tabspacefull + "Selected Interface : " +  fcolor.BGreen + str(__builtin__.SELECTED_IFACE_MAC).ljust(20) + fcolor.BWhite + " [" + fcolor.BRed + str(__builtin__.SELECTED_IFACE) + fcolor.BWhite + "]"
    print fcolor.BWhite + tabspacefull + "Monitor Interface  : " +  fcolor.BGreen + str(__builtin__.SELECTED_MON_MAC).ljust(20) + fcolor.BWhite + " [" + fcolor.BRed + str(__builtin__.SELECTED_MON) + fcolor.BWhite + "]"
    print fcolor.BWhite + tabspacefull +"Managed Interface  : " +  fcolor.BGreen + str(__builtin__.SELECTED_MANIFACE_MAC).ljust(20) + fcolor.BWhite + " [" + fcolor.BRed + str(__builtin__.SELECTED_MANIFACE) + fcolor.BWhite + "]"

def LookupMAC(sMACAddr):
    __builtin__.SELECTTYPE="MAC"
    __builtin__.MatchBSSIDCt=0
    __builtin__.MatchStationCt=0
    if sMACAddr=="":
        usr_resp=AskQuestion("Enter the MAC to lookup for","xx:xx:xx:xx:xx:xx","U"," ","")
    else:
        usr_resp=sMACAddr
    __builtin__.SearchType="0"
    __builtin__.SearchTypelbl="Exact"
    if IsHex(usr_resp)==False:
        printc ("!!","Invalid MAC Address specified !","")
        return;
    if len(usr_resp)>17 :
        printc ("!!","Search MAC should not be more than 17 characters !","")
        return;
    elif len(usr_resp)>1:
        sMAC=usr_resp
        if str(sMAC).find("*")==-1:
            oui=Check_OUI(sMAC,"1")
            printc(".",fcolor.BWhite + "MAC Address OUI     : " + fcolor.SCyan + str(oui),"")
            tmac=str(sMAC).replace("*","").replace("-","").replace(":","")
            if len(tmac)<11:
                usr_resp="*" + sMAC + "*"
            if len(tmac)==11:
                usr_resp=sMAC + "*"
        if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]=="*":
            __builtin__.SearchType="1"      # Find Match
            __builtin__.SearchTypelbl="Containing"
        if str(usr_resp)[:1]!="*" and str(usr_resp)[-1:]=="*":
            __builtin__.SearchType="2"      # Match beginning
            __builtin__.SearchTypelbl="Begining With"
        if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]!="*":
            __builtin__.SearchType="3"      # Match ending
            __builtin__.SearchTypelbl="Ending With"
        __builtin__.SearchVal=str(usr_resp).replace("*","")
        __builtin__.SearchLen=len(__builtin__.SearchVal)
        printc (".",fcolor.BWhite + "Search MAC Criteria : " + fcolor.BRed + str(__builtin__.SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        i=0
        while i < len(ListInfo_BSSID):
            ToDisplay = 0
            if __builtin__.SearchType=="0" and str(ListInfo_BSSID[i])==__builtin__.SearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="1" and str(ListInfo_BSSID[i]).find(__builtin__.SearchVal)!=-1:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="2" and str(ListInfo_BSSID[i])[:__builtin__.SearchLen]==__builtin__.SearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="3" and str(ListInfo_BSSID[i])[-__builtin__.SearchLen:]==__builtin__.SearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.ShowBSSIDList2.append (ListInfo_BSSID[i])
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if ToDisplay==1:
                YOURMAC=""
                if ListInfo_BSSID[i]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_BSSID[i]==__builtin__.SELECTED_MON_MAC or ListInfo_BSSID[i]==__builtin__.SELECTED_IFACE_MAC:
                    YOURMAC=fcolor.BRed + " [YOUR MAC]"
                print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_BSSID[i]) + fcolor.SGreen + " (BSSID)" + str(YOURMAC)
            i += 1
        i=0
        while i < len(ListInfo_STATION):
            ToDisplay = 0
            if __builtin__.SearchType=="0" and str(ListInfo_STATION[i])==__builtin__.SearchVal:
                __builtin__.ShowStationList.append (i)
                __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                __builtin__.MatchStationCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="1" and str(ListInfo_STATION[i]).find(__builtin__.SearchVal)!=-1:
                __builtin__.ShowStationList.append (i)
                __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                __builtin__.MatchStationCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="2" and str(ListInfo_STATION[i])[:__builtin__.SearchLen]==__builtin__.SearchVal:
                __builtin__.ShowStationList.append (i)
                __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                __builtin__.MatchStationCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="3" and str(ListInfo_STATION[i])[-__builtin__.SearchLen:]==__builtin__.SearchVal:
                __builtin__.ShowStationList.append (i)
                __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                __builtin__.MatchStationCt += 1
                ToDisplay=1
            if ToDisplay==1:
                YOURMAC=""
                if ListInfo_STATION[i]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[i]==__builtin__.SELECTED_MON_MAC or ListInfo_STATION[i]==__builtin__.SELECTED_IFACE_MAC:
                    YOURMAC=fcolor.BRed + " [YOUR MAC]"
                print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_STATION[i]) + fcolor.SGreen + " (Station)" + str(YOURMAC)
            i += 1

def LookupName(sName):
    __builtin__.SELECTTYPE="NAME"
    __builtin__.MatchBSSIDCt=0
    __builtin__.MatchStationCt=0
    if sName=="":
        usr_resp=AskQuestion("Enter the Name to lookup for","",""," ","")
    else:
        usr_resp=sName
    __builtin__.SearchType="0"
    __builtin__.SearchTypelbl="Exact"
    if len(usr_resp)>32 :
        printc ("!!","Search Name should not be more than 32 characters !","")
    elif len(usr_resp)>1:
        if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]=="*":
            __builtin__.SearchType="1"      # Find Match
            __builtin__.SearchTypelbl="Containing"
        if str(usr_resp)[:1]!="*" and str(usr_resp)[-1:]=="*":
            __builtin__.SearchType="2"      # Match beginning
            __builtin__.SearchTypelbl="Begining With"
        if str(usr_resp)[:1]=="*" and str(usr_resp)[-1:]!="*":
            __builtin__.SearchType="3"      # Match ending
            __builtin__.SearchTypelbl="Ending With"
        __builtin__.SearchVal=str(usr_resp).replace("*","")
        __builtin__.SearchLen=len(__builtin__.SearchVal)
        printc (".",fcolor.BWhite + "Search Name Criteria : " + fcolor.BRed + str(__builtin__.SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        i=0
        while i < len(ListInfo_BSSID):
            ToDisplay = 0
            UESSID=str(ListInfo_ESSID[i]).upper()
            __builtin__.USearchVal=str(__builtin__.SearchVal).upper()
            if __builtin__.SearchType=="0" and str(UESSID)==__builtin__.USearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="1" and str(UESSID).find(__builtin__.USearchVal)!=-1:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="2" and str(UESSID)[:__builtin__.SearchLen]==__builtin__.USearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if __builtin__.SearchType=="3" and str(UESSID)[-__builtin__.SearchLen:]==__builtin__.USearchVal:
                __builtin__.ShowBSSIDList.append (i)
                __builtin__.MatchBSSIDCt += 1
                ToDisplay=1
            if ToDisplay==1:
                YOURMAC=""
                if ListInfo_BSSID[i]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_BSSID[i]==__builtin__.SELECTED_MON_MAC or ListInfo_BSSID[i]==__builtin__.SELECTED_IFACE_MAC:
                    YOURMAC=fcolor.BRed + " [YOUR MAC]"
                print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_BSSID[i]) + fcolor.SGreen + " (ESSID)\t\tESSID : " + fcolor.SPink + str(ListInfo_ESSID[i]) + str(YOURMAC)
            i += 1
        i=0
        while i < len(ListInfo_STATION):
            ToDisplay = 0
            ProbeData=[]
            ProbeData=str(ListInfo_PROBE[i]).split(" / ")
            j=0 
            while j<len(ProbeData):
                ToDisplay=0;FoundProbe=""
                UProbeData=str(ProbeData[j]).upper()
                __builtin__.USearchVal=str(__builtin__.SearchVal).upper()
                if __builtin__.SearchType=="0" and str(UProbeData)==__builtin__.USearchVal:
                    FoundProbe=str(ProbeData[j])
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    __builtin__.MatchStationCt += 1
                    ToDisplay=1
                    j=len(ProbeData)
                if __builtin__.SearchType=="1" and str(UProbeData).find(__builtin__.USearchVal)!=-1:
                    FoundProbe=str(ProbeData[j])
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    __builtin__.MatchStationCt += 1
                    ToDisplay=1
                    j=len(ProbeData)
                if __builtin__.SearchType=="2" and str(UProbeData)[:__builtin__.SearchLen]==__builtin__.USearchVal:
                    FoundProbe=str(ProbeData[j])
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    __builtin__.MatchStationCt += 1
                    ToDisplay=1
                    j=len(ProbeData)
                if __builtin__.SearchType=="3" and str(UProbeData)[-__builtin__.SearchLen:]==__builtin__.USearchVal:
                    FoundProbe=str(ProbeData[j])
                    __builtin__.ShowStationList.append (i)
                    __builtin__.ShowStationList2.append (ListInfo_STATION[i])
                    __builtin__.MatchStationCt += 1
                    ToDisplay=1
                    j=len(ProbeData)
                j += 1
            if ToDisplay==1:
                YOURMAC=""
                if ListInfo_STATION[i]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[i]==__builtin__.SELECTED_MON_MAC or ListInfo_STATION[i]==__builtin__.SELECTED_IFACE_MAC:
                    YOURMAC=fcolor.BRed + " [YOUR MAC]"
                print tabspacefull + fcolor.SGreen + "Found Match : " + fcolor.SWhite + str(ListInfo_STATION[i]) + fcolor.SGreen + " (Station Probe)\tProbe : " + fcolor.SBlue + str(FoundProbe) + str(YOURMAC)
            i += 1

def OptInfoDisplay(HeaderLine,DisplayHeader):
    if HeaderLine!="":
        LineBreak()
    if DisplayHeader=="1":
        printc ("+", fcolor.BBlue + "Information Lookup Menu","")
    DisplayMyMAC()
    print tabspacefull + StdColor + "Information Lookup allow user to search for MAC address of Access Point and Wireless Station detected. "
    print tabspacefull + StdColor + "It also allow user to search for SSID of Access Point and also Probe name broadcasted from Wireless station."
    print tabspacefull + StdColor + "User can also search for partial MAC or Name by adding '*' infront / back of the search variable."
    print tabspacefull + StdColor + "Once information is found, it will display the full detail of the devices including it association with Access Point/Station."
    print ""
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "AC Address\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - " + SelColor + "N" + StdColor + "ames of Access Point / Probes\n"
    OptionA=Option1 + Option2
    print OptionA
    usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","M / N","U","RETURN","1")
    if usr_resp=="RETURN" or usr_resp=="R":
        return;
    if usr_resp=="1" or usr_resp=="M":
        print ""
        LookupMAC("")
        ProcessOptInfoDisplay()
    if usr_resp=="2" or usr_resp=="N":
        print ""
        LookupName("")
        ProcessOptInfoDisplay()
    return;

def ProcessOptInfoDisplay():
    if __builtin__.MatchBSSIDCt>0 or __builtin__.MatchStationCt>0:
        if __builtin__.MatchBSSIDCt>0:
            printc ("i","Total BSSID Matched   : " + fcolor.BRed + str(__builtin__.MatchBSSIDCt),"")
        if __builtin__.MatchStationCt>0:
            printc ("i","Total Station Matched : " + fcolor.BRed + str(__builtin__.MatchStationCt),"")
        print ""
        printc ("x","Press any key to display the listing detail...","")
    else:
        if SELECTTYPE=="MAC":
            printc ("!!","The specified MAC address was not found in current listing !!!","")
        if SELECTTYPE=="NAME":
            printc ("!!","The specified Name was not found in current listing !!!","")
        print ""
        if __builtin__.SearchVal!="":
            usr_resp=AskQuestion(fcolor.BGreen + "Do you want to try to search the database files" + fcolor.BGreen,"Y/n","U","Y","1")
            if usr_resp=="Y":
                if SELECTTYPE=="MAC":
                    SearchDBFiles("MAC", __builtin__.SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
                    OptInfoDisplay("","1")
                    return;
                if SELECTTYPE=="NAME":
                    SearchDBFiles("NAME", __builtin__.SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
                    OptInfoDisplay("","1")
                    return;
            else:
                OptInfoDisplay("1","1")
                return;
        else:
            OptInfoDisplay("1","1")
            return;
    if __builtin__.MatchBSSIDCt>0:
        DisplayBSSIDDetail()
    if __builtin__.MatchStationCt>0:
        DisplayStationDetail()
    usr_resp=AskQuestion(fcolor.BGreen + "Do you want to try to search the database files" + fcolor.BGreen,"Y/n","U","Y","1")
    if usr_resp=="Y":
        if SELECTTYPE=="MAC":
            SearchDBFiles("MAC", __builtin__.SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)
        if SELECTTYPE=="NAME":
            SearchDBFiles("NAME", __builtin__.SearchVal,__builtin__.SearchLen,__builtin__.SearchType,__builtin__.SearchTypelbl)

def OptFilterDisplay(HeaderLine):
    if HeaderLine!="":
        LineBreak()
    GetFilterDetail()
    printc ("+", fcolor.BBlue + "Filtering Menu ","")
    print StdColor + tabspacefull + "This option user to filter encryption type, signal range, channel, having clients and WPS enabled access point."
    print StdColor + tabspacefull + "It also enable filtering of probes, signal range, associated and unassociated station."
    print ""
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "ccess Point\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "tation / Client\n"
    Option3 =tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nassociated Station\n"
    Option4=""
    if __builtin__.DisplayAllFilter!="":
        Option4 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear All Filters\n"
    OptionA=Option1 + Option2 + Option3  + Option4
    print OptionA
    if __builtin__.DisplayAllFilter!="":
        print __builtin__.DisplayAllFilter
    usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","A / S / U" ,"U","RETURN","1")
    if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            __builtin__.NETWORK_FILTER="ALL"
            __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            __builtin__.NETWORK_CHANNEL_FILTER="ALL"
            __builtin__.NETWORK_WPS_FILTER="ALL"
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            printc (" ","All Filters Cleared !","")
            OptFilterDisplay("1")
            return;
    if usr_resp=="RETURN":
        return;
    if usr_resp=="A" or usr_resp=="1":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Access Point\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "E" + StdColor + " - " + SelColor + "E" + StdColor + "ncryption Type\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "hannel\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "N" + StdColor + " - Clie" + SelColor + "n" + StdColor + "t\n"
        Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "W" + StdColor + " - " + SelColor + "W" + StdColor + "PS\n"
        Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","E/S/C/N/W/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_FILTER="ALL"
            __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            __builtin__.NETWORK_CHANNEL_FILTER="ALL"
            __builtin__.NETWORK_WPS_FILTER="ALL"
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            printc (" ","Access Point Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        if usr_resp=="1" or usr_resp=="E":
            if __builtin__.NETWORK_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(__builtin__.NETWORK_FILTER), "")
            usr_resp=AskQuestion("Enter Encryption Filter",STxt + "WPA / WPA2 / WPA* / WEP / OPN / OTH / ALL","U","ALL","1")
            if usr_resp=="ALL":
                __builtin__.NETWORK_FILTER="ALL"
                OptFilterDisplay("1")
                return;
            else:
                __builtin__.NETWORK_FILTER=str(usr_resp)
                OptFilterDisplay("1")
                return;
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Access Point)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_SIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_SIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_SIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_SIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_SIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_SIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_SIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_SIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="3" or usr_resp=="C":
            if __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CHANNEL_FILTER), "")
            __builtin__.NETWORK_CHANNEL_FILTER=AskQuestion("Enter Channel to Filter","Numbers","N","ALL","1")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="4" or usr_resp=="N":
            if __builtin__.NETWORK_CLIENT_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CLIENT_FILTER), "")
            usr_resp=AskQuestion("Display of Access Point with Clients",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_CLIENT_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_CLIENT_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_CLIENT_FILTER="No"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="5" or usr_resp=="W":
            if __builtin__.NETWORK_WPS_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_WPS_FILTER), "")
            usr_resp=AskQuestion("Display only Access Point with WPS",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_WPS_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_WPS_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_WPS_FILTER="No"
            OptFilterDisplay("1")
            return;
    if usr_resp=="2" or usr_resp=="S":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Stations\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "robes\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "ssociated Station\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nassociated Station\n"
        Option6 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","P/S/A/U/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            printc (" ","Station Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="1" or usr_resp=="P":
            if __builtin__.NETWORK_PROBE_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_PROBE_FILTER), "")
            usr_resp=AskQuestion("Display only if station having probe names",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_PROBE_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_PROBE_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_PROBE_FILTER="No"
            OptFilterDisplay("1")
            return
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Station)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_CSIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="RETURN":
                OptFilterDisplay("1")
                return
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_CSIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_CSIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_CSIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_CSIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_CSIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_CSIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;
        elif usr_resp=="3" or usr_resp=="A":
            if __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter (Associated) = " + SelBColor + str(NETWORK_ASSOCIATED_FILTER), "")
            usr_resp=AskQuestion("Display only if station associated",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_ASSOCIATED_FILTER="Yes"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="No"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_ASSOCIATED_FILTER="No"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="Yes"
            OptFilterDisplay("1")
            return
        elif usr_resp=="4" or usr_resp=="U":
            if __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter (Unassociated) = " + SelBColor + str(NETWORK_UNASSOCIATED_FILTER), "")
            usr_resp=AskQuestion("Display only if station is not associated",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
            __builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_ASSOCIATED_FILTER="No"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_ASSOCIATED_FILTER="Yes"
                __builtin__.NETWORK_UNASSOCIATED_FILTER="No"
            OptFilterDisplay("1")
            return
    if usr_resp=="3" or usr_resp=="U":
        Option1 = "\n" + tabspacefull + fcolor.BWhite + "Filtering On Unassociated Station\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "robes\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ignal Range\n"
        Option4 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
        OptionA=Option1 + Option2 + Option3 + Option4 
        print OptionA
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","P/S/A/U/X","U","RETURN","1")
        if usr_resp=="RETURN":
            OptFilterDisplay("1")
            return
        print ""
        if usr_resp=="9" or usr_resp=="X":
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            printc (" ","Station Filtration Cleared !","")
            OptFilterDisplay("1")
            return;
        elif usr_resp=="1" or usr_resp=="P":
            if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_UPROBE_FILTER), "")
            usr_resp=AskQuestion("Display only if unassociated station having probe names",SelColor + "Y" + StdColor + "es / " + SelColor + "N" + StdColor + "o","U","ALL","1")
            __builtin__.NETWORK_UPROBE_FILTER="ALL"
            if usr_resp=="1" or usr_resp=="Y" or usr_resp=="YES":
                __builtin__.NETWORK_UPROBE_FILTER="Yes"
            if usr_resp=="2" or usr_resp=="N" or usr_resp=="NO":
                __builtin__.NETWORK_UPROBE_FILTER="No"
            OptFilterDisplay("1")
            return
        elif usr_resp=="2" or usr_resp=="S":
            Option1 = tabspacefull + fcolor.BWhite + "Filtering On Signal Range (Station)\n"
            Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "V" + StdColor + " - " + SelColor + "V" + StdColor + "Good\n"
            Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "G" + StdColor + " - " + SelColor + "G" + StdColor + "ood\n"
            Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "A" + StdColor + " - " + SelColor + "A" + StdColor + "verage\n"
            Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "oorS\n"
            Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "U" + StdColor + " - " + SelColor + "U" + StdColor + "nknown\n"
            Option7 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "X" + StdColor + " - " + SelColor + "" + StdColor + "Clear Filter\n"
            OptionA=Option1 + Option2 + Option3 + Option4 + Option5 + Option6 + Option7
            print OptionA
            if __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
                printc (" " , fcolor.BWhite + "Current Filter = " + SelBColor + str(NETWORK_UCSIGNAL_FILTER), "")
            usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","V/G/A/P/U/X","U","RETURN","1")
            if usr_resp=="RETURN":
                OptFilterDisplay("1")
                return
            if usr_resp=="1" or usr_resp=="VGOOD" or usr_resp=="V":
                __builtin__.NETWORK_UCSIGNAL_FILTER="V.Good"
            if usr_resp=="2" or usr_resp=="GOOD" or usr_resp=="G":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Good"
            if usr_resp=="3" or usr_resp=="AVERAGE" or usr_resp=="A":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Average"
            if usr_resp=="4" or usr_resp=="POOR" or usr_resp=="P":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Poor"
            if usr_resp=="5" or usr_resp=="UNKNOWN" or usr_resp=="U":
                __builtin__.NETWORK_UCSIGNAL_FILTER="Unknown"
            if usr_resp=="9" or usr_resp=="X":
                __builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
            OptFilterDisplay("1")
            return;

def KillSubProc(sProc):
    cmdLine="ps -eo pid | grep '" + str(sProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    ps.wait();ps.stdout.close()
    sProc=str(sProc)
    if str(readout)==str(sProc):
        os.killpg(int(sProc), signal.SIGTERM)

def StartProbeESSID(sProbeName):
    printc ("i",fcolor.BGreen + "Probing for [" + fcolor.BRed + str(sProbeName) + fcolor.BGreen + "]....","")
    printc (" ",fcolor.SGreen + "Probing will take a couple of seconds..","")
    printc (" ",fcolor.SGreen + "Once the terminal close immediately after it is open, it is likely probing interface is busy..","")
    printc (" ",fcolor.SGreen + "Try to wait a while and conduct probe again..","")
    print""
    cmdLine="ps -eo pid | grep '" + str(__builtin__.IWListProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    __builtin__.IWListProc=str(__builtin__.IWListProc)
    if str(readout)==str(__builtin__.IWListProc):
        os.killpg(int(__builtin__.IWListProc), signal.SIGTERM)
    cmdLine="xterm -geometry 100x3-0-200 -iconic -bg black -fg white -fn 5x8 -title 'Probing ESSID [ " + str(sProbeName) + " ].. terminal will terminate once completed.' -e 'iwlist " + __builtin__.SELECTED_MANIFACE + " scanning essid \x22" + str(sProbeName) + "\x22 > /dev/null 2>&1'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)
    __builtin__.ProbeProc=ps.pid
    Ask=AskQuestion("Probe [ " + fcolor.BRed + str(sProbeName) + fcolor.BGreen + " ] again ?" ,"y/N","U","N","1")
    KillSubProc(__builtin__.ProbeProc)
    if Ask=="Y":
        StartProbeESSID(sProbeName)
    return

def ProbeESSID(sProbeName):
    if sProbeName=="":
        usr_resp=AskQuestion("Enter the ESSID to Probe" ,"","","","1")
        if len(usr_resp)>0:
            x=0
            Skip=0
            sProbeName=usr_resp
            while x < len(__builtin__.ListInfo_BSSID):
                if usr_resp==__builtin__.ListInfo_ESSID[x]:
                    Ask=AskQuestion("The ESSID [ " + fcolor.BRed + sProbeName + fcolor.BGreen + " ] already exist, do you want to continue to probe for the name" ,"y/N","U","N","1")
                    if Ask!="Y":
                        Skip=1
                x += 1
            if Skip!=1:
                StartProbeESSID(sProbeName)
                return
    else:
         StartProbeESSID(sProbeName)
    return

def RestartApplication():
    printc ("!!!","Restarting the application.....","")
    python = sys.executable
    os.execl(python,python, * sys.argv)

def RestoreAllSetting():
    printc ("!!!","Deleting All Existing Configuration.....","")
    DelFile (__builtin__.ConfigFile,1)
    DelFile (__builtin__.PktConfig,1)
    DelFile (__builtin__.MonitorMACfile,1)
    RestartApplication()

def ResetInterface(CMD):
    if CMD=="1":
        print ""
        printc ("i",fcolor.BGreen + "Shutting down all interfaces .....","")
    ShutdownMonitor()
    KillAllMonitor()
    CreateMonitor(CMD)
    if CMD=="1":
        printc ("i",fcolor.BGreen + "Restarting all interfaces .....","")
    RunAirodump()
    if __builtin__.LOAD_WPS=="Yes" and __builtin__.FIXCHANNEL==0:
        RunWash()
    if __builtin__.LOAD_IWLIST=="Yes" and __builtin__.FIXCHANNEL==0:
        RunIWList()

def OptControls(HeaderLine):
    if HeaderLine!="":
        LineBreak()
    printc ("+", fcolor.BBlue + "Operation Control Menu","")
    Option0 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "R" + StdColor + " - Shutdown all interfaces and " + SelColor + "R" + StdColor + "estart again\n"
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "P" + StdColor + " - " + SelColor + "P" + StdColor + "robe Acess Point Name\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - Refresh " + SelColor + "N" + StdColor + "ow\n"
    Option3 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "S" + StdColor + " - Re" + SelColor + "s" + StdColor + "tart Application (All active listing will be cleared) \n"
    Option4 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "T" + StdColor + " - Res" + SelColor + "t" + StdColor + "ore all setting (All configuration will be reset, application will restart) \n"
    OptionA=Option0 + Option1 + Option2 + Option3 + Option4
    print OptionA
    usr_resp=AskQuestion("Choose an option","R / P / N / S / T","U","RETURN","1")
    if usr_resp=="RETURN":
        return;
    if usr_resp=="0" or usr_resp=="R":
        LineBreak()
        ResetInterface("1")
    if usr_resp=="1" or usr_resp=="P":
        LineBreak()
        ProbeESSID("")
    if usr_resp=="2" or usr_resp=="N":
        LineBreak()
        return "TIME0"
    if usr_resp=="3" or usr_resp=="S":
        LineBreak()
        Result=AskQuestion(fcolor.SRed + "Active listing will be cleared, are you sure you want to exit ?"+ fcolor.BGreen,"y/N","U","N","1")
        if Result=="Y":
           RestartApplication()
    if usr_resp=="4" or usr_resp=="T":
        LineBreak()
        Result=AskQuestion(fcolor.SRed + "All your setting will be removed, are you sure ?"+ fcolor.BGreen,"y/N","U","N","1")
        if Result=="Y":
            RestoreAllSetting()
    return;

def OptConfiguration(HeaderLine):
    if HeaderLine!="":
        LineBreak()
    printc ("+", fcolor.BBlue + "Application Configuation","")
    Option0 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "D" + StdColor + " - Change Regulatory " + SelColor + "D" + StdColor + "omain\t\t\t" + fcolor.SGreen + "[ Current : " + str(GetRegulatoryDomain()) + " ]\n"
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "R" + StdColor + " - " + SelColor + "R" + StdColor + "efreshing rate of information\t\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.TIMEOUT) + " sec ]\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "T" + StdColor + " - " + SelColor + "T" + StdColor + "ime before removing inactive AP/Station\t" + fcolor.SGreen + "[ Current : " + str(HIDE_AFTER_MIN) + " min / " + str(TOTALLY_REMOVE_MIN) + " min]\n"
    Option3 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "ide inactive Access Point/Station\t\t" + fcolor.SGreen + "[ Access Point : " + str(__builtin__.HIDE_INACTIVE_SSID) + " / Station : " + str(__builtin__.HIDE_INACTIVE_STN) + " ]\n"
    Option4 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "B" + StdColor + " - " + SelColor + "B" + StdColor + "eep if alert found\t\t\t\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.ALERTSOUND) + " ]\n"
    Option5 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "S" + StdColor + " - " + SelColor + "S" + StdColor + "ensitivity of IDS\t\t\t\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.SENSITIVITY_LVL) + " ]\n"
    Option6 = tabspacefull + SelBColor + "6" + StdColor + "/" + SelBColor + "A" + StdColor + " - Save PCap when " + SelColor + "A" + StdColor + "ttack detected\t\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.SAVE_ATTACKPKT) + " ]\n"
    Option7 = tabspacefull + SelBColor + "7" + StdColor + "/" + SelBColor + "M" + StdColor + " - Save PCap when " + SelColor + "M" + StdColor + "onitored MAC/Name seen\t" + fcolor.SGreen + "[ Current : " + str(__builtin__.SAVE_MONPKT) + " ]\n"
    Option8 = tabspacefull + SelBColor + "8" + StdColor + "/" + SelBColor + "W" + StdColor + " - " + SelColor + "W" + StdColor + "hitelist Setting (Bypass alert for MAC/Name)\n"
    Option9 =""
    OptionA=Option0 + Option1 + Option2 + Option3  + Option4 + Option5+ Option6  + Option7 + Option8+ Option9
    print OptionA
    usr_resp=AskQuestion("Choose an option","D/R/T/H/B/W/C","U","RETURN","1")
    if usr_resp=="RETURN":
        return;
    if usr_resp=="8" or usr_resp=="W":
        OptWhitelist("1","1")
    if usr_resp=="0" or usr_resp=="D":
        ChangeRegulatoryDomain()
    if usr_resp=="-":
        SaveConfig("1")
    if usr_resp=="5" or usr_resp=="S":
        SetIDS_Sensitivity("")
        return
    if usr_resp=="6" or usr_resp=="A":
        usr_resp=AskQuestion("Save PCap file when attack detected  " + fcolor.SGreen + "[Current : " + str(__builtin__.SAVE_ATTACKPKT) + "]" ,"Y/n","U","Y","1")
        if usr_resp=="Y":
            __builtin__.SAVE_ATTACKPKT="Yes"
        else:
            __builtin__.SAVE_ATTACKPKT="No"
        SaveConfig("")
        return
    if usr_resp=="7" or usr_resp=="M":
        usr_resp=AskQuestion("Save PCap file when monitored MAC/Name detected  " + fcolor.SGreen + "[Current : " + str(__builtin__.SAVE_MONPKT) + "]" ,"y/N","U","N","1")
        if usr_resp=="Y":
            __builtin__.SAVE_MONPKT="Yes"
        else:
            __builtin__.SAVE_MONPKT="No"
        SaveConfig("")
        return
    if usr_resp=="1" or usr_resp=="R":
        usr_resp=AskQuestion("Refresh detail after number of seconds " + fcolor.SGreen + "[Current : " + str(__builtin__.TIMEOUT) + "]" ,"Default 30","N","30","1")
        __builtin__.TIMEOUT=usr_resp
        return
    if usr_resp=="2" or usr_resp=="T":
        usr_resp=AskQuestion("Select duration before " + fcolor.BRed + "H" + fcolor.BYellow + "ide AP/Station / " + fcolor.BRed + "R" + fcolor.BYellow + "emove AP/Station" ,"H/R","U","RETURN","1")
        if usr_resp=="RETURN":
            return
        if usr_resp=="H":
            usr_resp=AskQuestion("Number of minutes before hiding inactive AP/Station " + fcolor.SGreen + "[Current : " + str(HIDE_AFTER_MIN) + "]" ,"Default 1","N","1","1")
            __builtin__.HIDE_AFTER_MIN=usr_resp
            return
        if usr_resp=="R":
            usr_resp=AskQuestion("Number of minutes before removing inactive AP/Station " + fcolor.SGreen + "[Current : " + str(TOTALLY_REMOVE_MIN) + "]" ,"Default 120","N","120","1")
            __builtin__.TOTALLY_REMOVE_MIN=usr_resp
            return
    if usr_resp=="3" or usr_resp=="H":
        usr_resp=AskQuestion("Select " + fcolor.BRed + "A" + fcolor.BYellow + "ccess Point / " + fcolor.BRed + "S" + fcolor.BYellow + "tation" ,"A/S","U","Y","1")
        if usr_resp=="A":
            usr_resp=AskQuestion("Hide Inactive Access Point " + fcolor.SGreen + "[Current : " + str(__builtin__.HIDE_INACTIVE_SSID) + "]" ,"Y/n","U","Y","1")
            if usr_resp=="N":
                __builtin__.HIDE_INACTIVE_SSID="No"
                return
            else:
                __builtin__.HIDE_INACTIVE_SSID="Yes"
                return
        if usr_resp=="S":
            usr_resp=AskQuestion("Hide Inactive Station " + fcolor.SGreen + "[Current : " + str(__builtin__.HIDE_INACTIVE_STN) + "]" ,"Y/n","U","Y","1")
            if usr_resp=="N":
                __builtin__.HIDE_INACTIVE_STN="No"
                return
            else:
                __builtin__.HIDE_INACTIVE_STN="Yes"
                return
    if usr_resp=="4" or usr_resp=="B":
        usr_resp=AskQuestion("Beep if Alert Found " + fcolor.SGreen + "- Current = " + str(__builtin__.ALERTSOUND) + " " + fcolor.BGreen,"Y/n","U","Y","1")
        if usr_resp=="Y":
            __builtin__.ALERTSOUND="Yes"
        elif usr_resp=="N":
            __builtin__.ALERTSOUND="No"
    OptConfiguration("1")
    return

def DisplayWhitelist():
    if len(__builtin__.WhiteMACList)==0 and len(__builtin__.WhiteMACList)==0:
        printc ("i","No items was specified in current setting..","")
    else:
        printc (".", fcolor.BPink + "Whitelist Items","")
        x=0
        while x < len(__builtin__.WhiteMACList):
            printc (" ",fcolor.SWhite + "MAC  : " + fcolor.BGreen + str(__builtin__.WhiteMACList[x]),"")
            x=x+1
        x=0
        while x < len(__builtin__.WhiteNameList):
            printc (" ",fcolor.SWhite + "Name : " + fcolor.BGreen + str(__builtin__.WhiteNameList[x]),"")
            x=x+1
        LineBreak()

def OptWhitelist(HeaderLine,DisplayHeader):
    if HeaderLine!="":
        LineBreak()
    GetWhitelist()
    Skip=0
    if DisplayHeader=="1":
        printc ("+", fcolor.BBlue + "Whitelist Setting Menu","")
    print tabspacefull + StdColor + "Whitelist setting allow user to bypass any alert from the specified MAC addresses / Names.";print ""
    DisplayWhitelist()
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "AC Address [BSSID/STATION]\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - " + SelColor + "N" + StdColor + "ame of Access Point/Probe Names\n"
    Option3 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "lear all Monitoring Items\n"
    OptionA=Option1 + Option2 + Option3
    print OptionA
    usr_resp=AskQuestion("Select Whitelist Type : ",STxt + "M / N / C","U","RETURN","1")
    if usr_resp=="RETURN":
        return
    if usr_resp=="C" or usr_resp=="9":
        open(WhitelistFile,"w").write("")
        __builtin__.WhiteMACList=[]
        __builtin__.WhiteNameList=[]
        printc ("i",fcolor.BRed + "All items cleared from the whitelist..","")
        OptWhitelist("1","1")
        return
    if usr_resp=="M" or usr_resp=="1":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd MAC / " + STxt + "D" + NTxt + "elete / " + STxt + "C" + NTxt + "lear","U","RETURN","1")
        if usr_resp=="RETURN":
            OptWhitelist("1","1")
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the MAC Address to monitor (xx:xx:xx:xx:xx:xx) " ,"","U","","1")
            if len(usr_resp)==17:
                x=0
                while x < len(__builtin__.WhiteMACList):
                    if usr_resp==__builtin__.WhiteMACList[x]:
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.WhiteMACList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to whitelisting..","")
                    SaveWhitelist()
                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the MAC Address to remove (xx:xx:xx:xx:xx:xx) " ,"","U","","")
            if len(usr_resp)==17:
                if usr_resp in __builtin__.WhiteMACList:
                    __builtin__.WhiteMACList.remove (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted from whitelist..","")
                    SaveWhitelist()
                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(WhitelistFile,"w").write("")
            __builtin__.WhiteMACList=[]
            printc ("i",fcolor.SGreen + "All MAC Addresses cleared from the whitelist..","")
        OptWhitelist("1","1")
        return
    if usr_resp=="N" or usr_resp=="2":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd ESSID/Probe Name / " + STxt + "D" + NTxt + "elete / " + STxt + "C" + NTxt + "lear","U","RETURN","1")
        if usr_resp=="RETURN":
            OptWhitelist("1","1")
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the Name to Whitelist (Case sensitive)" ,"","","","1")
            if len(usr_resp)>0:
                x=0
                while x < len(__builtin__.WhiteNameList):
                    if usr_resp==__builtin__.WhiteNameList[x]:
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.WhiteNameList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to whitelisting..","")
                    SaveWhitelist()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the Name to Remove (Case sensitive)" ,"","","","")
            if len(usr_resp)>0:
                if usr_resp in __builtin__.WhiteNameList:
                    __builtin__.WhiteNameList.remove (str(usr_resp))
                    print "__builtin__.WhiteNameList : " + str(__builtin__.WhiteNameList)
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted from whitelist..","")
                    SaveWhitelist()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(WhitelistFile,"w").write("")
            __builtin__.WhiteNameList=[]
            printc ("i",fcolor.SGreen + "All Names are cleared from the Whitelist..","")
        OptWhitelist("1","1")
        return
    return

def OptMonitorMAC(HeaderLine):
    if HeaderLine!="":
        LineBreak()
    MonitoringMACStr=""
    __builtin__.MonitoringMACList=[]
    GetMonitoringMAC()
    Skip=""
    printc ("+",fcolor.BBlue + "MAC / Names Monitoring Setting","")
    print  tabspacefull + StdColor + "Monitoring Setting allow user to monitor MAC address and Name of Access Point/Station/Probes."
    print  tabspacefull + StdColor + "Once the specified MAC addresses / Names were detected, it will display the detail."
    print  tabspacefull + StdColor + "User can also set alert beep if speficied items is spotted. [Application Configuration] --> [Beep if alert found]"
    print ""
    DisplayMonitoringMAC()
    Option1 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "M" + StdColor + " - " + SelColor + "M" + StdColor + "AC Address [BSSID/STATION]\n"
    Option2 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "N" + StdColor + " - " + SelColor + "N" + StdColor + "ame of Access Point/Probe Names\n"
    Option3 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "C" + StdColor + " - " + SelColor + "C" + StdColor + "lear all Monitoring Items\n"
    OptionA=Option1 + Option2 + Option3
    print OptionA
    usr_resp=AskQuestion("Select Monitoring Type : ",STxt + "M / N / C","U","RETURN","1")
    if usr_resp=="RETURN":
        return
    if usr_resp=="C" or usr_resp=="9":
        open(MonitorMACfile,"w").write("")
        __builtin__.MonitoringMACList=[]
        __builtin__.MonitoringNameList=[]
        printc ("i",fcolor.BRed + "All items cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return
    if usr_resp=="M" or usr_resp=="1":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd MAC / " + STxt + "D" + NTxt + "elete / " + STxt + "C" + NTxt + "lear","U","RETURN","1")
        if usr_resp=="RETURN":
            OptMonitorMAC("1")
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the MAC Address to monitor (xx:xx:xx:xx:xx:xx) " ,"","U","","1")
            if len(usr_resp)==17:
                x=0
                while x < len(__builtin__.MonitoringMACList):
                    if usr_resp==__builtin__.MonitoringMACList[x]:
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.MonitoringMACList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the MAC Address to remove (xx:xx:xx:xx:xx:xx) " ,"","U","","")
            if len(usr_resp)==17:
                if usr_resp in __builtin__.MonitoringMACList:
                    __builtin__.MonitoringMACList.remove (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted from monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(MonitorMACfile,"w").write("")
            __builtin__.MonitoringMACList=[]
            printc ("i",fcolor.SGreen + "All MAC Addresses cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return
    if usr_resp=="N" or usr_resp=="2":
        usr_resp=AskQuestion("Select an option : ",STxt + "A" + NTxt + "dd ESSID/Probe Name / " + STxt + "D" + NTxt + "elete / " + STxt + "C" + NTxt + "lear","U","RETURN","1")
        if usr_resp=="RETURN":
            OptMonitorMAC("1")
            return
        if usr_resp=="A":
            usr_resp=AskQuestion("Enter the Name to Monitor" ,"","","","1")
            if len(usr_resp)>0:
                x=0
                while x < len(__builtin__.MonitoringNameList):
                    if usr_resp.upper()==__builtin__.MonitoringNameList[x].upper():
                        Skip=1
                    x=x+1
                if Skip!=1:
                    __builtin__.MonitoringNameList.append (str(usr_resp))
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " added to monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " already exist !!","")
        if usr_resp=="D":
            usr_resp=AskQuestion("Enter the Name to Remove" ,"","","","")
            if len(usr_resp)>0:
                if usr_resp in __builtin__.MonitoringNameList:
                    __builtin__.MonitoringNameList.remove (str(usr_resp))
                    print "__builtin__.MonitoringNameList : " + str(__builtin__.MonitoringNameList)
                    printc ("i",fcolor.SGreen + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SGreen + " deleted from monitoring list..","")
                    SaveMonitoringMAC()
                else:
                    printc ("!",fcolor.SRed + "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " does not exist !!","")
            else:
                if usr_resp!="":
                    printc ("!",fcolor.SRed +  "The Name " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!","")
        if usr_resp=="C":
            open(MonitorMACfile,"w").write("")
            __builtin__.MonitoringNameList=[]
            printc ("i",fcolor.SGreen + "All Names are cleared from the monitoring list..","")
        OptMonitorMAC("1")
        return
    return

def OptOutputDisplay(CMD):
    if CMD=="":
        printc ("+", fcolor.BBlue + "Change Listing Display ","")
        print tabspacefull + StdColor + "This option allow user to switch display on the various viewing type of access point and station information.";print ""
        Option1 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "H" + StdColor + " - " + SelColor + "H" + StdColor + "ide both Access Points & Stations Listing Display\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "A" + StdColor + " - Display " + SelColor + "A" + StdColor + "ccess Points Listing Only\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "S" + StdColor + " - Display " + SelColor + "S" + StdColor + "tations Listing Only\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "B" + StdColor + " - Dispay " + SelColor + "B" + StdColor + "oth Access Points & Stations Listing (Separated View)\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "P" + StdColor + " - Advanced View with " + SelColor + "P" + StdColor + "robes Request (Merging associated Stations with Access Points) - " + fcolor.BYellow + "[Recommended]\n"
        Option6 = tabspacefull + SelBColor + "5" + StdColor + "/" + SelBColor + "O" + StdColor + " - Advanced View with" + SelColor + "o" + StdColor + "ut probing request (Merging associated Stations with Access Points)\n"
        Option7 = tabspacefull + SelBColor + "6" + StdColor + "/" + SelBColor + "C" + StdColor + " - Display one time bar " + SelColor + "c" + StdColor + "hart of Access Points information\n"
        Option8 = "\n" + tabspacefull + SelBColor + "7" + StdColor + "/" + SelBColor + "C" + StdColor + " - Hide/Show Association/Co" + SelColor + "n" + StdColor + "nection Alert."+ fcolor.SGreen + "[ Current : No ]".rjust(39) + "\n"
        Option9 = tabspacefull + SelBColor + "8" + StdColor + "/" + SelBColor + "U" + StdColor + " - Hide/Show S" + SelColor + "u" + StdColor + "spicious Activity Listing Alert"+ fcolor.SGreen + "[ Current : Yes ]".rjust(35) + "\n"
        Option10 = tabspacefull + SelBColor + "9" + StdColor + "/" + SelBColor + "I" + StdColor + " - Hide/Show " + SelColor + "I" + StdColor + "ntrusion Detection/Attacks Alert."+ fcolor.SGreen + "[ Current : Yes ]".rjust(34) + "\n"
        OptionA=Option1 + Option2 + Option3 + Option4  + Option5 + Option6 + Option7 + Option8 + Option9+ Option10 
        print OptionA
        printc (" " , fcolor.BWhite + "Current Setting = " + SelBColor + str(__builtin__.NETWORK_VIEW), "")
        usr_resp=AskQuestion("Choose an option / " + STxt + "R" + NTxt + "eturn","","U","RETURN","1")
    else:
        usr_resp=CMD
    if usr_resp=="10" or usr_resp=="W":
        SaveConfig("1")
    if usr_resp=="0" or usr_resp=="1" or usr_resp=="2" or usr_resp=="3" or usr_resp=="4"  or usr_resp=="5":
      __builtin__.NETWORK_VIEW=usr_resp
    if usr_resp=="H" or usr_resp=="A" or usr_resp=="S" or usr_resp=="B" or usr_resp=="P"  or usr_resp=="O" or usr_resp=="6" or usr_resp=="C":
        if usr_resp=="H":
            __builtin__.NETWORK_VIEW="0"
        if usr_resp=="A":
            __builtin__.NETWORK_VIEW="1"
        if usr_resp=="S":
            __builtin__.NETWORK_VIEW="2"
        if usr_resp=="B":
            __builtin__.NETWORK_VIEW="3"
        if usr_resp=="P":
            __builtin__.NETWORK_VIEW="4"
        if usr_resp=="0":
            __builtin__.NETWORK_VIEW="5"
        if usr_resp=="C" or usr_resp=="6":
            DisplayNetworkChart()
    if CMD!="":
        printc (" ",fcolor.BGreen + "Display Option Set : " + fcolor.BYellow + str(CMD),"")
    SaveConfig("")
    LineBreak()
    return;

def printc(PrintType, PrintText,PrintText2):
    """
    Function	   : Displaying text with pre-defined icon and color
    Usage of printc:
        PrintType      - Type of Icon to display
        PrintText      - First sentence to display
        PrintText2     - Second sentence, "?" as reply text, "@"/"@^" as time in seconds
    Examples       : Lookup DemoOnPrintC() for examples
    """
    ReturnOut=""
    bcolor=fcolor.SWhite
    pcolor=fcolor.BGreen
    tcolor=fcolor.SGreen
    if PrintType=="i":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
    if PrintType=="H":
        pcolor=fcolor.BBlue
        tcolor=fcolor.BWhite
        hcolor=fcolor.BUBlue
    if PrintType=="!":
        pcolor=fcolor.BRed
        tcolor=fcolor.BYellow
    if PrintType=="!!":
        PrintType="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.SRed
    if PrintType=="!!!":
        PrintType="!"
        pcolor=fcolor.BRed
        tcolor=fcolor.BRed
    if PrintType==".":
        pcolor=fcolor.BGreen
        tcolor=fcolor.SGreen
    if PrintType=="-":
        pcolor=fcolor.SWhite
        tcolor=fcolor.SWhite
    if PrintType=="--":
        PrintType="-"
        pcolor=fcolor.BWhite
        tcolor=fcolor.BWhite
    if PrintType=="..":
        PrintType="."
        pcolor=fcolor.BGreen
        tcolor=fcolor.BGreen
    if PrintType==">" or PrintType=="+":
        pcolor=fcolor.BCyan
        tcolor=fcolor.BCyan
    if PrintType==" ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.Green
    if PrintType=="  ":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if PrintType=="?":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BGreen
    if PrintType=="x":
        pcolor=fcolor.BRed
        tcolor=fcolor.BBlue
    if PrintType=="*":
        pcolor=fcolor.BYellow
        tcolor=fcolor.BPink
    if PrintType=="@" or PrintType=="@^":
        pcolor=fcolor.BRed
        tcolor=fcolor.White
    firstsixa=""
    if PrintText!="":
        tscolor=fcolor.Blue
        ts = time.time()
        DateTimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S')
        TimeStamp=datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        DateStamp=datetime.datetime.fromtimestamp(ts).strftime('%d/%m/%Y')
        PrintText=PrintText.replace("%dt -",tscolor + DateTimeStamp + " -" + tcolor)
        PrintText=PrintText.replace("%dt",tscolor + DateTimeStamp + tcolor)
        PrintText=PrintText.replace("%t -",tscolor + TimeStamp + " -" + tcolor)
        PrintText=PrintText.replace("%t",tscolor + TimeStamp + tcolor)
        PrintText=PrintText.replace("%d -",tscolor + DateStamp + " -" + tcolor)
        PrintText=PrintText.replace("%d",tscolor + DateStamp + tcolor)
        PrintText=PrintText.replace("%an",tscolor + ScriptName + tcolor)
        if "%cs" in PrintText:
            PrintText=PrintText.replace("%cs",tscolor + PrintText2 + tcolor)
            PrintText2=""
        lPrintText=len(PrintText) 
        if lPrintText>6:
            firstsix=PrintText[:6].lower()
            firstsixa=firstsix
            if firstsix=="<$rs$>":
                ReturnOut="1"
                lPrintText=lPrintText-6
                PrintText=PrintText[-lPrintText:]
    if __builtin__.PrintToFile=="1" and PrintType!="@" and PrintType!="x" and PrintType!="@^" and firstsixa!="<$rs$>":
        PrintTypep=PrintType
        if PrintTypep=="  " or PrintTypep==" ":
            PrintTypep="   " + __builtin__.tabspace
        else:
            PrintTypep="[" + PrintType + "]  "
        open(LogFile,"a+b").write(RemoveColor(PrintTypep) + RemoveColor(str(PrintText.lstrip().rstrip())) + "\n")
    if PrintType=="x":
        if PrintText=="":
            PrintText="Press Any Key To Continue..."
        c1=bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText
        print c1,
        sys.stdout.flush()
        read_a_key()
        print ""
        return
    if PrintType=="H":
        c1=bcolor + "[" + pcolor + "i" + bcolor + "]" + __builtin__.tabspace + hcolor + PrintText + fcolor.CReset 
        if ReturnOut!="1":
            print c1
            return c1
        else:
            return c1
    if PrintType=="@" or PrintType=="@^":
        if PrintText2=="":
            PrintText2=5
        t=int(PrintText2)
        while t!=0:
            s=bcolor + "[" + pcolor + str(t) + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
            s=s.replace("%s",pcolor+str(PrintText2)+tcolor)
            sl=len(s)
            print s,
            sys.stdout.flush()
            time.sleep(1)
            s=""
            ss="\r"
            print "" + s.ljust(sl+2) + ss,
            sys.stdout.flush()
            if PrintType=="@^":
                t=t-1
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    line = sys.stdin.readline()
                    print "line : " + line
                    if line:
                        print bcolor + "[" + fcolor.BRed + "!" + bcolor + "]" + __builtin__.tabspace + fcolor.Red + "Interupted by User.." + fcolor.Green
                        return
            else:
                t=t-1            
        c1=bcolor + "[" + pcolor + "-" + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + "\r"
        c1=c1.replace("%s",pcolor+str(PrintText2)+tcolor)
        print c1,
        sys.stdout.flush()
        return
    if PrintType=="?":
        if PrintText2!="":
            usr_resp=raw_input(bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + " ( " + pcolor + PrintText2 + tcolor + " ) : " + fcolor.BWhite)
            return usr_resp;
        else:
            usr_resp=raw_input(bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + " : " + fcolor.BWhite)
            return usr_resp;
    if PrintType==" " or PrintType=="  ":
        if ReturnOut!="1":
            print bcolor + "   " + __builtin__.tabspace + tcolor + PrintText + PrintText2
        else:
            return bcolor + "   " + __builtin__.tabspace + tcolor + PrintText + PrintText2
    else:
        if ReturnOut!="1":
            print bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + PrintText2
        else:
            return bcolor + "[" + pcolor + PrintType + bcolor + "]" + __builtin__.tabspace + tcolor + PrintText + PrintText2

def AskQuestion(QuestionText, ReplyText, ReplyType, DefaultReply, DisplayReply):
    """
    Function	        : Question for user input. Quite similar to printc("?") function
    Usage of AskQuestion:
        QuestionText    - Question Text to ask
        ReplyText       - The reply text. Ex : "Y/n")
    Examples            : Lookup DemoAskQuestion() for examples
    """
    if DisplayReply=="":
        DisplayReply=1
    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    tcolor=fcolor.BGreen
    if ReplyText!="":
        Ques=QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : "
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + Ques + fcolor.BWhite)
    else:
        usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + QuestionText + " : " + fcolor.BWhite)
    if DefaultReply!="":
        if usr_resp=="":
            if DisplayReply=="1":
                printc (" ",fcolor.SWhite + "Default Selected ==> " + fcolor.BYellow + str(DefaultReply),"")   
            return DefaultReply
        else:
            if ReplyType=="U":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.upper()),"")   
               return usr_resp.upper()
            if ReplyType=="FN":
               if os.path.isfile(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FP":
               if os.path.exists(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename/Pathname [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="PN":
               if os.path.isdir(usr_resp)==True:
                   if usr_resp[-1:]!="/":
                       usr_resp=usr_resp + "/"
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Path [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="L":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.lower()),"")   
               return usr_resp.lower()
            if ReplyType=="N":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
    if DefaultReply=="":
        if usr_resp=="":
            if ReplyText!="":
                usr_resp=raw_input(bcolor + "[" + pcolor + "?" + bcolor + "]" + __builtin__.tabspace + tcolor + QuestionText + " ( " + pcolor + ReplyText + tcolor + " ) : " + fcolor.BWhite)
                return usr_resp;
            else:
                if ReplyType=="MA" or ReplyType=="FN" or ReplyType=="PN" or ReplyType=="FP":
                    usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                    return usr_resp;
                else:
                    if DisplayReply=="1":
                        printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str("Nothing"),"")   
                    return usr_resp;
        else:
            if ReplyType=="MN":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FN":
               if os.path.isfile(usr_resp)==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Filename [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="PN":
               if os.path.isdir(usr_resp)==True:
                   if usr_resp[-1:]!="/":
                       usr_resp=usr_resp + "/"
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp
               else:
                   printc ("!!","Path [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="FP":
               if os.path.exists(usr_resp)==True:
                   if os.path.isfile(usr_resp)==True:
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Filename ==> " + fcolor.BYellow + str(usr_resp),"")   
                       return usr_resp
                   if os.path.isdir(usr_resp)==True:
                       if usr_resp[-1:]!="/":
                           usr_resp=usr_resp + "/"
                       if DisplayReply=="1":
                           printc (" ",fcolor.SWhite + "Path ==> " + fcolor.BYellow + str(usr_resp),"")   
                       return usr_resp
                   return usr_resp
               else:
                   printc ("!!","Filename/Pathname [" + fcolor.SYellow + usr_resp + fcolor.SRed + "] does not exist !.","")
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
            if ReplyType=="U":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.upper()),"")   
               return usr_resp.upper()
            if ReplyType=="L":
               if DisplayReply=="1":
                   printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp.lower()),"")   
               return usr_resp.lower()
            if ReplyType=="N":
               if usr_resp.isdigit()==True:
                   if DisplayReply=="1":
                       printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
                   return usr_resp;
               else:
                   usr_resp=AskQuestion(QuestionText, ReplyText,ReplyType,DefaultReply,DisplayReply)
                   return usr_resp;
    if usr_resp=="":
        if DisplayReply=="1":
            printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str("Nothing"),"")   
        return usr_resp;
    else:
        if DisplayReply=="1":
            printc (" ",fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(usr_resp),"")   
        return usr_resp;

def printl (DisplayText,ContinueBack,PrevIconCount):
    """
    Function	   : Displaying text on the same line
    Usage of printl:
        DisplayText        - Text to Display
        ContinueBack = "0" - Start DisplayText on beginning of line.
        ContinueBack = "1" - Start from the back of the previous DisplayText
        ContinueBack = "2" - Start DisplayText on beginning of line with Icon,PrevIconCount need to contain value
        PrevIconCount      - Value of last icon count
    Examples       : Lookup DemoOnPrintl() for examples
    """
    icolor=fcolor.BGreen
    bcolor=fcolor.SWhite
    IconDisplay=""
    if ContinueBack=="":
       ContinueBack="0"
    if PrevIconCount=="":
        PrevIconCount="0"
    else:
        PrevIconCount=int(PrevIconCount)+1
    if PrevIconCount>=8:
        PrevIconCount=0
    PrevIconCount=str(PrevIconCount)
    if PrevIconCount=="0":
        IconDisplay="|"
    if PrevIconCount=="1":
        IconDisplay="/"
    if PrevIconCount=="2":
        IconDisplay="-"
    if PrevIconCount=="3":
        IconDisplay="\\"
    if PrevIconCount=="4":
        IconDisplay="|"
    if PrevIconCount=="5":
        IconDisplay="/"
    if PrevIconCount=="6":
        IconDisplay="-"
    if PrevIconCount=="7":
        IconDisplay="\\"
    if ContinueBack=="0":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
        sys.stdout.write("\r")
        sys.stdout.flush()
        sys.stdout.write (" " * TWidth + "\r")
        sys.stdout.flush()
        sys.stdout.write(DisplayText)
        sys.stdout.flush()
    if ContinueBack=="1":
        sys.stdout.write(DisplayText)
        sys.stdout.flush()
    if ContinueBack=="2":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
        sys.stdout.write("\r")
        sys.stdout.flush()
        sys.stdout.write (" " * TWidth + "\r")
        sys.stdout.flush()
        sys.stdout.write(bcolor + "[" + icolor + str(IconDisplay) + bcolor + "]" + __builtin__.tabspace + DisplayText)
        sys.stdout.flush()
    return str(PrevIconCount);

def CenterText(CTxtColor, DisplayText):
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    DisplayTextL=len(DisplayText) 
    HWidth=(TWidth / 2) - (DisplayTextL / 2)
    SPA=" " * HWidth 
    SWidth=TWidth - (HWidth + DisplayTextL)
    SPA2=" " * SWidth 
    print CTxtColor + SPA + DisplayText + SPA2 + "" + fcolor.CReset

def printd(PrintText):
    if __builtin__.DEBUG==1:
        print fcolor.CDebugB  + "[DBG]  " + fcolor.CDebug + PrintText  + fcolor.CReset
    if __builtin__.DEBUG==2:
        print fcolor.CDebugB + "[DBG]  " + fcolor.CDebug + PrintText + fcolor.CReset
        print fcolor.CReset + fcolor.White + "       [Break - Press Any Key To Continue]" + fcolor.CReset
        read_a_key()

def DrawLine(LineChr,LineColor,LineCount,ToHide):
    """
    Function	     : Drawing of Line with various character type, color and count
    Usage of DrawLine:
        LineChr      - Character to use as line
        LineColor    - Color of the line
        LineCount    - Number of character to print. "" is print from one end to another
    Examples         : Lookup DemoDrawLine for examples
    """
    printd(fcolor.CDebugB + "DrawLine Function\n" + fcolor.CDebug + "       LineChr - " + str(LineChr) + "\n       " + "LineColor = " + str(LineColor) + "\n       " + "LineCount = " + str(LineCount))
    if LineColor=="":
        LineColor=fcolor.SBlack
    if LineChr=="":
        LineChr="_"
    if LineCount=="":
        curses.setupterm()
        TWidth=curses.tigetnum('cols')
        TWidth=TWidth-1
    else:
        TWidth=LineCount
    if ToHide=="":
        print LineColor + LineChr * TWidth
    else:
        return LineColor + LineChr * TWidth

def CombineListing(List1, List2, List3, List4, List5, List6, List7, List8):
    __builtin__.MergedList=[]
    __builtin__.MergedSpaceList=[]
    __builtin__.TitleList=[]
    CombineText="";ListMax1=0;ListMax2=0;ListMax3=0;ListMax4=0;ListMax5=0;ListMax6=0;ListMax7=0;ListMax8=0;x=0
    if str(List1)!="":
        while x < len(List1):
            if str(List1[x])!="":
                ETxt=RemoveColor(str(List1[x]))
                if len(ETxt)>ListMax1:
                    ListMax1=len(ETxt)
            x = x +1
        printd ("ListMax1 : " + str(ListMax1))
        ListMax1 = ListMax1 + 4
    x=0
    if str(List2)!="":
        while x < len(List2):
            if str(List2[x])!="":
                ETxt=RemoveColor(str(List2[x]))
                if len(ETxt)>ListMax2:
                    ListMax2=len(ETxt)
            x = x +1
        printd ("ListMax2 : " + str(ListMax2))
        ListMax2 = ListMax2 + 4
    x=0
    if str(List3)!="":
        while x < len(List3):
            if str(List3[x])!="":
                ETxt=RemoveColor(str(List3[x]))
                if len(ETxt)>ListMax3:
                    ListMax3=len(ETxt)
            x = x +1
        printd ("ListMax3 : " + str(ListMax3))
        ListMax3 = ListMax3 + 4
    x=0
    if str(List4)!="":
        while x < len(List4):
            if str(List4[x])!="":
                ETxt=RemoveColor(str(List4[x]))
                if len(ETxt)>ListMax4:
                    ListMax4=len(ETxt)
            x = x +1
        printd ("ListMax4 : " + str(ListMax4))
        ListMax4 = ListMax4 + 4
    x=0
    if str(List5)!="":
        while x < len(List5):
            if str(List5[x])!="":
                ETxt=RemoveColor(str(List5[x]))
                if len(ETxt)>ListMax5:
                    ListMax5=len(ETxt)
            x = x +1
        printd ("ListMax5 : " + str(ListMax5))
        ListMax5 = ListMax5 + 4
    x=0
    if str(List6)!="":
        while x < len(List6):
            if str(List6[x])!="":
                ETxt=RemoveColor(str(List6[x]))
                if len(ETxt)>ListMax6:
                    ListMax6=len(ETxt)
            x = x +1
        printd ("ListMax6 : " + str(ListMax6))
        ListMax6 = ListMax6 + 4
    x=0
    if str(List7)!="":
        while x < len(List7):
            if str(List7[x])!="":
                ETxt=RemoveColor(str(List7[x]))
                if len(ETxt)>ListMax7:
                    ListMax7=len(ETxt)
            x = x +1
        printd ("ListMax7 : " + str(ListMax7))
        ListMax7 = ListMax7 + 4
    x=0
    if str(List8)!="":
        while x < len(List8):
            if str(List8[x])!="":
                ETxt=RemoveColor(str(List8[x]))
                if len(ETxt)>ListMax8:
                    ListMax8=len(ETxt)
            x = x +1
        printd ("ListMax8 : " + str(ListMax8))
        ListMax8 = ListMax8 + 4
    printd ("ListMax1 - After + 4 : " + str(ListMax1))
    printd ("ListMax2 - After + 4 : " + str(ListMax2))
    printd ("ListMax3 - After + 4  : " + str(ListMax3))
    printd ("ListMax4 - After + 4  : " + str(ListMax4))
    printd ("ListMax5 - After + 4  : " + str(ListMax5))
    printd ("ListMax6 - After + 4  : " + str(ListMax6))
    printd ("ListMax7 - After + 4  : " + str(ListMax7))
    printd ("ListMax8 - After + 4  : " + str(ListMax8))
    __builtin__.MergedSpaceList.append(5)
    __builtin__.MergedSpaceList.append(ListMax1)
    __builtin__.MergedSpaceList.append(ListMax2)
    __builtin__.MergedSpaceList.append(ListMax3)
    __builtin__.MergedSpaceList.append(ListMax4)
    __builtin__.MergedSpaceList.append(ListMax5)
    __builtin__.MergedSpaceList.append(ListMax6)
    __builtin__.MergedSpaceList.append(ListMax7)
    __builtin__.MergedSpaceList.append(ListMax8)
    i=0
    while i < len(List1):
        remain1spc=ListMax1 - len(RemoveColor(List1[i]))
        CombineText=List1[i] + "<#&!#>" + " " * remain1spc
        if str(List2)!="":
            if str(List2[i])!="":
                remainspc=ListMax2 - len(RemoveColor(List2[i]))
                CombineText=CombineText  + List2[i] + " " * remainspc
            else:
                CombineText=CombineText + " " * ListMax2
        if str(List3)!="":
            if str(List3[i])!="":
                remainspc=ListMax3 - len(RemoveColor(List3[i]))
                CombineText=CombineText + "" + List3[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax3
        if str(List4)!="":
            if str(List4[i])!="":
                remainspc=ListMax4 - len(RemoveColor(List4[i]))
                CombineText=CombineText + "" + List4[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax4
        if str(List5)!="":
            if str(List5[i])!="":
                remainspc=ListMax5 - len(RemoveColor(List5[i]))
                CombineText=CombineText + "" + List5[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax5
        if str(List6)!="":
            if str(List6[i])!="":
                remainspc=ListMax6 - len(RemoveColor(List6[i]))
                CombineText=CombineText + "" + List6[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax6
        if str(List7)!="":
            if str(List7[i])!="":
                remainspc=ListMax7 - len(RemoveColor(List7[i]))
                CombineText=CombineText + "" + List7[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax7
        if str(List8)!="":
            if str(List8[i])!="":
                remainspc=ListMax8 - len(RemoveColor(List8[i]))
                CombineText=CombineText + "" + List8[i] + " " * remainspc
            else:
                CombineText=CombineText + "" + " " * ListMax8
        CombineText=CombineText.lstrip().rstrip()
        __builtin__.MergedList.append(str(CombineText))
        i = i + 1
    return i;

def QuestionFromList(ListTitle,ListTitleSpace,ListUse,AskQuestion,RtnType):
    __builtin__.ListingIndex=""
    bcolor=fcolor.SWhite
    pcolor=fcolor.BYellow
    ttcolor=fcolor.BBlue
    lcolor=fcolor.SYellow
    scolor=fcolor.BRed
    tcolor=fcolor.BGreen
    x=0
    sn=0
    CombineTitle=""
    totallen=0
    while x < len(ListTitle):
        xlen=len(ListTitle[x])
        remainspc=ListTitleSpace[x] - xlen
        if x==8:
            remainspc = remainspc - 4
            if remainspc<1:
                remainspc=1
        CombineTitle=CombineTitle + ListTitle[x] + " " * remainspc
        x = x +1 
    totallen=len(CombineTitle) + 1
    printl("    ","1","")
    DrawLine("=",fcolor.SWhite,totallen,"")
    print bcolor + "[" + pcolor + "*" + bcolor + "]  " + ttcolor + str(CombineTitle) + fcolor.CReset
    printl("    ","1","")
    DrawLine("=",fcolor.SWhite,totallen,"")
    for i, showtext in enumerate(ListUse):
        sn=i + 1
        remainspc = 4 - len(str(sn))
        showtext=showtext.replace("<#&!#>","")
        print "     " +scolor + str(sn) + "." + " " * remainspc + lcolor+ showtext
    printl("    ","1","")
    DrawLine("^",fcolor.SWhite,totallen,"")
    usr_resp=raw_input (bcolor + "[" + pcolor + "?" + bcolor + "]  " + tcolor + str(AskQuestion) + " [ " + scolor + "1" + tcolor + "-" + scolor + str(sn) + tcolor + " / " + scolor + "0" + fcolor.SWhite + " = Cancel" + tcolor + " ] : " + fcolor.BWhite)
    while not usr_resp.isdigit() or int(usr_resp) < 0 or int(usr_resp) > len(ListUse):
        print ""
        Result=QuestionFromList(ListTitle,ListTitleSpace,ListUse,AskQuestion,RtnType)
        return str(Result)
    if RtnType=="1":
        usr_resp = int(usr_resp) - 1
        __builtin__.ListingIndex=usr_resp
        SelList=ListUse[int(usr_resp)]
        SelList=SelList.replace("<#&!#>","\t")
        SelList=RemoveColor(SelList)
        POS=SelList.find("\t", 2) +1
        SelList=SelList[:POS]
        Rtn=SelList
        ps=subprocess.Popen("echo " + str(SelList) + " | cut -d '\t' -f1" , shell=True, stdout=subprocess.PIPE)	
        Rtn=ps.stdout.read()
        Rtn=Rtn.replace("\n","")
        if usr_resp==-1:
            usr_resp=0
            Rtn="0"
        return Rtn;
    else:
        usr_resp=usr_resp.replace("\n","")
        __builtin__.ListingIndex=usr_resp
        return usr_resp;

def DelFile(strFileName,ShowDisplay):
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0
    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(strFileName)
        if Result=="F":
            os.remove(strFileName)
            RtnResult=True
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "File [ " + fcolor.SRed + strFileName + fcolor.SGreen + " ] deleted.","")
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "File [ " + fcolor.SYellow + strFileName + fcolor.SRed + " ] does not exist.","")
        return RtnResult
    else:
        filelist = glob.glob(strFileName)
        fc=0
        for f in filelist:
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "Deleting [ " + fcolor.SRed + str(f) + fcolor.SGreen + " ]...","")
            os.remove(f)
            fc=fc+1
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.SGreen + " ] files deleted.","")
        RtnResult=True
    return RtnResult

def MoveInstallationFiles(srcPath,dstPath):
    import shutil
    listOfFiles = os.listdir(srcPath)
    listOfFiles.sort()
    for f in listOfFiles:
        if f!=".git" and f!=".gitignore":
            srcfile = srcPath + f
            dstfile = dstPath + f
            if f==__builtin__.ScriptName:
                shutil.copy2(srcfile, "/usr/sbin/" + str(__builtin__.ScriptName))
                printd("Copy to " + "/usr/sbin/" + str(__builtin__.ScriptName))
                result=os.system("chmod +x /usr/sbin/" + __builtin__.ScriptName + " > /dev/null 2>&1")
                printd("chmod +x " + "/usr/sbin/" + str(__builtin__.ScriptName))
            if os.path.exists(dstfile):
                os.remove(dstfile)
            shutil.move(srcfile, dstfile)
            print fcolor.SGreen + "        Moving " + fcolor.CUnderline + f + fcolor.CReset + fcolor.SGreen + " to " + dstfile
            if f==__builtin__.ScriptName:
                result=os.system("chmod +x " + dstfile + " > /dev/null 2>&1")
                printd("chmod +x " + str(dstfile))

def GetScriptVersion(cmdScriptName):
    if cmdScriptName=="":
        cmdScriptName=__builtin__.ScriptFullPath
    VerStr=""
    findstr="appver=\""
    printd ("Get Version : " + cmdScriptName)
    if os.path.exists(cmdScriptName)==True:
        ps=subprocess.Popen("cat " + cmdScriptName + " | grep '" + findstr + "' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
        VerStr=ps.stdout.read()
        VerStr=VerStr.replace("appver=\"","")
        VerStr=VerStr.replace("\"","")
        VerStr=VerStr.replace("\n","")
        return VerStr;

def GetUpdate(ExitMode):
    if ExitMode=="":
        ExitMode="1"
    github="https://github.com/SYWorks/WAIDPS.git"
    Updatetmpdir="/tmp/git-update-wh/"
    DownloadedScriptLocation=Updatetmpdir + __builtin__.ScriptName
    dstPath=os.getcwd() + "/"
    dstPath=appdir
    dstScript=dstPath + __builtin__.ScriptName
    CurVersion=GetScriptVersion(dstScript)
    printc (".","Retrieving update details ....","")
    result=RemoveTree(Updatetmpdir,"")
    result=os.system("git clone " + github + " " + Updatetmpdir + " > /dev/null 2>&1")
    if result==0:
        printc (" ",fcolor.SGreen + "Package downloaded..","")
        NewVersion=GetScriptVersion(DownloadedScriptLocation)
        if CurVersion!=NewVersion:
            printc ("i","Current Version\t: " + fcolor.BRed + str(CurVersion),"")
            printc ("  ",fcolor.BWhite + "New Version\t: " + fcolor.BRed + str(NewVersion),"")
            Ask=AskQuestion ("Do you want to update ?","Y/n","","Y","")
            if Ask=="y" or Ask=="Y" or Ask=="":
                srcPath=Updatetmpdir
                result=MoveInstallationFiles(srcPath,dstPath)
                result=os.system("chmod +x " + dstScript + " > /dev/null 2>&1")
                result=RemoveTree(Updatetmpdir,"")
                print ""
                printc ("i",fcolor.BGreen + "Application updated !!","")
                printc ("  ",fcolor.SGreen + "Re-run the updated application on [ " + fcolor.BYellow + dstScript + fcolor.SGreen + " ]..","")
                if ExitMode=="1":
                    exit(0)
                else:
                    return
            else:
                printc ("i",fcolor.BWhite + "Update aborted..","")
                result=RemoveTree(Updatetmpdir,"")
        else:
            printc ("i","Your already have the latest version [ " + fcolor.BRed + str(CurVersion) + fcolor.BWhite + " ].","")
            printc ("  ",fcolor.BWhite + "Update aborted..","")
            result=RemoveTree(Updatetmpdir,"")
            if ExitMode=="1":
                exit(0)
            else:
                return
    else:
        printd ("Unknown Error : " + str(result))
        printc ("!!!","Unable to retrieve update !!","")
        if ExitMode=="1":
            exit(1)
        else:
            return

def GetDir(LookupPath):
    """
        Function   : Return the varius paths such as application path, current path and Temporary path
        Example    : 
    """
    import os
    import tempfile
    pathname, scriptname = os.path.split(sys.argv[0])
    if LookupPath=="":
        LookupPath="appdir"
    LookupPath=LookupPath.lower()
    if LookupPath=="curdir":
        result=os.getcwd()
    if LookupPath=="appdir":
       result=os.path.realpath(os.path.dirname(sys.argv[0]))
    if LookupPath=="exedir":
        result=os.path.dirname(sys.executable)
    if LookupPath=="relativedir":
        result=pathname
    if LookupPath=="scriptdir":
        result=os.path.abspath(pathname)
    if LookupPath=="sysdir":
        result=sys.path[0]
    if LookupPath=="pypath":
        result=sys.path[1]
    if LookupPath=="homedir":
        result=os.environ['HOME']
    if LookupPath=="tmpdir":
        result=tempfile.gettempdir()
    if LookupPath=="userset":
        result=appdir
    result=result + "/"
    if result[-2:]=="//":
        result=result[:len(str(result))-1]
    return result;

def CheckLinux():
    """
        Function : Check for Current OS. Exit if not using Linux
    """
    from subprocess import call
    from platform import system
    os = system()
    printd ("Operating System : " + os)
    if os != 'Linux':
        printc ("!!!","This application only works on Linux.","")
        exit(1)

def CheckPyVersion(MinPyVersion):
    """
        Function : Check for current Python Version. 
                   Exit if current version is less than MinPyVersion
    """
    import platform
    PyVersion = platform.python_version()
    printd ("Python Version : " + PyVersion)
    if MinPyVersion!="":
        if MinPyVersion >= PyVersion:
            printc ("!!!",fcolor.BGreen + "Your Python version " + fcolor.BRed + str(PyVersion) + fcolor.BGreen + " may be outdated.","")
            printc ("  ",fcolor.BWhite + "Minimum version required for this application is " + fcolor.BRed + str(MinPyVersion) + fcolor.BWhite + ".","")
            exit(0)

def GetAppName():
    """
        Function : Get Current Script Name
        Return   : ScriptName  = Actual script name
                   __builtin__.DScriptName = For Display
    """
    __builtin__.ScriptName=os.path.basename(__file__)
    __builtin__.DScriptName="./" + __builtin__.ScriptName
    appdir=os.path.realpath(os.path.dirname(sys.argv[0]))
    __builtin__.FullScriptName=str(appdir) + "/" + str(__builtin__.ScriptName)
    printd("__builtin__.FullScriptName : " + __builtin__.FullScriptName)
    printd("ScriptName : " + str(__builtin__.ScriptName))

def ShowBanner():
    Ver=fcolor.BWhite + "  Version " + appver + " (Updated - " + appupdated + ")"
    wordart = random.randrange(1,10+1)
    if wordart == 1:
        print fcolor.BGreen + """ __          __     _____ _____  _____   _____ 
 \ \        / /\   |_   _|  __ \|  __ \ / ____|
  \ \  /\  / /  \    | | | |  | | |__) | (___  
   \ \/  \/ / /\ \   | | | |  | |  ___/ \___ \ 
    \  /\  / ____ \ _| |_| |__| | |     ____) |
     \/  \/_/    \_\_____|_____/|_|    |_____/ """ + str(Ver)
        return
    if wordart == 2:
        print fcolor.BGreen + " _    _  ___  _________________  _____ "
        print fcolor.BGreen + "| |  | |/ _ \\|_   _|  _  \\ ___ \\/  ___|"
        print fcolor.BGreen + "| |  | / /_\\ \\ | | | | | | |_/ /\\ `--. "
        print fcolor.BGreen + "| |/\\| |  _  | | | | | | |  __/  `--. \\"
        print fcolor.BGreen + "\\  /\\  / | | |_| |_| |/ /| |    /\\__/ /"
        print fcolor.BGreen + " \\/  \\/\\_| |_/\\___/|___/ \\_|    \\____/ "+ str(Ver)
        return
    if wordart == 3:
        print fcolor.BGreen + " __      __  _____  .___________ __________  _________"
        print fcolor.BGreen + "/  \\    /  \\/  _  \\ |   \\______ \\\\______   \\/   _____/"
        print fcolor.BGreen + "\\   \\/\\/   /  /_\\  \\|   ||    |  \\|     ___/\\_____  \\ "
        print fcolor.BGreen + " \\        /    |    \\   ||    `   \\    |    /        \\"
        print fcolor.BGreen + "  \\__/\\  /\\____|__  /___/_______  /____|   /_______  /"
        print fcolor.BGreen + "       \\/         \\/            \\/                 \\/ "+ str(Ver)
        return
    if wordart == 4:
        print fcolor.BGreen + """ ____      ____  _       _____  ______   _______    ______   
|_  _|    |_  _|/ \     |_   _||_   _ `.|_   __ \ .' ____ \  
  \ \  /\  / / / _ \      | |    | | `. \ | |__) || (___ \_| 
   \ \/  \/ / / ___ \     | |    | |  | | |  ___/  _.____`.  
    \  /\  /_/ /   \ \_  _| |_  _| |_.' /_| |_    | \____) | 
     \/  \/|____| |____||_____||______.'|_____|    \______.' """+ str(Ver)
        return
    if wordart == 5:
        print fcolor.BGreen + """ _       _  _____  _  ___    ___    ___   
( )  _  ( )(  _  )(_)(  _`\ (  _`\ (  _`\ 
| | ( ) | || (_) || || | ) || |_) )| (_(_)
| | | | | ||  _  || || | | )| ,__/'`\__ \ 
| (_/ \_) || | | || || |_) || |    ( )_) |
`\___x___/'(_) (_)(_)(____/'(_)    `\____)"""+ str(Ver)
        return
    if wordart == 6:
        print fcolor.BGreen + """ _       _____    ________  ____  _____
| |     / /   |  /  _/ __ \/ __ \/ ___/
| | /| / / /| |  / // / / / /_/ /\__ \ 
| |/ |/ / ___ |_/ // /_/ / ____/___/ / 
|__/|__/_/  |_/___/_____/_/    /____/  """+ str(Ver)
        return
    if wordart == 7:
        print fcolor.BGreen + """__        ___    ___ ____  ____  ____  
\ \      / / \  |_ _|  _ \|  _ \/ ___| 
 \ \ /\ / / _ \  | || | | | |_) \___ \ 
  \ V  V / ___ \ | || |_| |  __/ ___) |
   \_/\_/_/   \_|___|____/|_|   |____/  """+ str(Ver)
        return
    if wordart == 8:
        print fcolor.BGreen + "__      ___   ___ ___  ___  ___ "
        print fcolor.BGreen + "\\ \\    / /_\\ |_ _|   \\| _ \\/ __|"
        print fcolor.BGreen + " \\ \\/\\/ / _ \\ | || |) |  _/\\__ \\"
        print fcolor.BGreen + "  \\_/\\_/_/ \\_\\___|___/|_|  |___/"+ str(Ver)
        return
    if wordart == 9:
        print fcolor.BGreen + """ __        ___    ___ ____  ____  ____  
 \ \      / / \  |_ _|  _ \|  _ \/ ___| 
  \ \ /\ / / _ \  | || | | | |_) \___ \ 
   \ V  V / ___ \ | || |_| |  __/ ___) |
    \_/\_/_/   \_\___|____/|_|   |____/ """+ str(Ver)
        return
    if wordart == 10:
        print fcolor.BGreen + """##      ##    ###    #### ########  ########   ######  
##  ##  ##   ## ##    ##  ##     ## ##     ## ##    ## 
##  ##  ##  ##   ##   ##  ##     ## ##     ## ##       
##  ##  ## ##     ##  ##  ##     ## ########   ######  
##  ##  ## #########  ##  ##     ## ##              ## 
##  ##  ## ##     ##  ##  ##     ## ##        ##    ## 
 ###  ###  ##     ## #### ########  ##         ######  """+ str(Ver)
        return
                                                                                  

def ShowSYWorks():
    print fcolor.BWhite + " _  _  _  _  _  _  _    _  _  _  _  _  _  _  _  _  _  _ "
    WordColor=fcolor.BUBlue
    BubbleColor=fcolor.BBlue
    BC1="|"
    BC2="|"
    DisplayTxt = BubbleColor + BC1 + WordColor + "S" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "Y" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "W" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "O" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "K" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "S" + fcolor.CReset + BubbleColor + BC2 + "  " + BC1 + WordColor + "P" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "O" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "G" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "R" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "A" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "M" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "M" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "I" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "N" + fcolor.CReset + BubbleColor + BC1 + BC2 + WordColor + "G" + fcolor.CReset + BubbleColor + BC2 + fcolor.SWhite + "  - syworks (at) gmail.com"
    sys.stdout.write(DisplayTxt)
    sys.stdout.flush()

def DisplayAppDetail():
    ShowBanner()
    ShowSYWorks()
    print "";print ""
    print fcolor.BGreen + apptitle + " " + appver + fcolor.SGreen + " " + appDesc
    print fcolor.CReset + fcolor.SWhite + appnote
    print ""

def DisplayDisclaimer():
    printc ("!!!","Legal  Disclaimer :- " + fcolor.Red + "FOR EDUCATIONAL PURPOSES ONLY !!","")
    print fcolor.SWhite + " Usage of this application for attacking target without prior mutual consent is illegal. It is the"
    print fcolor.SWhite + " end user's responsibility to obey all applicable local, state and  federal laws. Author assume no"
    print fcolor.SWhite + " liability and are not responsible for any misuse or damage caused by this application."
    print ""

def DisplayFullDescription():
    print fcolor.BRed + " Description : "
    print fcolor.SGreen + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.SWhite + " "
    print fcolor.BWhite + " "
    print ""

def DisplayDescription():
    print fcolor.BRed + "Description : "
    print fcolor.SWhite + " WAIDPS, Wiresless Auditing, Intrusion Detection & Prevention System is a tool designed to harvest all WiFi information (AP / Station details) in your"
    print fcolor.SWhite + " surrounding and store as a database for reference. With the stored data, user can further lookup for specific MAC or names for detailed information of"
    print fcolor.SWhite + " it relation to other MAC addresses. It primarily purpose is to detect wireless attacks in WEP/WPA/WPS encryption."
    print fcolor.SWhite + " It also comes with an analyzer and viewer which allow user to further probe and investigation on the intrusion/suspicious packets captured. Additional"
    print fcolor.SWhite + " features such as blacklisting which allow user to monitor specific MACs/Names's activities. All information captured can also be saved into pcap files"
    print fcolor.SWhite + " for further investigation."
    print fcolor.SWhite + " "
    print ""

def DisplayDetailHelp():
    print fcolor.BGreen + "Usage   : " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " [options] " + fcolor.BBlue + "<args>"
    print fcolor.CReset + fcolor.Black + "          Running application without parameter will fire up the interactive mode."
    print ""
    print fcolor.BIPink + "Options:" + fcolor.CReset
    print fcolor.BWhite + "    -h  --help\t\t" + fcolor.CReset + fcolor.White + "- Show basic help message and exit"
    print fcolor.BWhite + "    -hh \t\t" + fcolor.CReset + fcolor.White + "- Show advanced help message and exit"
    print fcolor.BWhite + "        --update\t" + fcolor.CReset + fcolor.White + "- Check for updates"
    print fcolor.BWhite + "        --remove\t" + fcolor.CReset + fcolor.White + "- Uninstall application"
    print ""
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Duration to capture before analysing the captured data"
    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0" 
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1" 
    print ""
    DrawLine("-",fcolor.CReset + fcolor.Black,"","")
    print ""

def DisplayHelp():
    print fcolor.BGreen + "Usage   : " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " [options] " + fcolor.BBlue + "<args>"
    print fcolor.CReset + fcolor.Black + "          Running application without parameter will fire up the interactive mode."
    print ""
    print fcolor.BIPink + "Options:" + fcolor.CReset
    print fcolor.BWhite + "    -h  --help\t\t" + fcolor.CReset + fcolor.White + "- Show basic help message and exit"
    print fcolor.BWhite + "    -hh \t\t" + fcolor.CReset + fcolor.White + "- Show advanced help message and exit"
    print ""
    print fcolor.BWhite + "    -i  --iface" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Set Interface to use"
    print fcolor.BWhite + "    -t  --timeout" + fcolor.BBlue + " <arg>\t" + fcolor.CReset + fcolor.White + "- Duration to capture before analysing the captured data"
    print ""
    print fcolor.BGreen + "Examples: " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --update"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " -i " + fcolor.BBlue + "wlan0"
    print fcolor.BGreen + "          " + fcolor.BYellow + "" + DScriptName + fcolor.BWhite + " --iface " + fcolor.BBlue + "wlan1"
    print ""
    DrawLine("-",fcolor.CReset + fcolor.Black,"","")
    print ""

def GetParameter(cmdDisplay):
    """
   cmdDisplay = "0" : Does not display help if not specified
                "1" : Display help even not specified
                "2" : Display Help, exit if error
    """
    __builtin__.ReadPacketOnly=""
    __builtin__.LoopCount=99999999
    __builtin__.SELECTED_IFACE=""
    __builtin__.SELECTED_MON=""
    __builtin__.PRINTTOFILE=""
    __builtin__.ASSIGNED_MAC=""
    __builtin__.SPOOF_MAC=""
    __builtin__.AllArguments=""
    if cmdDisplay=="":
        cmdDisplay="0"
    Err=0
    totalarg=len(sys.argv)
    printd ("Argument Len    : " + str(totalarg))
    printd ("Argument String : " + str(sys.argv))
    if totalarg>1:
        i=1
        while i < totalarg:
            Err=""
            if i>0:
                i2=i+1
                if i2 >= len(sys.argv):
                   i2=i
                   i2str=""
                else:
                   i2str=str(sys.argv[i2])
                argstr=("Argument %d : %s" % (i, str(sys.argv[i])))
                printd (argstr) 
                arg=str(sys.argv[i])
                if arg=="-h" or arg=="--help":
                    DisplayHelp()
                    Err=0
                    exit()
                    break;
                elif arg=="-hh":
                    DisplayDetailHelp()
                    Err=0
                    exit()
                elif arg=="-ro":
                    Err=0
                    __builtin__.ReadPacketOnly="1"
                elif arg=="--update":
                    Err=0
                    GetUpdate("1")
                    exit()
                elif arg=="--remove":
                    Err=0
                    UninstallApplication()
                    exit()
                elif arg=="--spoof":
                    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Spoof MAC\t\t:  " + fcolor.BRed + "Enabled\n"
                    __builtin__.SPOOF_MAC="1"
                    Err=0
                elif arg=="-m" or arg=="--mac":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid MAC Address set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if len(i2str)==17:
                                Result=CheckMAC(i2str)
                                if Result!="":
                                    __builtin__.ASSIGNED_MAC=i2str 
                                    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Selected MAC\t\t:  " + fcolor.BRed + i2str + "\n"
                                    __builtin__.SPOOF_MAC="1"
                                else:
                                    printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                    Err=1
                            else:
                                printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid MAC Address set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-t" or arg=="--timeout":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid timeout variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if i2str.isdigit():
                                __builtin__.TIMEOUT=i2str
                                __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Timeout (Seconds)\t:  " + fcolor.BRed + str(__builtin__.TIMEOUT) + "\n"
                                if float(__builtin__.TIMEOUT)<20:
				    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.SWhite + "\t\t\t:  Timeout second set may be to low for detection.\n"
                            else:
                                printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid timeout variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-l" or arg=="--loop":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid __builtin__.LoopCount variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            if i2str.isdigit():
                                __builtin__.LoopCount=i2str
                                if float(__builtin__.LoopCount)<1:
				    __builtin__.AllArguments=__builtin__.AllArguments + fcolor.SWhite + "\t\t\t:  Minimum loop count is 1.\n"
                                    __builtin__.LoopCount=1
                                __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Loop Count\t\t:  " + fcolor.BRed + str(__builtin__.LoopCount) + "\n"
                            else:
                                printc("!!!","Invalid loop count variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                                Err=1
                        else:
                            printc("!!!","Invalid loop count variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif arg=="-i" or arg=="--iface":
                    i=i2
                    if i2str=="":
                        printc("!!!","Invalid Interface variable set !","")  
                        Err=1
                    else:
                        Err=0
                        if i2str[:1]!="-":
                            __builtin__.SELECTED_IFACE=i2str
                            __builtin__.AllArguments=__builtin__.AllArguments + fcolor.BWhite + "Selected interface\t:  " + fcolor.BRed + i2str + "\n"
                        else:
                            printc("!!!","Invalid Interface variable set [ " + fcolor.BWhite + i2str + fcolor.BRed + " ] !","")  
                            Err=1
                elif Err=="":
                        DisplayHelp()
                        printc("!!!","Invalid option set ! [ " + fcolor.BGreen + arg + fcolor.BRed + " ]","")
                        Err=1
                        exit(0)
                if Err==1:
                    if cmdDisplay=="2":
                        print ""
                        DisplayHelp()
                        exit(0)
                i=i+1
        if __builtin__.AllArguments!="":
            print fcolor.BYellow + "Parameter set:"
            print __builtin__.AllArguments
        else:
            print ""
            DisplayHelp()
        print ""
        printc ("i", fcolor.BCyan + "Entering Semi-Interactive Mode..","")
        result=DisplayTimeStamp("start","")
        print ""
    else:
        if cmdDisplay=="1":
            DisplayHelp()
        if cmdDisplay=="2":
            DisplayHelp()
            exit(0)
        else:
            printc ("i", fcolor.BCyan + "Entering Interactive Mode..","")
            result=DisplayTimeStamp("start","")
            print ""

def GetFileLine(filename,omitblank):
    if omitblank=="":
        omitblank="0"
    if omitblank=="1":
        with open(filename, 'r') as f: 
            lines = len(list(filter(lambda x: x.strip(), f)))
        __builtin__.TotalLine=lines
        __builtin__.UsableLine=lines
    if omitblank=="0":
        with open(filename) as f:
            lines=len(f.readlines())
        __builtin__.TotalLine=lines
        __builtin__.UsableLine=lines
    if omitblank=="2":
        lines=0
	with open(filename,"r") as f:
	    for line in f:
                sl=len(line.replace("\n",""))
                if sl>0:
                    __builtin__.TotalLine=__builtin__.TotalLine+1
                    if sl>=8 and sl<=63:
                        lines=lines+1
                        __builtin__.UsableLine=lines
    return lines

def CheckMAC(MACAddr):
    import string
    result=""
    allchars = "".join(chr(a) for a in range(256))
    delchars = set(allchars) - set(string.hexdigits)
    mac = MACAddr.translate("".join(allchars),"".join(delchars))
    if len(mac) != 12:
        return result;
    else:
        result=MACAddr.upper()
    return result;

def Explore(DirUrlName,ShowDisplay):
    if ShowDisplay=="":
        ShowDisplay=0
    Result=-1
    if DirUrlName!="":
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Opening location [ " + fcolor.SRed + DirUrlName + fcolor.SGreen + " ] ...","")
        Result=os.system("xdg-open " + str(DirUrlName) + " > /dev/null 2>&1")
    return Result

def UninstallApplication():
    Ask=AskQuestion ("Are you sure you want to remove this application ?","y/N","","N","")
    if Ask=="y" or Ask=="Y":
        curdir=os.getcwd() + "/"
        CurFileLocation=curdir + ScriptName
        if os.path.exists(CurFileLocation)==True:
            printd("Delete File : " + CurFileLocation)
            result=os.remove(CurFileLocation)
        if os.path.exists("/usr/sbin/" + ScriptName)==True:
            printd("Delete File : " + "/usr/sbin/" + str(ScriptName))
            result=os.remove("/usr/sbin/" + ScriptName)
        if os.path.exists(appdir)==True:
            printd("Remove Path : " + appdir)
            result=RemoveTree(appdir,"")
        Ask=AskQuestion ("Do you want to delete all the Database files created ?","y/N","","N","")
        if Ask=="Y":
            Delfile (__builtin__.FilenameHeader + "*.*","1")
        printc ("i", "Application successfully removed !!","")
        exit(0)
    else:
        printc ("i",fcolor.BWhite + "Uninstall aborted..","")
        exit(0)

def SelectInterfaceToUse():
    printc ("i", fcolor.BRed + "Wireless Adapter Selection","")
    Result = GetInterfaceList("MAN")
    if Result==0:
        printc ("!", fcolor.SRed + "No wireless adapter adapter found !!","")
        exit()
    Result = CombineListing(__builtin__.IFaceList, __builtin__.MACList,__builtin__.UpDownList,__builtin__.IEEEList,__builtin__.StatusList,__builtin__.ModeList,"","")
    if int(Result)>1:
        __builtin__.TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','Mode','','']
        Result=QuestionFromList(__builtin__.TitleList, __builtin__.MergedSpaceList,__builtin__.MergedList,"Select the interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectInterfaceToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        __builtin__.SELECTED_IFACE=__builtin__.IFaceList[int(Result)]
    else:
        __builtin__.SELECTED_IFACE=__builtin__.IFaceList[0]
    return __builtin__.SELECTED_IFACE;

def Run(cmdRun,Suppress):
    if Suppress=="":
        Suppress="1"
    rtncode=-1
    cmdExt=""
    if cmdRun=="":
        return rtncode;
    if cmdRun.find(">")!=-1 or cmdRun.find(">>")!=-1:
        Suppress="0"
    if Suppress=="1":
        cmdExt=" > /dev/null 2>&1"
    ps=Popen(str(cmdRun) + str(cmdExt), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
    pid=ps.pid 
    readout=ps.stdout.read()
    return str(readout)

def SelectMonitorToUse():
    time.sleep (0)
    MonCt = GetInterfaceList("MON")
    if MonCt==0:
        printc ("i", fcolor.BRed + "Monitoring Adapter Selection","")
    MonCt = GetInterfaceList("MON")
    if MonCt==0:
        printc ("!", fcolor.SRed + "No monitoring adapter found !!","")
        exit()
    Result = CombineListing(__builtin__.IFaceList, __builtin__.MACList,__builtin__.UpDownList,__builtin__.IEEEList,__builtin__.StatusList,"","","")
    if int(Result)>1:
        __builtin__.TitleList=['Sel','Iface','MAC Address','Up ?', 'IEEE','Status','','','']
        Result=QuestionFromList(__builtin__.TitleList, __builtin__.MergedSpaceList,__builtin__.MergedList,"Select the monitoring interface from the list","0")
        if Result=="0":
                 Result=AskQuestion(fcolor.SGreen + "You need to select a monitoring interface to use," + fcolor.BGreen + " retry ?","Y/n","U","Y","1")
                 if Result=="Y":
                     Result=SelectMonitorToUse()
                     return Result
                 else:
                     exit(0)
        Result=int(Result)-1
        __builtin__.SELECTED_MON=__builtin__.IFaceList[int(Result)]
    else:
        __builtin__.SELECTED_MON=__builtin__.IFaceList[0]
    return __builtin__.SELECTED_MON;

def IsFileDirExist(strFilePath):
    """
        Function   : Check if a file/path exist
        Return     : "F" - Exist File 
                   : "D" - Exist Directory
                   : "E" - Does not exist
    """
    RtnResult="E"
    if os.path.exists(strFilePath)==True:
        if os.path.isfile(strFilePath)==True:
            RtnResult="F"
        if os.path.isdir(strFilePath)==True:
            RtnResult="D"
    return RtnResult;

def ShutdownMonitor():
    ps=subprocess.Popen("iw probe0 del  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    ps=subprocess.Popen("iw wlmon0 del  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    ps=subprocess.Popen("killall 'airodump-ng' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    ps=subprocess.Popen("killall 'tshark' > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE)	
    time.sleep(0.1)
    ps.wait();ps.stdout.close()

def exit_gracefully(code=0):
    os.system("stty echo")
    KillAllMonitor()
    printc (" ","","")
    printc ("*", fcolor.BRed + "Application shutdown !!","")
    if __builtin__.TimeStart!="":
        result=DisplayTimeStamp("summary-a","")
    if __builtin__.PrintToFile=="1":
        print fcolor.BGreen + "     Result Log\t: " + fcolor.SGreen + LogFile
        open(LogFile,"a+b").write("\n\n")
    __builtin__.PrintToFile="0"
    print ""
    ShutdownMonitor()
    if __builtin__.ERRORFOUND!=1:
        print ""
        print fcolor.BWhite + "Please support by liking my page at " + fcolor.BBlue + "https://www.facebook.com/syworks" +fcolor.BWhite + " (SYWorks-Programming)"
    print fcolor.BRed + __builtin__.ScriptName + " Exited." 
    print ''
    readline.write_history_file(__builtin__.CommandHistory)
    exit(code)

def AddTime(tm, secs):
    fulldate = datetime.datetime(tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second)
    fulldate = fulldate + datetime.timedelta(seconds=secs)
    return fulldate

def Percent(val, digits):
    val *= 10 ** (digits + 2)
    return '{1:.{0}f} %'.format(digits, floor(val) / 10 ** digits)

def ChangeHex(n):
    x = (n % 16)
    c = ""
    if (x < 10):
        c = x
    if (x == 10):
        c = "A"
    if (x == 11):
        c = "B"
    if (x == 12):
        c = "C"
    if (x == 13):
        c = "D"
    if (x == 14):
        c = "E"
    if (x == 15):
        c = "F"
    if (n - x != 0):
        Result=ChangeHex(n / 16) + str(c)
    else:
        Result=str(c)
    if len(Result)==1:
        Result="0" + str(Result)
    if len(Result)==3:
        Result=Result[-2:]
    return Result

def SpoofMAC(IFACE,ASSIGNED_MAC):
    if ASSIGNED_MAC=="":
        H1="00"
        H2=ChangeHex(random.randrange(255))
        H3=ChangeHex(random.randrange(255))
        H4=ChangeHex(random.randrange(255))
        H5=ChangeHex(random.randrange(255))
        H6=ChangeHex(random.randrange(255))
        ASSIGNED_MAC=str(H1) + ":" + str(H2) + ":" + str(H3) + ":" + str(H4) + ":" + str(H5) + ":" + str(H6) 
    Result=""
    ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    MACADDR=MACADDR[:17]
    if str(MACADDR)!=ASSIGNED_MAC:
        printc ("i",fcolor.BRed + "Spoofing [ " + str(IFACE) + " ] MAC Address","")
        printc (" ",fcolor.BBlue + "Existing MAC\t: " + fcolor.BWhite + str(MACADDR),"")
        printc (" ",fcolor.BBlue + "Spoof MAC\t\t: " + fcolor.BWhite +  str(ASSIGNED_MAC),"")
        Result=MACADDR
        Ask=AskQuestion("Continue to spoof the MAC Address ?","Y/n","U","Y","0")
        if Ask=="Y":
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " down hw ether " + str(ASSIGNED_MAC) + " > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
            time.sleep(1)
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE)
            NEWADDR=""
            NEWADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
            NEWADDR=NEWADDR[:17]
            ps.wait();ps.stdout.close()
            if str(NEWADDR)==str(ASSIGNED_MAC):
                printc (" ",fcolor.BBlue + "MAC Address successfully changed to [ " + fcolor.BYellow + str(ASSIGNED_MAC) + fcolor.BBlue + " ]","")
                Result=str(ASSIGNED_MAC)
            else:
                printc (" ",fcolor.BRed + "Failed to change MAC Address !!","")
                Ask=AskQuestion("Retry with a new MAC Address ?","Y/n","U","Y","0")
                if Ask=="Y":
                    Result=SpoofMAC(IFACE,"")
                    return Result;
                else:
                    printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
                    printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(NEWADDR) + fcolor.BBlue + " ]","")
                    return Result
        else:
            printc (" ",fcolor.BRed + "You choose to abort spoofing of MAC address.","")
            printc (" ",fcolor.BBlue + "Using MAC Address [ " + fcolor.BYellow + str(MACADDR) + fcolor.BBlue + " ]","")
    return Result
class Command(object):

    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):

        def target():
	    printd ("Thread started")
            self.process = subprocess.Popen(self.cmd, shell=True)
            self.process.communicate()
	    printd ("Thread Finish")
        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
	    printd ("Terminating process..")
            self.process.terminate()
            thread.join()
	    printd ("Process Terminated")

def IsAscii(inputStr):
    return all(ord(c) < 127 and ord(c) > 31 for c in inputStr)

def CheckSSIDChr(ESSID_Name):
    if IsAscii(ESSID_Name)==False:
        ESSID_Name=""
    return ESSID_Name

def IsProgramExists(program):
    """
	Check if program exist
    """
    proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
	return False
    if txt[0].strip() != '' and txt[1].strip() == '':
	return True
    return not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)

def DownloadFile(sURL,FileLoc,ToDisplay):
  try:
    if ToDisplay=="1":
        printc ("..","Downloading file from " + fcolor.BBlue + str(sURL),"")
    urllib.urlretrieve(sURL,FileLoc)
    if IsFileDirExist(__builtin__.MACOUI)=="F":
        printc ("i","File successfully saved to " + FileLoc,"")
    else:
        printc ("!!!","File failed to save. Please do it manually.","")
    return;
  except:
    printc ("!!!","Error downloading... please make sure you run as root and have internet access.","")

def CheckRequiredFiles():
    MISSING_FILE=0
    ERROR_MSG=""
    for req_file in __builtin__.RequiredFiles:
        if IsProgramExists(req_file): continue
	ERROR_MSG= ERROR_MSG + str(printc (" ","<$rs$>" + fcolor.SGreen + "Required file not found - " + fcolor.BRed + str(req_file) + "\n",""))
        MISSING_FILE += 1
    if MISSING_FILE!=0:
        TXT_1=""
        TXT_2="was"
        if MISSING_FILE>1:
            TXT_1="s"
            TXT_2="were"
        print ""
	printc ("!!!",fcolor.BGreen + "The following file" + TXT_1 + " required by " + apptitle + " " + TXT_2 + " not found:- " ,"")
        print ERROR_MSG
        print ""
        printc ("..","Developer does not provide any support on how you could install all these application.","")
        printc ("..","To save the hassle, run this script on Backtrack/Kali Linux as all these required applications are already preinstalled.","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    if IsFileDirExist(__builtin__.MACOUI)!="F":
        printc ("!!!","MAC OUI Database (Optional) not found !","")
        printc ("  ",fcolor.SGreen + "Database can be downloaded at " + fcolor.SBlue + "https://raw.githubusercontent.com/SYWorks/Database/master/mac-oui.db","")
        printc ("  ",fcolor.SGreen + "Copy the download file " + fcolor.BGreen + "mac-oui.db" + fcolor.SGreen +" and copy it to " + fcolor.BRed + dbdir + "\n\n","")
        usr_resp=AskQuestion(fcolor.BGreen + "Or do you prefer to download it now ?" + fcolor.BGreen,"Y/n","U","Y","1")
        if usr_resp=="Y":
            DownloadFile("https://raw.githubusercontent.com/SYWorks/Database/master/mac-oui.db",dbdir + "mac-oui.db","1")
        print ""
        printc ("x","Press any key to continue...","")

def CreateDatabaseFiles():
    if IsFileDirExist(DBFile1)!="F" or IsFileDirExist(DBFile2)!="F" or IsFileDirExist(DBFile3)!="F" or IsFileDirExist(DBFile4)!="F" or IsFileDirExist(DBFile5)!="F" or IsFileDirExist(DBFile6)!="F":
        print ""
        printc (".",fcolor.BGreen + "Creating database files....","")
        if IsFileDirExist(DBFile1)!="F":
            WriteData="Station;Connected BSSID;AP First Seen;Client First Seen;Reported;Hotspot ESSID;\n"
            open(DBFile1,"a+b").write(WriteData)
        if IsFileDirExist(DBFile2)!="F":
            WriteData="BSSID;Enriched;Mode;First Seen;Last Seen;Channel;Privacy;Cipher;Authentication;Max Rate;Bit Rates;Power;GPS Lat;GPS Lon;GPS Alt;WPS;WPS Ver;Reported;ESSID;\n"
            open(DBFile2,"a+b").write(WriteData)
        if IsFileDirExist(DBFile3)!="F":
            WriteData="Station;Connected BSSID;First Seen;Last Seen;Power;Reported;Connected ESSID;\n"
            open(DBFile3,"a+b").write(WriteData)
        if IsFileDirExist(DBFile4)!="F":
            WriteData="Station;Reported;Probes Name;\n"
            open(DBFile4,"a+b").write(WriteData)
        if IsFileDirExist(DBFile5)!="F":
            WriteData="Station;Connected BSSID;Connected ESSID;\n"
            open(DBFile5,"a+b").write(WriteData)
        if IsFileDirExist(DBFile6)!="F":
            WriteData="Station;Initial BSSID;New BSSID;Reported;Initial ESSID;New ESSID;\n"
            open(DBFile6,"a+b").write(WriteData)
        printc (".",fcolor.BGreen + "Done....","")
        print ""
    if os.stat(DBFile1)==0 or os.stat(DBFile2)==0 or os.stat(DBFile3)==0 or os.stat(DBFile4)==0 or os.stat(DBFile5)==0 or os.stat(DBFile1)==6:
        print ""
        printc ("!!!","Even database files is able to write onto the Database folder, however it seem write access is impossible.","")
        printc ("!!!","Script will not proceed..","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    

def CheckAppLocation():
    import shutil
    cpath=0
    if os.path.exists(appdir)==True:
        printd ("[" + appdir + "] exist..")
    else:
        printd ("[" + appdir + "] does not exist..")
        result=MakeTree(appdir,"")
        cpath=1
    if os.path.exists(dbdir)==True:
        printd ("[" + dbdir + "] exist..")
    else:
        printd ("[" + dbdir + "] does not exist..")
        result=MakeTree(dbdir,"")
        cpath=1
    if os.path.exists(savedir)==True:
        printd ("[" + savedir + "] exist..")
    else:
        printd ("[" + savedir + "] does not exist..")
        result=MakeTree(savedir,"")
        cpath=1
    if os.path.exists(attackdir)==True:
        printd ("[" + attackdir + "] exist..")
    else:
        printd ("[" + attackdir + "] does not exist..")
        result=MakeTree(attackdir,"")
        cpath=1
    if os.path.exists(mondir)==True:
        printd ("[" + mondir + "] exist..")
    else:
        printd ("[" + mondir + "] does not exist..")
        result=MakeTree(mondir,"")
        cpath=1
    curdir=os.getcwd() + "/"
    printd ("Current Path : " + str(curdir))
    CurFileLocation=curdir + ScriptName
    AppFileLocation=appdir + ScriptName
    printd("Current File : " + str(CurFileLocation))
    printd("Designated File : " + str(AppFileLocation))
    if os.path.exists(AppFileLocation)==False:
        printd("File Not found in " + str(AppFileLocation))
        printd("Copy file from [" + str(CurFileLocation) + "] to [" + str(AppFileLocation) + " ]")
        shutil.copy2(CurFileLocation, AppFileLocation)
        result=os.system("chmod +x " + AppFileLocation + " > /dev/null 2>&1")
        cpath=1
    if os.path.exists("/usr/sbin/" + ScriptName)==False:
        printd("File Not found in " + "/usr/sbin/" + str(ScriptName))
        printd("Copy file from [" + str(CurFileLocation) + "] to [" + "/usr/sbin/" + str(ScriptName) + " ]")
        shutil.copy2(CurFileLocation, "/usr/sbin/" + str(ScriptName))
        result=os.system("chmod +x " + "/usr/sbin/" + str(ScriptName) + " > /dev/null 2>&1")
        cpath=1
    if PathList!="":
        printd("PathList : " + str(PathList))
        for path in PathList:
            newPath=appdir + path
            printd("Checking : " + str(newPath))
            if os.path.exists(newPath)==False:
                printd("Path [ " + str(newPath) + " ] not found.")
                cpath=1
                result=MakeTree(newPath,"")
                cpath=1
    if os.stat(AppFileLocation)==0:
        printc ("!!!","Even application files is copy to the  to " + str(appdir) + ", however it seem write access is impossible.","")
        printc ("!!!","Script will not proceed..","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    if cpath==1:
        print ""
        printc ("i",fcolor.BWhite + "You can now run " + fcolor.BRed + ScriptName + fcolor.BWhite + " from " + fcolor.BRed + appdir + fcolor.BWhite + " by doing the following :","")
        printc (" ",fcolor.BGreen + "cd " + appdir,"")
        printc (" ",fcolor.BGreen + "./" + ScriptName,"")
        print ""
        printc ("x","","")

def GetRegulatoryDomain():
    ps=subprocess.Popen("iw reg get | grep -i 'country' | awk '{print $2}' | sed 's/://g'" , shell=True, stdout=subprocess.PIPE)	
    CurrentReg=ps.stdout.read().replace("\n","").lstrip().rstrip()
    return CurrentReg;

def ChangeRegulatoryDomain():
    LineBreak()
    printc ("+",fcolor.BBlue + "Regulatory Domain Configuration","")
    printc (" " ,StdColor + "For a updated list,you may wish to download it from http://linuxwireless.org/download/wireless-regdb.","")
    printc (" " ,StdColor + "Below is the current Regulatory Domain for this system :","")
    print ""
    ps=subprocess.Popen("iw reg get" , shell=True, stdout=subprocess.PIPE)	
    CurrentReg=ps.stdout.read().replace("\n","\n   " + __builtin__.tabspace)
    CurrentReg=tabspacefull + CurrentReg
    print fcolor.SGreen + CurrentReg
    printc (" ", StdColor + "Most frequency country code [ " + fcolor.BYellow + "BR" + StdColor +" ]/ [" + fcolor.BYellow + "BO" + StdColor + "] / [" + fcolor.BYellow + "JP" + StdColor + "] ","")
    CountryCode=AskQuestion ("Enter A New Country Code ",fcolor.SWhite + "Default - " + fcolor.BYellow + "JP","U","JP","1")
    if CountryCode!="" and len(CountryCode)==2:
        ps=subprocess.Popen("iw reg set " + str(CountryCode) , shell=True, stdout=subprocess.PIPE)	
    else:
        printc ("!", fcolor.SRed + "You have entered an invalid Country Code, setting skipped","")
        print ""

def MakeTree(dirName,ShowDisplay):
    if ShowDisplay=="":
        ShowDisplay=0
    RtnResult=False
    printd ("Make Tree - " + dirName)
    printd ("Check Exists : " + str(os.path.exists(dirName)))
    printd ("IsFileDirExist : " + str(IsFileDirExist(dirName)))
    if not os.path.exists(dirName) or IsFileDirExist(dirName)=="E":
        printd ("Tree - " + dirName + " not found")
        ldir=[]
        splitpath = "/"
        ldir = dirName.split("/")
        i = 1
        while i < len(ldir):
            splitpath = splitpath + ldir[i] + "/"
            i = i + 1
            if not os.path.exists(splitpath):
                if ShowDisplay=="1":
                    printc (".",fcolor.SGreen + "Creating path [ " + fcolor.SRed + splitpath + fcolor.SGreen + " ] ...","")
                os.mkdir(splitpath, 0755)
                RtnResult=True
        printc (".",fcolor.SGreen + "Path [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] created...","")
        return RtnResult
    else:
        printd ("Tree - " + dirName + " Found")
        printc ("!!",fcolor.SRed + "Path [ " + fcolor.SYellow + dirName + fcolor.SRed + " ] already exist.","")
        RtnResult=True
        return RtnResult
    return RtnResult

def RemoveTree(dirName,ShowDisplay):
    import shutil
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay="0"
    if os.path.exists(dirName)==True:
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Removing Tree [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] ...","")
        shutil.rmtree(dirName)
        RtnResult=True
    else:
        if ShowDisplay=="1":
            printc ("!!",fcolor.SRed + "Path [ " + fcolor.SYellow + dirName + fcolor.SRed + " ] does not exist..","")
        return RtnResult;
    if IsFileDirExist(dirName)=="E":
        RtnResult=True
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "Tree [ " + fcolor.SRed + dirName + fcolor.SGreen + " ] Removed...","")
        return RtnResult
    else:
        return RtnResult

def CopyFile(RootSrcPath,RootDstPath, strFileName,ShowDisplay):
    import shutil
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0
    if RootSrcPath[-1:]!="/":
        RootSrcPath=RootSrcPath + "/"
    if RootDstPath[-1:]!="/":
        RootDstPath=RootDstPath + "/"
    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(RootSrcPath + strFileName)
        if Result=="F":
            if not os.path.exists(RootDstPath):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
                Result=MakeTree(RootDstPath,ShowDisplay)
            if os.path.exists(RootDstPath + strFileName):
                os.remove(RootDstPath + strFileName)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Copying  [ " + fcolor.SWhite + RootSrcPath + strFileName + fcolor.SGreen + " ] to [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            shutil.copy(RootSrcPath + strFileName, RootDstPath + strFileName)
            if os.path.exists(RootDstPath + strFileName):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] ....","")
                RtnResult=True
                return RtnResult;
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File copying [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] failed....","")
            return RtnResult;
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Source File [ " + fcolor.SRed + RootSrcPath  + strFileName + fcolor.SGreen + " ] not found !!","")
            return RtnResult;
    else:
        if not os.path.exists(RootDstPath):
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
            Result=MakeTree(RootDstPath,ShowDisplay)
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "   Listing File...." + RootSrcPath + strFileName,"")
        filelist = glob.glob(RootSrcPath + strFileName)
        fc=0
        for file in filelist:
            if os.path.exists(RootDstPath + file):
                os.remove(RootDstPath + file)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + file + fcolor.SGreen + " ] ....","")
            DstFile=file.replace(RootSrcPath,RootDstPath)
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + file + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            shutil.copy(file, DstFile)
            if os.path.exists(DstFile):
                fc=fc+1
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File copying [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] failed....","")
        if ShowDisplay=="1":
            printc (" ",fcolor.BGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.BGreen + " ] files copied.","")
        RtnResult=fc
    return RtnResult

def MoveFile(RootSrcPath,RootDstPath, strFileName,ShowDisplay):
    import shutil
    import glob, os
    RtnResult=False
    if ShowDisplay=="":
        ShowDisplay=0
    if RootSrcPath[-1:]!="/":
        RootSrcPath=RootSrcPath + "/"
    if RootDstPath[-1:]!="/":
        RootDstPath=RootDstPath + "/"
    if strFileName.find("*")==-1 and strFileName.find("?")==-1:
        Result=IsFileDirExist(RootSrcPath + strFileName)
        if Result=="F":
            if not os.path.exists(RootDstPath):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
                Result=MakeTree(RootDstPath,ShowDisplay)
            if os.path.exists(RootDstPath + strFileName):
                os.remove(RootDstPath + strFileName)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + RootSrcPath + strFileName + fcolor.SGreen + " ] to [ " + fcolor.SRed + RootDstPath + strFileName + fcolor.SGreen + " ] ....","")
            shutil.move(RootSrcPath + strFileName, RootDstPath + strFileName)
            if os.path.exists(RootDstPath + strFileName):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] ....","")
                RtnResult=True
                return RtnResult;
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File moving [ " + fcolor.SRed + RootDstPath  + strFileName + fcolor.SGreen + " ] failed....","")
            return RtnResult;
        else:
            if ShowDisplay=="1":
                printc ("!!",fcolor.SRed + "Source File [ " + fcolor.SRed + RootSrcPath  + strFileName + fcolor.SGreen + " ] not found !!","")
            return RtnResult;
    else:
        if not os.path.exists(RootDstPath):
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Making Directory [ " + fcolor.SRed + RootDstPath + fcolor.SGreen + " ] ....","")
            Result=MakeTree(RootDstPath,ShowDisplay)
        if ShowDisplay=="1":
            printc (" ",fcolor.SGreen + "   Listing File...." + RootSrcPath + strFileName,"")
        filelist = glob.glob(RootSrcPath + strFileName)
        fc=0
        for file in filelist:
            if os.path.exists(RootDstPath + file):
                os.remove(RootDstPath + file)
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   Removing Existing Destination File [ " + fcolor.SRed + RootDstPath + file + fcolor.SGreen + " ] ....","")
            DstFile=file.replace(RootSrcPath,RootDstPath)
            if ShowDisplay=="1":
                printc (" ",fcolor.SGreen + "   Moving  [ " + fcolor.SWhite + file + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            shutil.move(file, DstFile)
            if os.path.exists(DstFile):
                fc=fc+1
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
            else:
                if ShowDisplay=="1":
                    printc ("!!",fcolor.SRed + "   File moving [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] failed....","")
        if ShowDisplay=="1":
            printc (" ",fcolor.BGreen + "Total [ " + fcolor.BRed + str(fc) + fcolor.BGreen + " ] files moved.","")
        RtnResult=fc
    return RtnResult

def MoveTree(RootSrcDir,RootDstDir,ShowDisplay):
    import shutil
    if ShowDisplay=="":
        ShowDisplay="0"
    ti=0
    td=0
    for Src_Dir, dirs, files in os.walk(RootSrcDir):
        Dst_Dir = Src_Dir.replace(RootSrcDir, RootDstDir)
        if Src_Dir!=RootSrcDir and Dst_Dir!=RootDstDir:
            td=td+1
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Moving Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + Dst_Dir + fcolor.CReset + fcolor.SGreen + " ] ..."
        if not os.path.exists(Dst_Dir):
            os.mkdir(Dst_Dir)
        for file_ in files:
            SrcFile = os.path.join(Src_Dir, file_)
            DstFile = os.path.join(Dst_Dir, file_)
            if os.path.exists(DstFile):
                os.remove(DstFile)
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Moving File " + "[ " + fcolor.SWhite + SrcFile + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
            shutil.move(SrcFile, Dst_Dir)
            ti=ti+1
            if os.path.exists(Dst_Dir):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File moved to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
        if IsFileDirExist(Src_Dir)=="D":
            if Src_Dir!=RootSrcDir:
                print fcolor.SGreen + "        Removing Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] ...."
                Result=os.rmdir(Src_Dir)
    if ShowDisplay=="1":
        print fcolor.BGreen + "     Total [ " + fcolor.BRed + str(td) + fcolor.BGreen + " ] director(ies) and [ " + fcolor.BRed + str(ti) + fcolor.BGreen + " ] file(s) transfered.."
    return str(ti);

def CopyTree(RootSrcDir,RootDstDir,ShowDisplay):
    import shutil
    if ShowDisplay=="":
        ShowDisplay="0"
    ti=0
    td=0
    for Src_Dir, dirs, files in os.walk(RootSrcDir):
        Dst_Dir = Src_Dir.replace(RootSrcDir, RootDstDir)
        if Src_Dir!=RootSrcDir and Dst_Dir!=RootDstDir:
            td=td+1
            if ShowDisplay=="1":
                print fcolor.SGreen + "        Copying Directory " + "[ " + fcolor.SWhite + Src_Dir + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + Dst_Dir + fcolor.CReset + fcolor.SGreen + " ] ..."
        if not os.path.exists(Dst_Dir):
            os.mkdir(Dst_Dir)
        for file_ in files:
            SrcFile = os.path.join(Src_Dir, file_)
            DstFile = os.path.join(Dst_Dir, file_)
            if os.path.exists(DstFile):
                if ShowDisplay=="1":
                    print fcolor.SGreen + "        Replacing File " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
                os.remove(DstFile)
                shutil.copy(SrcFile, Dst_Dir)
            else:
                if ShowDisplay=="1":
                    print fcolor.SGreen + "        Copy File " + "[ " + fcolor.SWhite + SrcFile + fcolor.CReset + fcolor.SGreen + " ] to [ " + fcolor.SRed + DstFile + fcolor.CReset + fcolor.SGreen + " ] ..."
                shutil.copy(SrcFile, Dst_Dir)
            ti=ti+1
            if os.path.exists(Dst_Dir):
                if ShowDisplay=="1":
                    printc (" ",fcolor.SGreen + "   File copied to [ " + fcolor.SRed + DstFile + fcolor.SGreen + " ] ....","")
    if ShowDisplay=="1":
        print fcolor.BGreen + "     Total [ " + fcolor.BRed + str(td) + fcolor.BGreen + " ] director(ies) and [ " + fcolor.BRed + str(ti) + fcolor.BGreen + " ] file(s) copied.."
    return str(ti);

def GetInterfaceList(cmdMode):
    if cmdMode=="":
        cmdMode="ALL"
    proc  = Popen("ifconfig -a", shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
    IFACE = "";IEEE = "";MODE = "";MACADDR="";IPADDR="";IPV6ADDR = "";BCAST="";MASK="";STATUS="";IFUP="";LANMODE="";GATEWAY="";IFaceCount=0
    __builtin__.IFaceList = []
    __builtin__.IEEEList = []
    __builtin__.ModeList = []
    __builtin__.MACList = []
    __builtin__.IPList = []
    __builtin__.IPv6List = []
    __builtin__.BCastList = []
    __builtin__.MaskList = []
    __builtin__.StatusList = []
    __builtin__.UpDownList = []
    __builtin__.ISerialList = []
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
	if ord(line[0]) != 32:
            printd ("Line : " + str(line))
            IFACE = line[:line.find(' ')]
            IFACE2=IFACE[:2].upper()
            if IFACE2!="ET" and IFACE2!="LO" and IFACE2!="VM" and IFACE2!="PP" and IFACE2!="AT" and IFACE2!="EN":
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -i 'Mode:' | tr -s ' ' | egrep -o 'Mode:..................' | cut -d ' ' -f1 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
                MODEN=ps.stdout.read().replace("\n","")
                MODE=MODEN.upper()
                ps=subprocess.Popen("iwconfig " + str(IFACE) + "| grep -o 'IEEE..........................' | cut -d ' ' -f2" , shell=True, stdout=subprocess.PIPE)	
                IEEE=ps.stdout.read().replace("\n","").upper().replace("802.11","802.11 ")
                LANMODE="WLAN"
            else:
                MODE="NIL";MODEN="Nil";IEEE="802.3";LANMODE="LAN"
            if IFACE2=="LO":
                MODE="LO";MODEN="Loopback";IEEE="Nil";LANMODE="LO"
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE)	
            MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
            MACADDR=MACADDR[:17]
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
            IPADDR=ps.stdout.read().replace("\n","").upper()    
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep -a -i 'inet6 addr:' | tr -s ' ' | sed -n '1p' | cut -d ' ' -f4" , shell=True, stdout=subprocess.PIPE)	
            IPV6ADDR=ps.stdout.read().replace("\n","").upper()
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep '\<Bcast\>' | sed -n '1p' | tr -s ' '  | cut -d ' ' -f4 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE)	
            BCAST=ps.stdout.read().replace("\n","").upper()
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep '\<Mask\>' | sed -n '1p' | tr -s ' '  | cut -d ' ' -f5 | cut -d ':' -f2" , shell=True, stdout=subprocess.PIPE)	
            MASK=ps.stdout.read().replace("\n","").upper()
            if cmdMode=="CON":
                ps=subprocess.Popen("netstat -r | grep -a -i '" + str(IFACE) + "'  | awk '{print $2}' | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | sed -n '1p'" , shell=True, stdout=subprocess.PIPE)	
                GATEWAY=ps.stdout.read().replace("\n","").upper()
            else:
                GATEWAY=""
            printd ("GATEWAY : " + GATEWAY)
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'MTU:' | sed -n '1p' | tr -s ' ' | grep -o '.\{0,100\}MTU'" , shell=True, stdout=subprocess.PIPE)	
            STATUS=ps.stdout.read().replace("\n","").upper().replace(" MTU","").lstrip().rstrip()
            ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'MTU:' | sed -n '1p' | tr -s ' ' | grep -o '.\{0,100\}MTU' | cut -d ' ' -f2 | grep 'UP'" , shell=True, stdout=subprocess.PIPE)	
            Result=ps.stdout.read().replace("\n","").upper().lstrip().rstrip()
            if Result=="UP":
                IFUP="Up"
            else:
                IFUP="Down"
            if cmdMode=="ALL":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(str(MODEN))
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST)
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MANAGED":
                if cmdMode=="MAN":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MONITOR":
                if cmdMode=="MON":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="MASTER":
                if cmdMode=="MAS":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if MODE=="AD-HOC":
                if cmdMode=="ADH":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST)
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="IP" and BCAST!="":
                if IPV6ADDR!="" or IPADDR!="":
                    IFaceCount=IFaceCount+1
                    __builtin__.ModeList.append(MODEN)
                    __builtin__.IFaceList.append(IFACE)
                    __builtin__.IEEEList.append(IEEE)
                    __builtin__.MACList.append(MACADDR)
                    __builtin__.IPList.append(IPADDR)
                    __builtin__.IPv6List.append(IPV6ADDR)
                    __builtin__.BCastList.append(BCAST) 
                    __builtin__.MaskList.append(MASK)
                    __builtin__.StatusList.append(STATUS)
                    __builtin__.UpDownList.append(IFUP)
                    __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="CON" and IPADDR!="" and GATEWAY!="" and BCAST!="":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="WLAN" and LANMODE=="WLAN":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="LAN" and LANMODE=="LAN":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
            if cmdMode=="LOOP" and LANMODE=="LO":
                IFaceCount=IFaceCount+1
                __builtin__.ModeList.append(MODEN)
                __builtin__.IFaceList.append(IFACE)
                __builtin__.IEEEList.append(IEEE)
                __builtin__.MACList.append(MACADDR)
                __builtin__.IPList.append(IPADDR)
                __builtin__.IPv6List.append(IPV6ADDR)
                __builtin__.BCastList.append(BCAST) 
                __builtin__.MaskList.append(MASK)
                __builtin__.StatusList.append(STATUS)
                __builtin__.UpDownList.append(IFUP)
                __builtin__.ISerialList.append(str(IFaceCount))
    return IFaceCount;

def Now():
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    RtnStr=str(TimeNow)
    return RtnStr;

def ReportNow():
    RtnStr=fcolor.SCyan + "  Reported : " + Now() + "\n"
    return RtnStr;

def GetSec(timestr):
    timestr=str(timestr)
    l = timestr.split(':')
    return int(l[0]) * 3600 + int(l[1]) * 60 + int(l[2])

def GetMin(timestr):
    timestr=str(timestr)
    l = timestr.split(':')
    return int(l[0]) * 360 + int(l[1])

def ConvertDateFormat(strTime,dtFormat):
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    strTime=str(strTime)
    DTStr=""
    if len(str(strTime))!=24:
        strTime=datetime.strptime(TimeNow, timefmt)
        return strTime;
    if str(strTime[3:4])!=" " or str(strTime[7:8])!=" " or str(strTime[10:11])!=" " or str(strTime[13:14])!=":" or str(strTime[16:17])!=":" or str(strTime[19:20])!=" " :
        print "<> : " + str(len(strTime))
        strTime=datetime.strptime(TimeNow, timefmt)
        return strTime;
    if strTime!="": 
        DTStr=str(datetime.strptime(strTime, dtFormat))
        DTStr=datetime.strptime(DTStr, timefmt)
    return str(DTStr)

def CalculateTime(StartTime,EndTime):
    from datetime import datetime
    timefmt="%Y-%m-%d %H:%M:%S"
    TimeNow=time.strftime(timefmt)
    StartTime=str(StartTime)
    EndTime=str(EndTime)
    if EndTime=="":
        EndTime=TimeNow
    if len(str(StartTime))!=19:
        StartTime=TimeNow
    if str(StartTime[4:5])!="-" or str(StartTime[7:8])!="-" or str(StartTime[10:11])!=" " or str(StartTime[13:14])!=":" or str(StartTime[16:17])!=":":
        StartTime=TimeNow
    if len(str(EndTime))!=19:
        EndTime=StartTime
    if str(EndTime[4:5])!="-" or str(EndTime[7:8])!="-" or str(EndTime[10:11])!=" " or str(EndTime[13:14])!=":" or str(EndTime[16:17])!=":":
        EndTime=StartTime
    StartTime=datetime.strptime(StartTime, timefmt)
    EndTime=datetime.strptime(EndTime, timefmt)
    TimeNow=datetime.strptime(TimeNow,timefmt)
    __builtin__.ElapsedTime = EndTime - StartTime
    __builtin__.TimeGap=TimeNow - EndTime
    __builtin__.TimeGapFull=__builtin__.TimeGap
    __builtin__.ElapsedTime=str(__builtin__.ElapsedTime)
    __builtin__.TimeGap=GetMin(__builtin__.TimeGap)
    return __builtin__.ElapsedTime;

def DisplayTimeStamp(cmdDisplayType,cmdTimeFormat):
    cmdDisplayType=cmdDisplayType.lower()
    if cmdTimeFormat=="":
        timefmt="%Y-%m-%d %H:%M:%S"
    else:
         timefmt=cmdTimeFormat
    if cmdDisplayType=="start":
        __builtin__.TimeStop=""
        __builtin__.DTimeStop=""
        __builtin__.DTimeStart=time.strftime(timefmt)
        printc ("  ",lblColor + "Started\t: " + txtColor + str(__builtin__.DTimeStart),"")
        __builtin__.TimeStart=datetime.datetime.now()
        return __builtin__.DTimeStart;
    if cmdDisplayType=="start-h":
        __builtin__.TimeStop=""
        __builtin__.DTimeStop=""
        __builtin__.DTimeStart=time.strftime(timefmt)
        __builtin__.TimeStart=datetime.datetime.now()
        return __builtin__.DTimeStart;
    if cmdDisplayType=="stop":
        __builtin__.DTimeStop=time.strftime(timefmt)
        printc ("  ",lblColor + "Stopped\t: " + txtColor + str(__builtin__.DTimeStop),"")
        __builtin__.TimeStop=datetime.datetime.now()
        return __builtin__.DTimeStop;
    if cmdDisplayType=="stop-h":
        __builtin__.DTimeStop=time.strftime(timefmt)
        __builtin__.TimeStop=datetime.datetime.now()
        return __builtin__.DTimeStop;
    if __builtin__.TimeStart!="":
        if cmdDisplayType=="summary" or cmdDisplayType=="summary-a":
            if __builtin__.TimeStop=="":
                __builtin__.TimeStop=datetime.datetime.now()
                __builtin__.DTimeStop=time.strftime(timefmt)
            ElapsedTime = __builtin__.TimeStop - __builtin__.TimeStart
	    ElapsedTime=str(ElapsedTime)
	    ElapsedTime=ElapsedTime[:-4]
            if cmdDisplayType=="summary-a":
                printc ("  ",lblColor + "Started\t: " + txtColor + str(__builtin__.DTimeStart),"")
                printc ("  ",lblColor + "Stopped\t: " + txtColor + str(__builtin__.DTimeStop),"")
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
            if cmdDisplayType=="summary":
	        printc ("  ",lblColor + "Time Spent\t: " + fcolor.BRed + str(ElapsedTime),"")
        return ElapsedTime;

def RewriteCSV():
    FoundClient=""
    open(__builtin__.NewCaptured_CSV,"wb").write("" )
    __builtin__.ListInfo_AllMAC=[]
    if IsFileDirExist(__builtin__.Captured_CSV)=="F":
        DelFile (__builtin__.NewCaptured_CSV,1)
        DelFile (__builtin__.NewCaptured_CSVFront,1)
        DelFile (__builtin__.Client_CSV,1)
        DelFile (__builtin__.SSID_CSV,1)
        with open(__builtin__.Captured_CSV,"r") as f:
            for line in f:
                line=line.replace("\n","").replace("\00","")
                if line!="":
                    FirstMAC=str(line).split(",")
                    FirstMAC=FirstMAC[0]
                    if len(FirstMAC)==17:
                        open(__builtin__.NewCaptured_CSVFront,"a+b").write(str(FirstMAC) + "\n")
                        __builtin__.ListInfo_AllMAC.append (str(FirstMAC))
                open(__builtin__.NewCaptured_CSV,"a+b").write(line + "\n")
                if line.find("Station MAC, First time seen, Last time seen")!=-1:
                   FoundClient="1"
                if FoundClient=="" and line.find("BSSID, First time seen, Last time seen, channel")==-1:
                    if len(line)>20:
                        open(__builtin__.SSID_CSV,"a+b").write(line + "\n")
                if FoundClient=="1" and line.find("Station MAC, First time seen, Last time seen")==-1:
                    if len(line)>20:
                        open(__builtin__.Client_CSV,"a+b").write(line + "\n")
        __builtin__.ListInfo_AllMAC_Dup=set([dp for dp in __builtin__.ListInfo_AllMAC if __builtin__.ListInfo_AllMAC.count(dp)>1])
    open(__builtin__.NewCaptured_Kismet,"wb").write("" )
    if IsFileDirExist(__builtin__.Captured_Kismet)=="F":
        with open(__builtin__.Captured_Kismet,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                open(__builtin__.NewCaptured_Kismet,"a+b").write(line + "\n")

def CheckRepeat(MACAddr):
    x=0
    Found="-"
    if str(__builtin__.ListInfo_AllMAC_Dup).find(MACAddr)!=-1:
        Found=MACAddr
    return Found

def DisplayClientList():
    x=0
    if __builtin__.NETWORK_VIEW=="2" or __builtin__.NETWORK_VIEW=="3":
        DisplayClientCount=0
        ToDisplayClient="1"
        DislpayNotShownClient=0
        ConnectedClient=0
        SkipClient=""
        GetFilterDetail()
        InfoColor=fcolor.SGreen
        CenterText(fcolor.BWhite + fcolor.BGGreen, "S T A T I O N S      L I S T I N G")
        print fcolor.BWhite + "STATION            BSSID\t\tPWR  Range\tLast Seen             Time Gap  ESSID                           OUI"
        DrawLine("^",fcolor.CReset + fcolor.Black,"","")
        while x < len(ListInfo_STATION):
            ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_PROBE_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_PROBE_FILTER=="Yes":
                    if len(ListInfo_PROBE[x])>0:
                        ToDisplayClient="1"
                elif __builtin__.NETWORK_PROBE_FILTER=="No":
                    if len(ListInfo_PROBE[x])==0:
                        ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_ASSOCIATED_FILTER=="Yes":
                    if ListInfo_CBSSID[x].find("Not Associated")==-1:
                        ToDisplayClient="1"
                if __builtin__.NETWORK_ASSOCIATED_FILTER=="No":
                    if ListInfo_CBSSID[x].find("Not Associated")!=-1:
                        ToDisplayClient="1"
            if ToDisplayClient=="1" and __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                ToDisplayClient=""
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes":
                    if ListInfo_CBSSID[x].find("Not Associated")!=-1:
                        ToDisplayClient="1"
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="No":
                    if ListInfo_CBSSID[x].find("Not Associated")==-1:
                        ToDisplayClient="1"
            if  ToDisplayClient=="1" and __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                ToDisplayClient=""    
                if ListInfo_CQualityRange[x].find(__builtin__.NETWORK_CSIGNAL_FILTER)!=-1:
                    ToDisplayClient="1"
            if __builtin__.HIDE_INACTIVE_STN=="No":                
                InfoColor=fcolor.SGreen
            else:
                InfoColor=fcolor.SWhite
            MACCOLOR=InfoColor
            SELFMAC=""
            if ListInfo_STATION[x]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[x]==__builtin__.SELECTED_MON_MAC or ListInfo_STATION[x]==__builtin__.SELECTED_IFACE_MAC:
                MACCOLOR=fcolor.BPink
                SELFMAC=fcolor.BWhite + " [ " + fcolor.BPink + "Your Interface MAC" + fcolor.BWhite + " ]"
            CBSSID=ListInfo_CBSSID[x]
            CBSSID=str(CBSSID).replace("Not Associated","Not Associated")
            if CBSSID!="Not Associated":
                ConnectedClient += 1
            if ToDisplayClient=="1":
                if int(__builtin__.ListInfo_CTimeGap[x]) >= int(__builtin__.HIDE_AFTER_MIN):
                    if __builtin__.HIDE_INACTIVE_STN!="Yes":
                        DisplayClientCount=DisplayClientCount+1
                        ToDisplayClient=""
                        print fcolor.SBlack + HighlightMonitoringMAC(str(ListInfo_STATION[x])) + fcolor.SBlack + "  " + str(CBSSID) + "\t" + str(ListInfo_CBestQuality[x]).ljust(5) + RemoveColor(str(ListInfo_CQualityRange[x])) + "\t" + str(ListInfo_CLastSeen[x]).ljust(22) + str(ListInfo_CTimeGapFull[x]).ljust(10) + "" + str(ListInfo_CESSID[x]).ljust(32) + str(ListInfo_COUI[x])+ RemoveColor(str(SELFMAC))
                        if ListInfo_PROBE[x]!="":
                            print fcolor.SBlack + "    Probe : " + str(ListInfo_PROBE[x])
                    else:
                        DislpayNotShownClient=DislpayNotShownClient+1
                        ToDisplayClient=""
            if ToDisplayClient=="1":
                DisplayClientCount=DisplayClientCount+1
                print InfoColor + MACCOLOR + HighlightMonitoringMAC(str(ListInfo_STATION[x])) + InfoColor + "  " + str(CBSSID) + "\t" + str(ListInfo_CBestQuality[x]).ljust(5) + str(ListInfo_CQualityRange[x]) + InfoColor + "\t" + str(ListInfo_CLastSeen[x]).ljust(22) + str(ListInfo_CTimeGapFull[x]).ljust(10) + "" + fcolor.SPink + str(ListInfo_CESSID[x]).ljust(32) + InfoColor + str(ListInfo_COUI[x])+ str(SELFMAC)
                if ListInfo_PROBE[x]!="":
                    print fcolor.SWhite + "    Probe : " + fcolor.BBlue + str(ListInfo_PROBE[x])
            x = x + 1
        LineBreak()
        if DisplayClientFilter!="":
            print fcolor.BGreen + "Filter       : " + str(DisplayClientFilter)
        LblColor=fcolor.SYellow
        SummaryColor=fcolor.BGreen
        print LblColor + "Client Total : " + SummaryColor + str(len(ListInfo_STATION)).ljust(17) + LblColor + "Updated      : " + SummaryColor + str(__builtin__.ListInfo_CExist).ljust(17) + LblColor + "Added : " + SummaryColor + str(__builtin__.ListInfo_CAdd).ljust(21) + LblColor + "Listed : " + SummaryColor + str(DisplayClientCount).ljust(21) + LblColor + "Not Shown : " + SummaryColor + str(DislpayNotShownClient) 
        print LblColor + "Connected    : " + SummaryColor + str(__builtin__.ListInfo_AssociatedCount).ljust(17) + LblColor + "Unassociated : " + SummaryColor + str(__builtin__.ListInfo_UnassociatedCount).ljust(17) + LblColor + "Probe : " + SummaryColor + str(__builtin__.ListInfo_ProbeCount).ljust(21) + LblColor + "Removed   : " + SummaryColor + str(ListInfo_CRemoved) 
        DrawLine("_",fcolor.CReset + fcolor.Black,"","")

def GetFilterDetail():
    __builtin__.DisplayNetworkFilter= ""
    __builtin__.DisplayClientFilter=""
    __builtin__.DisplayUnassocFilter=""
    __builtin__.DisplayAllFilter=""
    if __builtin__.NETWORK_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Encryption - " + fcolor.Pink + str(__builtin__.NETWORK_FILTER) + "\t"
    if __builtin__.NETWORK_SIGNAL_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_SIGNAL_FILTER) + "\t"
    if __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Channel - " + fcolor.Pink + str(__builtin__.NETWORK_CHANNEL_FILTER) + "\t"
    if __builtin__.NETWORK_WPS_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "WPS - " + fcolor.Pink + str(__builtin__.NETWORK_WPS_FILTER) + "\t"
    if __builtin__.NETWORK_CLIENT_FILTER!="ALL":
        __builtin__.DisplayNetworkFilter=__builtin__.DisplayNetworkFilter + fcolor.BCyan + "Client - " + fcolor.Pink + str(__builtin__.NETWORK_CLIENT_FILTER) + "\t"
    if __builtin__.NETWORK_PROBE_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Probe - " + fcolor.Pink + str(__builtin__.NETWORK_PROBE_FILTER) + "\t"
    if __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Associated - " + fcolor.Pink + str(__builtin__.NETWORK_ASSOCIATED_FILTER) + "\t"
    if __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Unassociated - " + fcolor.Pink + str(__builtin__.NETWORK_UNASSOCIATED_FILTER) + "\t"
    if __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
        __builtin__.DisplayClientFilter=__builtin__.DisplayClientFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_CSIGNAL_FILTER) + "\t"
    if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
        __builtin__.DisplayUnassocFilter=__builtin__.DisplayUnassocFilter + fcolor.BCyan + "Probe - " + fcolor.Pink + str(__builtin__.NETWORK_UPROBE_FILTER) + "\t"
    if __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
        __builtin__.DisplayUnassocFilter=__builtin__.DisplayUnassocFilter + fcolor.BCyan + "Signal - " + fcolor.Pink + str(__builtin__.NETWORK_UCSIGNAL_FILTER) + "\t"
    if __builtin__.DisplayNetworkFilter!="":
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Access Point Filter         : " + str(__builtin__.DisplayNetworkFilter) 
    if __builtin__.DisplayClientFilter!="":
        if __builtin__.DisplayAllFilter!="":
            __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + "\n"
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Station Filter              : " + str(__builtin__.DisplayClientFilter) 
    if __builtin__.DisplayUnassocFilter!="":
        if __builtin__.DisplayAllFilter!="":
            __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + "\n"
        __builtin__.DisplayAllFilter=__builtin__.DisplayAllFilter + str(tabspacefull) + fcolor.BWhite +         "Unassociated Station Filter : " + str(__builtin__.DisplayUnassocFilter) 

def SortStationList():
    return
    tmpListInfo_STATION=[]
    tmpListInfo_CFirstSeen=[]
    tmpListInfo_CLastSeen=[]
    tmpListInfo_CBestQuality=[]
    tmpListInfo_CQualityRange=[]
    tmpListInfo_CQualityPercent=[]
    tmpListInfo_CPackets=[]
    tmpListInfo_STNStandard=[]
    tmpListInfo_CBSSID=[]
    tmpListInfo_CBSSIDPrev=[]
    tmpListInfo_CBSSIDPrevList=[]
    tmpListInfo_PROBE=[]
    tmpListInfo_CESSID=[]
    tmpListInfo_COUI=[]
    tmpListInfo_CElapse=[]
    tmpListInfo_CTimeGap=[]
    tmpListInfo_CTimeGapFull=[]
    SortListInfo_STATION=[]
    SortListInfo_STATION=__builtin__.ListInfo_STATION
    SortListInfo_STATION.sort()
    x=0
    while x<len(SortListInfo_STATION):
        SortMAC=SortListInfo_STATION[x]
        foundloc=FindMACIndex(SortMAC,__builtin__.ListInfo_STATION)
        print "MAC : " + SortMAC + " / " + str(ListInfo_STATION[x]) + " / " + str(foundloc)
        if foundloc!=-1:
            tmpListInfo_STATION.append (__builtin__.ListInfo_STATION[foundloc])
            tmpListInfo_CFirstSeen.append (__builtin__.ListInfo_CFirstSeen[foundloc])
            tmpListInfo_CLastSeen.append (__builtin__.ListInfo_CLastSeen[foundloc])
            tmpListInfo_CBestQuality.append (__builtin__.ListInfo_CBestQuality[foundloc])
            tmpListInfo_CQualityRange.append (__builtin__.ListInfo_CQualityRange[foundloc])
            tmpListInfo_CQualityPercent.append (__builtin__.ListInfo_CQualityPercent[foundloc])
            tmpListInfo_CPackets.append (__builtin__.ListInfo_CPackets[foundloc])
            tmpListInfo_STNStandard.append (__builtin__.ListInfo_STNStandard[foundloc])
            tmpListInfo_CBSSID.append (__builtin__.ListInfo_CBSSID[foundloc])
            tmpListInfo_CBSSIDPrev.append (__builtin__.ListInfo_CBSSIDPrev[foundloc])
            tmpListInfo_CBSSIDPrevList.append (__builtin__.ListInfo_CBSSIDPrevList[foundloc])
            tmpListInfo_PROBE.append (__builtin__.ListInfo_PROBE[foundloc])
            tmpListInfo_CESSID.append (__builtin__.ListInfo_CESSID[foundloc])
            tmpListInfo_COUI.append (__builtin__.ListInfo_COUI[foundloc])
            tmpListInfo_CElapse.append (__builtin__.ListInfo_CElapse[foundloc])
            tmpListInfo_CTimeGap.append (__builtin__.ListInfo_CTimeGap[foundloc])
            tmpListInfo_CTimeGapFull.append (__builtin__.ListInfo_CTimeGapFull[foundloc])
        x += 1
    print "1 - " + " / " + str(len(__builtin__.ListInfo_STATION)) + " / " + str(len(tmpListInfo_STATION))
    print "2 - " + " / " + str(len(__builtin__.ListInfo_CFirstSeen)) + " / " + str(len(tmpListInfo_CFirstSeen))
    print "3 - " + " / " + str(len(__builtin__.ListInfo_CLastSeen)) + " / " + str(len(tmpListInfo_CLastSeen))
    print "4 - " + " / " + str(len(__builtin__.ListInfo_CBestQuality)) + " / " + str(len(tmpListInfo_CBestQuality))
    print "5 - " + " / " + str(len(__builtin__.ListInfo_CQualityRange)) + " / " + str(len(tmpListInfo_CQualityRange))
    print "6 - " + " / " + str(len(__builtin__.ListInfo_CQualityPercent)) + " / " + str(len(tmpListInfo_CQualityPercent))
    print "1 - " + " / " + str(len(__builtin__.ListInfo_CPackets)) + " / " + str(len(tmpListInfo_CPackets))
    print "8 - " + " / " + str(len(__builtin__.ListInfo_STNStandard)) + " / " + str(len(tmpListInfo_STNStandard))
    print "9 - " + " / " + str(len(__builtin__.ListInfo_CBSSID)) + " / " + str(len(tmpListInfo_CBSSID))
    print "10 - " + " / " + str(len(__builtin__.ListInfo_CBSSIDPrev)) + " / " + str(len(tmpListInfo_CBSSIDPrev))
    print "11 - " + " / " + str(len(__builtin__.ListInfo_CBSSIDPrevList)) + " / " + str(len(tmpListInfo_CBSSIDPrevList))
    print "12 - " + " / " + str(len(__builtin__.ListInfo_PROBE)) + " / " + str(len(tmpListInfo_PROBE))
    print "13 - " + " / " + str(len(__builtin__.ListInfo_CESSID)) + " / " + str(len(tmpListInfo_CESSID))
    print "14 - " + " / " + str(len(__builtin__.ListInfo_COUI)) + " / " + str(len(tmpListInfo_COUI))
    print "15 - " + " / " + str(len(__builtin__.ListInfo_CElapse)) + " / " + str(len(tmpListInfo_CElapse))
    print "16 - " + " / " + str(len(__builtin__.ListInfo_CTimeGap)) + " / " + str(len(tmpListInfo_CTimeGap))
    print "17 - " + " / " + str(len(__builtin__.ListInfo_CTimeGapFull)) + " / " + str(len(tmpListInfo_CTimeGapFull))
    __builtin__.ListInfo_STATION=tmpListInfo_STATION
    __builtin__.ListInfo_CFirstSeen=tmpListInfo_CFirstSeen
    __builtin__.ListInfo_CLastSeen=tmpListInfo_CLastSeen
    __builtin__.ListInfo_CBestQuality=tmpListInfo_CBestQuality
    __builtin__.ListInfo_CQualityRange=tmpListInfo_CQualityRange
    __builtin__.ListInfo_CQualityPercent=tmpListInfo_CQualityPercent
    __builtin__.ListInfo_CPackets=tmpListInfo_CPackets
    __builtin__.ListInfo_STNStandard=tmpListInfo_STNStandard
    __builtin__.ListInfo_CBSSID=tmpListInfo_CBSSID
    __builtin__.ListInfo_CBSSIDPrev=tmpListInfo_CBSSIDPrev
    __builtin__.ListInfo_CBSSIDPrevList=tmpListInfo_CBSSIDPrevList
    __builtin__.ListInfo_PROBE=tmpListInfo_PROBE
    __builtin__.ListInfo_CESSID=tmpListInfo_CESSID
    __builtin__.ListInfo_COUI=tmpListInfo_COUI
    __builtin__.ListInfo_CElapse=tmpListInfo_CElapse
    __builtin__.ListInfo_CTimeGap=tmpListInfo_CTimeGap
    __builtin__.ListInfo_CTimeGapFull=tmpListInfo_CTimeGapFull
    return

def SortBSSIDList():
    return
    x=0
    tmpListInfo_ESSID=[]
    tmpListInfo_HiddenSSID=[]
    tmpListInfo_BSSIDTimes=[]
    tmpListInfo_BSSID=[]
    tmpListInfo_Channel=[]
    tmpListInfo_APStandard=[]
    tmpListInfo_ESS=[]
    tmpListInfo_Cloaked=[]
    tmpListInfo_Privacy=[]
    tmpListInfo_Cipher=[]
    tmpListInfo_Auth=[]
    tmpListInfo_MaxRate=[]
    tmpListInfo_Beacon=[]
    tmpListInfo_Data=[]
    tmpListInfo_Total=[]
    tmpListInfo_FirstSeen=[]
    tmpListInfo_LastSeen=[]
    tmpListInfo_BestQuality=[]
    tmpListInfo_BestSignal=[]
    tmpListInfo_BestNoise=[]
    tmpListInfo_GPSBestLat=[]
    tmpListInfo_GPSBestLon=[]
    tmpListInfo_GPSBestAlt=[]
    tmpListInfo_QualityRange=[]
    tmpListInfo_QualityPercent=[]
    tmpListInfo_BSSID_OUI=[]
    tmpListInfo_WPS=[]
    tmpListInfo_WPSVer=[]
    tmpListInfo_WPSLock=[]
    tmpListInfo_ConnectedClient=[]
    tmpListInfo_Freq=[]
    tmpListInfo_Signal=[]
    tmpListInfo_Enriched=[]
    tmpListInfo_Quality=[]
    tmpListInfo_BitRate=[]
    tmpListInfo_WPAVer=[]
    tmpListInfo_PairwiseCipher=[]
    tmpListInfo_GroupCipher=[]
    tmpListInfo_AuthSuite=[]
    tmpListInfo_LastBeacon=[]
    tmpListInfo_Mode=[]
    tmpListInfo_EncKey=[]
    tmpListInfo_SSIDElapse=[]
    tmpListInfo_SSIDTimeGap=[]
    tmpListInfo_SSIDTimeGapFull=[]
    SortListInfo_BSSID=[]
    SortListInfo_BSSID=__builtin__.ListInfo_BSSID
    SortListInfo_BSSID.sort()
     
    while x<len(SortListInfo_BSSID):
        SortMAC=SortListInfo_BSSID[x]
        foundloc=FindMACIndex(SortMAC,__builtin__.ListInfo_BSSID)
        if foundloc!=-1:
            tmpListInfo_ESSID.append (__builtin__.ListInfo_ESSID[foundloc])
            tmpListInfo_HiddenSSID.append (__builtin__.ListInfo_HiddenSSID[foundloc])
            tmpListInfo_BSSIDTimes.append (__builtin__.ListInfo_BSSIDTimes[foundloc])
            tmpListInfo_BSSID.append (__builtin__.ListInfo_BSSID[foundloc])
            tmpListInfo_Channel.append (__builtin__.ListInfo_Channel[foundloc])
            tmpListInfo_APStandard.append (__builtin__.ListInfo_APStandard[foundloc])
            tmpListInfo_ESS.append (__builtin__.ListInfo_ESS[foundloc])
            tmpListInfo_Cloaked.append (__builtin__.ListInfo_Cloaked[foundloc])
            tmpListInfo_Privacy.append (__builtin__.ListInfo_Privacy[foundloc])
            tmpListInfo_Cipher.append (__builtin__.ListInfo_Cipher[foundloc])
            tmpListInfo_Auth.append (__builtin__.ListInfo_Auth[foundloc])
            tmpListInfo_MaxRate.append (__builtin__.ListInfo_MaxRate[foundloc])
            tmpListInfo_Beacon.append (__builtin__.ListInfo_Beacon[foundloc])
            tmpListInfo_Data.append (__builtin__.ListInfo_Data[foundloc])
            tmpListInfo_Total.append (__builtin__.ListInfo_Total[foundloc])
            tmpListInfo_FirstSeen.append (__builtin__.ListInfo_FirstSeen[foundloc])
            tmpListInfo_LastSeen.append (__builtin__.ListInfo_LastSeen[foundloc])
            tmpListInfo_BestQuality.append (__builtin__.ListInfo_BestQuality[foundloc])
            tmpListInfo_BestSignal.append (__builtin__.ListInfo_BestSignal[foundloc])
            tmpListInfo_BestNoise.append (__builtin__.ListInfo_BestNoise[foundloc])
            tmpListInfo_GPSBestLat.append (__builtin__.ListInfo_GPSBestLat[foundloc])
            tmpListInfo_GPSBestLon.append (__builtin__.ListInfo_GPSBestLon[foundloc])
            tmpListInfo_GPSBestAlt.append (__builtin__.ListInfo_GPSBestAlt[foundloc])
            tmpListInfo_QualityRange.append (__builtin__.ListInfo_QualityRange[foundloc])
            tmpListInfo_QualityPercent.append (__builtin__.ListInfo_QualityPercent[foundloc])
            tmpListInfo_BSSID_OUI.append (__builtin__.ListInfo_BSSID_OUI[foundloc])
            tmpListInfo_WPS.append (__builtin__.ListInfo_WPS[foundloc])
            tmpListInfo_WPSVer.append (__builtin__.ListInfo_WPSVer[foundloc])
            tmpListInfo_WPSLock.append (__builtin__.ListInfo_WPSLock[foundloc])
            tmpListInfo_ConnectedClient.append (__builtin__.ListInfo_ConnectedClient[foundloc])
            tmpListInfo_Freq.append (__builtin__.ListInfo_Freq[foundloc])
            tmpListInfo_Signal.append (__builtin__.ListInfo_Signal[foundloc])
            tmpListInfo_Enriched.append (__builtin__.ListInfo_Enriched[foundloc])
            tmpListInfo_Quality.append (__builtin__.ListInfo_Quality[foundloc])
            tmpListInfo_BitRate.append (__builtin__.ListInfo_BitRate[foundloc])
            tmpListInfo_WPAVer.append (__builtin__.ListInfo_WPAVer[foundloc])
            tmpListInfo_PairwiseCipher.append (__builtin__.ListInfo_PairwiseCipher[foundloc])
            tmpListInfo_GroupCipher.append (__builtin__.ListInfo_GroupCipher[foundloc])
            tmpListInfo_AuthSuite.append (__builtin__.ListInfo_AuthSuite[foundloc])
            tmpListInfo_LastBeacon.append (__builtin__.ListInfo_LastBeacon[foundloc])
            tmpListInfo_Mode.append (__builtin__.ListInfo_Mode[foundloc])
            tmpListInfo_EncKey.append (__builtin__.ListInfo_EncKey[foundloc])
            tmpListInfo_SSIDElapse.append (__builtin__.ListInfo_SSIDElapse[foundloc])
            tmpListInfo_SSIDTimeGap.append (__builtin__.ListInfo_SSIDTimeGap[foundloc])
            tmpListInfo_SSIDTimeGapFull.append (__builtin__.ListInfo_SSIDTimeGapFull[foundloc])
        x += 1
    __builtin__.ListInfo_ESSID=tmpListInfo_ESSID
    __builtin__.ListInfo_HiddenSSID=tmpListInfo_HiddenSSID
    __builtin__.ListInfo_BSSIDTimes=tmpListInfo_BSSIDTimes
    __builtin__.ListInfo_BSSID=tmpListInfo_BSSID
    __builtin__.ListInfo_Channel=tmpListInfo_Channel
    __builtin__.ListInfo_APStandard=tmpListInfo_APStandard
    __builtin__.ListInfo_ESS=tmpListInfo_ESS
    __builtin__.ListInfo_Cloaked=tmpListInfo_Cloaked
    __builtin__.ListInfo_Privacy=tmpListInfo_Privacy
    __builtin__.ListInfo_Cipher=tmpListInfo_Cipher
    __builtin__.ListInfo_Auth=tmpListInfo_Auth
    __builtin__.ListInfo_MaxRate=tmpListInfo_MaxRate
    __builtin__.ListInfo_Beacon=tmpListInfo_Beacon
    __builtin__.ListInfo_Data=tmpListInfo_Data
    __builtin__.ListInfo_Total=tmpListInfo_Total
    __builtin__.ListInfo_FirstSeen=tmpListInfo_FirstSeen
    __builtin__.ListInfo_LastSeen=tmpListInfo_LastSeen
    __builtin__.ListInfo_BestQuality=tmpListInfo_BestQuality
    __builtin__.ListInfo_BestSignal=tmpListInfo_BestSignal
    __builtin__.ListInfo_BestNoise=tmpListInfo_BestNoise
    __builtin__.ListInfo_GPSBestLat=tmpListInfo_GPSBestLat
    __builtin__.ListInfo_GPSBestLon=tmpListInfo_GPSBestLon
    __builtin__.ListInfo_GPSBestAlt=tmpListInfo_GPSBestAlt
    __builtin__.ListInfo_QualityRange=tmpListInfo_QualityRange
    __builtin__.ListInfo_QualityPercent=tmpListInfo_QualityPercent
    __builtin__.ListInfo_BSSID_OUI=tmpListInfo_BSSID_OUI
    __builtin__.ListInfo_WPS=tmpListInfo_WPS
    __builtin__.ListInfo_WPSVer=tmpListInfo_WPSVer
    __builtin__.ListInfo_WPSLock=tmpListInfo_WPSLock
    __builtin__.ListInfo_ConnectedClient=tmpListInfo_ConnectedClient
    __builtin__.ListInfo_Freq=tmpListInfo_Freq
    __builtin__.ListInfo_Signal=tmpListInfo_Signal
    __builtin__.ListInfo_Enriched=tmpListInfo_Enriched
    __builtin__.ListInfo_Quality=tmpListInfo_Quality
    __builtin__.ListInfo_BitRate=tmpListInfo_BitRate
    __builtin__.ListInfo_WPAVer=tmpListInfo_WPAVer
    __builtin__.ListInfo_PairwiseCipher=tmpListInfo_PairwiseCipher
    __builtin__.ListInfo_GroupCipher=tmpListInfo_GroupCipher
    __builtin__.ListInfo_AuthSuite=tmpListInfo_AuthSuite
    __builtin__.ListInfo_LastBeacon=tmpListInfo_LastBeacon
    __builtin__.ListInfo_Mode=tmpListInfo_Mode
    __builtin__.ListInfo_EncKey=tmpListInfo_EncKey
    __builtin__.ListInfo_SSIDElapse=tmpListInfo_SSIDElapse
    __builtin__.ListInfo_SSIDTimeGap=tmpListInfo_SSIDTimeGap
    __builtin__.ListInfo_SSIDTimeGapFull=tmpListInfo_SSIDTimeGapFull
    return

def DisplayInfrastructure():
    __builtin__.ListInfo_AssociatedCount =0
    ConnectedClient=0
    WPACount=0;WEPCount=0;OPNCount=0;OTHCount=0;DisplayNotShownClient=0;DisplayNotShownSSID=0;DisplayClientCount=0;DisplayCount=0;DisplayEnriched=0;UNASSOC=0
    if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3" or __builtin__.NETWORK_VIEW=="4"  or __builtin__.NETWORK_VIEW=="5":
        x=0;Skip=""
        GetFilterDetail()
        if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
            CenterText(fcolor.BWhite + fcolor.BGGreen, "A C C E S S     P O I N T S    L I S T I N G")
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            CenterText(fcolor.BWhite + fcolor.BGGreen, "A C C E S S     P O I N T S   /   W I R E L E S S      C L I E N T S    L I S T I N G")
        print fcolor.BWhite + "BSSID              STN  ENC   CIPHER      AUTH      CH   PWR    Range    11S   WPS  Ver  LCK    ESSID                            OUI"
        DrawLine("^",fcolor.CReset + fcolor.Black,"","")
        while x < len(ListInfo_BSSID):
            if ListInfo_Privacy[x].find("WPA")!=-1:
                CPrivacy=fcolor.SCyan 
                WPACount += 1
            elif ListInfo_Privacy[x].find("WEP")!=-1:
                CPrivacy=fcolor.SRed
                WEPCount += 1
            elif ListInfo_Privacy[x].find("OPN")!=-1:
                CPrivacy=fcolor.SYellow
                OPNCount += 1
            else:
                CPrivacy=fcolor.SBlack
                OTHCount += 1
            ToDisplay=""
            if __builtin__.NETWORK_SIGNAL_FILTER!="ALL":
                if ListInfo_QualityRange[x].find(__builtin__.NETWORK_SIGNAL_FILTER)!=-1:
                    ToDisplay="1"
            else:
                ToDisplay="1"
            if ToDisplay=="1" and __builtin__.NETWORK_FILTER!="ALL":
                if str(__builtin__.NETWORK_FILTER).find("*")!=-1:
                    RemoveWC=str(__builtin__.NETWORK_FILTER).replace("*","")
                    if ListInfo_Privacy[x].find(RemoveWC)!=-1:
                        ToDisplay="1"
                    else:
                        ToDisplay=""
                else:
                    if str(ListInfo_Privacy[x]).upper()==str(__builtin__.NETWORK_FILTER).upper()!=-1:
                        ToDisplay="1"
                    else:
                        ToDisplay=""
            if ToDisplay=="1" and __builtin__.NETWORK_CHANNEL_FILTER!="ALL":
                ToDisplay=""
                if ListInfo_Channel[x]==__builtin__.NETWORK_CHANNEL_FILTER:
                    ToDisplay="1"
            if ToDisplay=="1" and __builtin__.NETWORK_WPS_FILTER!="ALL":
                ToDisplay==""
                if __builtin__.NETWORK_WPS_FILTER=="Yes":
                    if ListInfo_WPS[x]=="Yes":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
                if __builtin__.NETWORK_WPS_FILTER=="No":
                    if ListInfo_WPS[x]=="-":
                        ToDisplay="1"
                    else:
                        ToDisplay=""
            if ToDisplay=="1" and __builtin__.NETWORK_CLIENT_FILTER!="ALL":
                ToDisplay==""
                if __builtin__.NETWORK_CLIENT_FILTER=="Yes" and ListInfo_ConnectedClient[x]!="0":
                    ToDisplay="1"
 
                if __builtin__.NETWORK_CLIENT_FILTER=="No" and ListInfo_ConnectedClient[x]=="0":
                    ToDisplay="1"
 
            EnrichData="  "
            if ListInfo_Enriched[x]=="Yes":
                EnrichData=fcolor.BIRed + " *"
                DisplayEnriched=DisplayEnriched+1
            if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
                if __builtin__.HIDE_INACTIVE_SSID=="No":
                    InfoColor=fcolor.SGreen
                else:
                    InfoColor=fcolor.SWhite
            else:
                if __builtin__.HIDE_INACTIVE_SSID=="No" or __builtin__.HIDE_INACTIVE_STN=="No":
                    InfoColor=fcolor.SGreen
                else:
                    InfoColor=fcolor.SWhite
            DisplayCount += 1
            DontShowClient=0
            BSSIDColor=InfoColor
            ClientColor=InfoColor
            ESSIDColor=fcolor.SPink
            OUIColor=fcolor.SCyan
            APStd=str(ListInfo_APStandard[x])
            APStd=APStd.replace("802.11 ","")
            if int(ListInfo_ConnectedClient[x])>0:
                BSSIDColor=fcolor.BYellow
                ClientColor=fcolor.BGreen
                ESSIDColor=fcolor.BPink
                OUIColor=fcolor.BCyan
            DESSID=str(ListInfo_ESSID[x])
            if str(ListInfo_ESSID[x])=="":
                DESSID=fcolor.SBlack + "<<NO ESSID>>                     "
            else:
                DESSID=str(DESSID).ljust(33)
            if int(__builtin__.ListInfo_SSIDTimeGap[x]) < int(__builtin__.HIDE_AFTER_MIN) and ToDisplay=="1":
                Cipher=ListInfo_Cipher[x]
                if Cipher=="CCMP WRAP TKIP":
                    Cipher="C/T/WRAP"
                if Cipher=="CCMP WEP104":
                    Cipher="CCMP/WEP104"
                if Cipher=="CCMP TKIP WEP104":
                    Cipher="C/T/WEP104"
                if ListInfo_Auth[x]=="MGTPSK":
                    ListInfo_Auth[x]="MGT/PSK"
                print  BSSIDColor + HighlightMonitoringMAC(str(ListInfo_BSSID[x])) + "  " + ClientColor + str(ListInfo_ConnectedClient[x]).ljust(5) + InfoColor + str(CPrivacy) + str(ListInfo_Privacy[x]).ljust(6) + InfoColor + str(Cipher).ljust(12) + str(ListInfo_Auth[x]).ljust(10) + str(ListInfo_Channel[x]).ljust(5) + str(ListInfo_BestQuality[x]).ljust(7) + str(ListInfo_QualityRange[x]) + InfoColor + "\t " + fcolor.SBlue + str(APStd).ljust(6) + InfoColor + str(ListInfo_WPS[x]).ljust(5)  + str(ListInfo_WPSVer[x]).ljust(5) + str(ListInfo_WPSLock[x]).ljust(5) + str(EnrichData) + ESSIDColor + str(DESSID) + OUIColor + str(ListInfo_BSSID_OUI[x]) 
            else:
                if __builtin__.HIDE_INACTIVE_SSID=="Yes":
                    DontShowClient=1
                    DisplayNotShownSSID=DisplayNotShownSSID+1
                elif ToDisplay=="1":
                    if ListInfo_Enriched[x]=="Yes":
                        EnrichData=fcolor.SBlack + " *"
                    print  fcolor.BIGray + str(ListInfo_BSSID[x]).ljust(19) + str(ListInfo_ConnectedClient[x]).ljust(5) + RemoveColor(str(CPrivacy)) + RemoveColor(str(ListInfo_Privacy[x])).ljust(6) + str(ListInfo_Cipher[x]).ljust(12) + str(ListInfo_Auth[x]).ljust(10) + str(ListInfo_Channel[x]).ljust(5) + str(ListInfo_BestQuality[x]).ljust(7) + RemoveColor(str(ListInfo_QualityRange[x])) + "\t " + str(APStd).ljust(6) + str(ListInfo_WPS[x]).ljust(5)  + str(ListInfo_WPSVer[x]).ljust(5) + str(ListInfo_WPSLock[x]).ljust(5) +  str(EnrichData) + str(DESSID) + str(ListInfo_BSSID_OUI[x])
                    print  fcolor.BIGray + "\t\t\tFirst Seen : " + fcolor.SBlack + ListInfo_FirstSeen[x].ljust(24) + fcolor.BIGray + "\tLast Seen : " + fcolor.SBlack + ListInfo_LastSeen[x] + fcolor.BIGray + "\t[ " + str(ListInfo_SSIDTimeGap[x]) + " min ago ]"
            if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
                if DontShowClient!=1:
                    cln=0
                    ClientCt=0
                    ToDisplayClient="1"
                    while cln < len(ListInfo_STATION):
                        if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                            UNASSOC=1
                        if ListInfo_BSSID[x]==ListInfo_CBSSID[cln]:
                            ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_PROBE_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_PROBE_FILTER=="Yes":
                                    if len(ListInfo_PROBE[cln])>0:
                                        ToDisplayClient="1"
                                elif __builtin__.NETWORK_PROBE_FILTER=="No":
                                    if len(ListInfo_PROBE[cln])==0:
                                        ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_ASSOCIATED_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_ASSOCIATED_FILTER=="Yes":
                                    if ListInfo_CBSSID[cln].find("not associated")==-1:
                                        ToDisplayClient="1"
                                if __builtin__.NETWORK_ASSOCIATED_FILTER=="No":
                                    if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                                        ToDisplayClient="1"
                            if ToDisplayClient=="1" and __builtin__.NETWORK_UNASSOCIATED_FILTER!="ALL":
                                ToDisplayClient=""
                                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes":
                                    if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                                        ToDisplayClient="1"
                                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="No":
                                    if ListInfo_CBSSID[cln].find("Not Associated")==-1:
                                        ToDisplayClient="1"
                            if  ToDisplayClient=="1" and __builtin__.NETWORK_CSIGNAL_FILTER!="ALL":
                                ToDisplayClient=""    
                                if ListInfo_CQualityRange[cln].find(__builtin__.NETWORK_CSIGNAL_FILTER)!=-1:
                                    ToDisplayClient="1"
                            if ToDisplayClient=="1":
                                Std11=ListInfo_STNStandard[cln]
                                Std11=Std11.replace("802.11 ","11")
                                MACCOLOR=fcolor.SGreen
                                SELFMAC=""
                                DLastSeen=""
                                if __builtin__.ListInfo_CTimeGap[cln]!="0":
                                    DLastSeen =fcolor.SBlack + " (Seen : " + str(__builtin__.ListInfo_CTimeGap[cln]) + " min ago)"
                                __builtin__.ListInfo_AssociatedCount += 1
                                if ListInfo_STATION[cln]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_MON_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_IFACE_MAC:
                                    MACCOLOR=fcolor.BPink
                                    SELFMAC=fcolor.BWhite + " [ " + fcolor.BPink + "Your Interface MAC" + fcolor.BWhite + " ]"
                                if int(__builtin__.ListInfo_CTimeGap[cln]) < int(__builtin__.HIDE_AFTER_MIN):
                                    DisplayClientCount=DisplayClientCount+1
                                    ClientCt=ClientCt+1
                                     
                                    print fcolor.SWhite + "   [" + fcolor.SGreen + str(ClientCt) + fcolor.SWhite + "]" + fcolor.BWhite + "\t  Client   :  - " + MACCOLOR + HighlightMonitoringMAC(str(ListInfo_STATION[cln])) + " " + fcolor.SBlue + str(Std11).ljust(15) + fcolor.SGreen + str(ListInfo_CBestQuality[cln]).ljust(7) + str(ListInfo_CQualityRange[cln]) + fcolor.CDim + fcolor.SGreen + "\t " + str(ListInfo_CLastSeen[cln]) + fcolor.CDim + fcolor.Cyan + "\t" + str(ListInfo_COUI[cln]) + str(DLastSeen) + str(SELFMAC)
                                else:
                                    if __builtin__.HIDE_INACTIVE_STN!="Yes":
                                        DisplayClientCount=DisplayClientCount+1
                                        ClientCt=ClientCt+1
                                        print fcolor.SBlack + "   [" + str(ClientCt) + "]" + "\t  Client   :  - " + HighlightMonitoringMAC(str(ListInfo_STATION[cln])) + " " + str(Std11).ljust(15)  + str(ListInfo_CBestQuality[cln]).ljust(7) + RemoveColor(str(ListInfo_CQualityRange[cln])) + "\t " + str(ListInfo_CLastSeen[cln]) + "\t" + str(ListInfo_COUI[cln]) + str(DLastSeen) + str(SELFMAC)
                                if ListInfo_PROBE[cln]!="" and __builtin__.NETWORK_VIEW!="5":
                                        if int(__builtin__.ListInfo_CTimeGap[cln]) < int(__builtin__.HIDE_AFTER_MIN):
                                                print fcolor.SWhite + "          Probe    :  - " + fcolor.SBlue + str(ListInfo_PROBE[cln])
                                        else:
                                            if __builtin__.HIDE_INACTIVE_STN!="Yes":
                                                print fcolor.SBlack + "          Probe    :  - " + fcolor.SBlack + str(ListInfo_PROBE[cln])
                        cln = cln + 1
            else:
                DisplayNotShownSSID += 1
            x=x+1
        DisplayUnassociated=0
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            if UNASSOC==1 and ToDisplayClient=="1":
                if __builtin__.NETWORK_UNASSOCIATED_FILTER=="Yes" or __builtin__.NETWORK_UNASSOCIATED_FILTER=="ALL": 
                    cln=0
                    print ""
                    CenterText(fcolor.BBlack + fcolor.BGIGreen,"< < << UNASSOCIATED STATIONS [Last seen within " + str(HIDE_AFTER_MIN) + " mins]   >> > >    ")
                    print fcolor.SYellow
                    while cln < len(ListInfo_STATION):
                        if ListInfo_CBSSID[cln].find("Not Associated")!=-1:
                            ToDisplay="1"
                            if __builtin__.NETWORK_UPROBE_FILTER!="ALL":
                                ToDisplay=""
                                if __builtin__.NETWORK_UPROBE_FILTER=="Yes" and ListInfo_PROBE[cln]!="":
                                    ToDisplay="1"
                                if __builtin__.NETWORK_UPROBE_FILTER=="No" and ListInfo_PROBE[cln]=="":
                                    ToDisplay="1"
                            if ToDisplay=="1" and __builtin__.NETWORK_UCSIGNAL_FILTER!="ALL":
                                ToDisplay=""
                                SRange=RemoveColor(str(ListInfo_CQualityRange[cln]))
                                if __builtin__.NETWORK_UCSIGNAL_FILTER==str(SRange):
                                    ToDisplay="1"
                            if ToDisplay=="1":
                                if int(__builtin__.ListInfo_CTimeGap[cln]) < int(__builtin__.HIDE_AFTER_MIN):
                                    MACCOLOR=fcolor.SGreen
                                    SELFMAC=""
                                    if ListInfo_STATION[cln]==__builtin__.SELECTED_MANIFACE_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_MON_MAC or ListInfo_STATION[cln]==__builtin__.SELECTED_IFACE_MAC:
                                        MACCOLOR=fcolor.BPink
                                        SELFMAC=fcolor.BWhite + " [ " + fcolor.BPink + "Your Interface MAC" + fcolor.BWhite + " ]"
                                    DisplayUnassociated += 1
                                    print MACCOLOR + HighlightMonitoringMAC(str(ListInfo_STATION[cln])) + "       " + fcolor.SGreen + str(ListInfo_CBestQuality[cln]).ljust(7) + str(ListInfo_CQualityRange[cln]) + fcolor.SGreen + "\t " + str(ListInfo_CFirstSeen[cln]) + "\t" + str(ListInfo_CLastSeen[cln]) + "   " + str(ListInfo_CTimeGapFull[cln]) + "\t" + str(ListInfo_COUI[cln]) + SELFMAC
                                    if ListInfo_PROBE[cln]!="" and __builtin__.NETWORK_VIEW=="4":
                                        print fcolor.SWhite + "Probe  : " + fcolor.BBlue + str(ListInfo_PROBE[cln])
                                else:
                                    DisplayNotShownClient=DisplayNotShownClient+1
                            else:
                                DisplayNotShownClient=DisplayNotShownClient+1
                        cln=cln+1 
                if DisplayUnassociated==0:
                    if __builtin__.DisplayUnassocFilter!="":
                        print fcolor.BWhite + "No matched unassociated station found !!"
                    else:
                        if __builtin__.NETWORK_UNASSOCIATED_FILTER!="No":
                            print fcolor.BRed + "No unassociated station found !!"
                if __builtin__.DisplayUnassocFilter!="":
                    print ""
                    print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayUnassocFilter)
            DrawLine("_",fcolor.CReset + fcolor.Black,"","")
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            CenterText(fcolor.BGBlue + fcolor.BWhite,"< < <<  SUMMARY  LISTING  >> > >      ")
            print fcolor.SYellow
        LblColor=fcolor.SYellow
        SummaryColor=fcolor.BGreen
        if __builtin__.NETWORK_VIEW=="1" or __builtin__.NETWORK_VIEW=="3":
             LineBreak()
        if __builtin__.DisplayNetworkFilter!="":
            print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayNetworkFilter)
        DTotalSSID=SummaryColor + str(len(ListInfo_BSSID)) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSCount) + " WPS" + LblColor + ")"
        DTotalSSID=str(DTotalSSID).ljust(53)
        DUpdated=SummaryColor + str(__builtin__.ListInfo_Exist) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSExist) + " WPS" + LblColor + ")"
        DUpdated=str(DUpdated).ljust(53)
        DAdded=SummaryColor + str(__builtin__.ListInfo_Add) + LblColor + " (" + SummaryColor + str(__builtin__.ListInfo_WPSAdd) + " WPS" + LblColor + ")"
        DAdded=str(DAdded).ljust(53)
        print LblColor + "SSID Total   : " + str(DTotalSSID) + "Updated      : " + str(DUpdated) + "Added : " + str(DAdded) + "Listed : " + SummaryColor + str(DisplayCount).ljust(11) + LblColor + "Not Shown : " + SummaryColor + str(DisplayNotShownSSID).ljust(11) + LblColor + "Enriched : " + SummaryColor + str(DisplayEnriched)
        print LblColor + "WPA/WPA2     : " + SummaryColor + str(WPACount).ljust(17) + LblColor + "WEP          : " + SummaryColor + str(WEPCount).ljust(17) + LblColor + "Open  : " + SummaryColor + str(OPNCount).ljust(17) + LblColor + "Others : " + SummaryColor + str(OTHCount).ljust(11) + LblColor + "Removed   : " + SummaryColor + str(ListInfo_BRemoved) 
        if __builtin__.NETWORK_VIEW=="4" or __builtin__.NETWORK_VIEW=="5":
            if __builtin__.DisplayClientFilter!="":
                print fcolor.BGreen + "Filter       : " + str(__builtin__.DisplayClientFilter)
            print LblColor + "Station Total: " + SummaryColor + str(len(ListInfo_STATION)).ljust(17) + LblColor + "Updated      : " + SummaryColor + str(__builtin__.ListInfo_CExist).ljust(17) + LblColor + "Added : " + SummaryColor + str(__builtin__.ListInfo_CAdd).ljust(17) + LblColor + "Listed : " + SummaryColor + str(DisplayClientCount).ljust(11) + LblColor + "Not Shown : " +  SummaryColor + str(DisplayNotShownClient)
            print LblColor + "Connected    : " + SummaryColor + str(__builtin__.ListInfo_AssociatedCount).ljust(17) + LblColor + "Unassociated : " + SummaryColor + str(__builtin__.ListInfo_UnassociatedCount).ljust(17) + LblColor + "Probe : " + SummaryColor + str(__builtin__.ListInfo_ProbeCount).ljust(37) + LblColor + "Removed   : " + SummaryColor + str(ListInfo_CRemoved) 
        print ""
                 

def DisplayPanel():
    os.system('clear')
    os.system('clear')
    ShowBanner()
    ShowSYWorks()
    print "\n\n" + fcolor.BGreen + apptitle + " " +  fcolor.SGreen + appDesc + fcolor.SGreen + ", By SYChua"
    LineBreak()
    return

def FindMACIndex(MACAddr,ListToFind):
    MACIndex=-1
    MACLoc=str(ListToFind).find(str(MACAddr))
    if MACLoc!=-1:
        MACIndex=int(MACLoc) -2
        MACIndex=MACIndex/21
        if ListToFind[MACIndex]!=MACAddr:
            MACIndex=-1
    return MACIndex

def RewriteIWList():
    if IsFileDirExist(__builtin__.TMP_IWList_DUMP)=="F" and __builtin__.FIXCHANNEL==0:
        open(__builtin__.IWList_DUMP,"w").write("")
        with open(__builtin__.TMP_IWList_DUMP,"r") as f:
            for line in f:
                line=line.replace("      Cell ","\n      Cell ").replace("\n\n","\n").replace("\00","").lstrip().rstrip()
                open(__builtin__.IWList_DUMP,"a+b").write(line + "\n")

def EnrichSSID():
    if __builtin__.FIXCHANNEL==0:
        RewriteIWList()
    if IsFileDirExist(__builtin__.TMP_IWList_DUMP)=="F" and __builtin__.FIXCHANNEL==0:
        open(__builtin__.TMP_IWList_DUMP,"a+b").write("Cell XX - Address: XX:XX:XX:XX:XX:XX")
        BSSID="";ESSI="";Freq="";Channel="";Quality="";Signal="";PairwiseCipher="";GroupCipher="";AuthSuite="";WPAVer="";EncKey="";WMode="";BitRate="";
        with open(__builtin__.TMP_IWList_DUMP,"r") as f:
            FoundStage="0"
            for line in f:
                line=line.replace("\n","").replace("\00","").lstrip().rstrip()
                if len(line)>1:
                    if str(line).find("Cell ")!=-1 and str(line).find("Address:")!=-1:
                        if FoundStage=="0":
                            FoundStage="1"
                            FLoc=str(line).find("Address:")
                            BSSID=str(line)[FLoc:].replace("Address:","").lstrip().rstrip()
                        else:
                            if BitRate!="" and BitRate[-3:]==" | ":
                                BitRate=BitRate[:-3]
                            if str(ListInfo_BSSID).find(str(BSSID))!=-1:
                                y=FindMACIndex(BSSID,ListInfo_BSSID)
                                __builtin__.ListInfo_Enriched[y]="Yes"
                                if Freq!="":
                                    __builtin__.ListInfo_Freq[y]=str(Freq)
                                if ESSID!="" and IsAscii(ESSID)==True and str(ESSID).find("\\x")==-1:
                                    if __builtin__.ListInfo_ESSID[y]!=str(ESSID):
                                        __builtin__.ListInfo_ESSID[y]=str(ESSID)
                                if Channel!="":
                                    __builtin__.ListInfo_Channel[y]=str(Channel)
                                if Quality!="":
                                    __builtin__.ListInfo_Quality[y]=str(Quality)
                                if Signal!="":
                                    __builtin__.ListInfo_Signal[y]=str(Signal)
                                    __builtin__.ListInfo_BestQuality[y]=str(Signal)
                                if BitRate!="":
                                    __builtin__.ListInfo_BitRate[y]=str(BitRate)
                                if LastBeacon!="":
                                    __builtin__.ListInfo_LastBeacon[y]=str(LastBeacon)
                                if PairwiseCipher!="":
                                    __builtin__.ListInfo_PairwiseCipher[y]=str(PairwiseCipher)
                                if GroupCipher!="":
                                    __builtin__.ListInfo_GroupCipher[y]=str(GroupCipher)
                                if AuthSuite!="":
                                    __builtin__.ListInfo_AuthSuite[y]=str(AuthSuite)
                                    if __builtin__.ListInfo_Auth[y]=="-" and len(AuthSuite)<5:
                                        __builtin__.ListInfo_Auth[y]=str(AuthSuite)
                                if WMode!="":
                                    __builtin__.ListInfo_Mode[y]=str(WMode)
                                if WPAVer!="":
                                    __builtin__.ListInfo_WPAVer[y]=str(WPAVer)
                                if EncKey!="":
                                    __builtin__.ListInfo_EncKey[y]=str(EncKey)
                                if WPAVer!="":
                                    if __builtin__.ListInfo_Privacy[y]=="" or __builtin__.ListInfo_Privacy[y]=="None":
                                       if str(WPAVer).find("WPA2")!=-1:
                                           __builtin__.ListInfo_Privacy[y]="WPA2"
                                       elif str(WPAVer).find("WPA ")!=-1:
                                           __builtin__.ListInfo_Privacy[y]="WPA"
                                if PairwiseCipher!="" and __builtin__.ListInfo_Cipher[y]=="-":
                                    __builtin__.ListInfo_Cipher[y]=PairwiseCipher
                            BSSID="";ESSID="";Freq="";Channel="";Quality="";Signal="";PairwiseCipher="";GroupCipher="";AuthSuite="";WPAVer="";EncKey="";WMode="";BitRate="";
                            FoundStage="1"
                            FLoc=str(line).find("Address:")
                            BSSID=str(line)[FLoc:].replace("Address:","").lstrip().rstrip()
                    if str(line).find("Frequency:")!=-1 and str(line).find("GHz")!=-1:
                        FLoc=str(line).find("Frequency:")
                        FLoc2=str(line).find("GHz")
                        Freq=str(line)[FLoc:-FLoc2].replace("Frequency:","").lstrip().rstrip()
                    if str(line).find("Channel ")!=-1 and str(line).find(")")!=-1:
                        line=line.replace("(","").replace(")","")
                        FLoc=str(line).find("Channel ")
                        Channel=str(line)[FLoc:].replace("Channel","").lstrip().rstrip()
                    if str(line).find("ESSID:\x22")!=-1 and str(line).find("ESSID:\x22\x22")==-1:
                        line=line.replace("ESSID:\x22","")
                        ESSID=str(line)[:-1]
                    if str(line).find("Quality=")!=-1 and str(line).find(" ")!=-1:
                        FLoc=str(line).find("Quality=")
                        FLoc2=str(line).find(" ")
                        FLoc2=len(line)-int(FLoc2)
                        Quality=str(line)[FLoc:-FLoc2].replace("Quality=","").lstrip().rstrip()
                    if str(line).find("Signal level=")!=-1:
                        FLoc=str(line).find("Signal level=")
                        Signal=str(line)[FLoc:].replace("Signal level=","").replace("dBm","").lstrip().rstrip()
                    if str(line).find("Mb/s")!=-1:
                        line=line.replace(";", " |").replace("Bit Rates:","")
                        BitRate=BitRate + str(line).lstrip().rstrip() + " | "
                    if str(line).find("Extra:")!=-1 or str(line).find("IE: ")!=-1:
                        if FoundStage=="1":
                            FoundStage="2"
                    if str(line).find("Last beacon: ")!=-1:
                        FLoc=str(line).find("Last beacon: ")
                        FLoc2=str(line).find("ago")
                        FLoc2=len(line)-int(FLoc2)
                        LastBeacon=str(line)[FLoc:-FLoc2].replace("Last beacon: ","").lstrip().rstrip()
                    if str(line).find("Pairwise Ciphers ")!=-1:
                        FLoc=str(line).find("Pairwise Ciphers ")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            PairwiseCipher=line.replace(" ","/")
                    if str(line).find("Group Cipher : ")!=-1:
                        FLoc=str(line).find("Group Cipher : ")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            GroupCipher=line.replace(" ","/")
                    if str(line).find("Authentication Suites")!=-1:
                        FLoc=str(line).find("Authentication Suites")
                        line=line[FLoc:]
                        FLoc=str(line).find(" : ")
                        if FLoc!=-1:
                            FLoc=FLoc+3
                            line=line[FLoc:]
                            AuthSuite=line
                    if str(line).find("WPA Version")!=-1:
                        FLoc=str(line).find("WPA Version")
                        line=line[FLoc:]
                        WPAVer=line
                    if str(line).find("WPA2 Version")!=-1:
                        FLoc=str(line).find("WPA2 Version")
                        line=line[FLoc:]
                        WPAVer=line
                    if str(line).find("Encryption key:")!=-1:
                        FLoc=str(line).find("Encryption key:")
                        line=line[FLoc:]
                        EncKey=line.replace("Encryption key:","")
                    if str(line).find("Mode:")!=-1:
                        FLoc=str(line).find("Mode:")
                        line=line[FLoc:]
                        WMode=line.replace("Mode:","")

def GetFrequency(sChannel):
    Freq=""
    if sChannel!="":
        if sChannel=='1':
            Freq = '2.412'
        if sChannel=='2':
            Freq = '2.417'
        if sChannel=='3':
            Freq = '2.422'
        if sChannel=='4':
            Freq = '2.427'
        if sChannel=='5':
            Freq = '2.432'
        if sChannel=='6':
            Freq = '2.437'
        if sChannel=='7':
            Freq = '2.442'
        if sChannel=='8':
            Freq = '2.447'
        if sChannel=='9':
            Freq = '2.452'
        if sChannel=='10':
            Freq = '2.457'
        if sChannel=='11':
            Freq = '2.462'
        if sChannel=='12':
            Freq = '2.467'
        if sChannel=='13':
            Freq = '2.472'
        if sChannel=='14':
            Freq = '2.484'
        if sChannel=='131':
            Freq = '3.6575'
        if sChannel=='132':
            Freq = '3.6625'
        if sChannel=='132':
            Freq = '3.66'
        if sChannel=='133':
            Freq = '3.6675'
        if sChannel=='133':
            Freq = '3.665'
        if sChannel=='134':
            Freq = '3.6725'
        if sChannel=='134':
            Freq = '3.67'
        if sChannel=='135':
            Freq = '3.6775'
        if sChannel=='136':
            Freq = '3.6825'
        if sChannel=='136':
            Freq = '3.68'
        if sChannel=='137':
            Freq = '3.6875'
        if sChannel=='137':
            Freq = '3.685'
        if sChannel=='138':
            Freq = '3.6895'
        if sChannel=='138':
            Freq = '3.69'
        if sChannel=='183':
            Freq = '4.915'
        if sChannel=='184':
            Freq = '4.92'
        if sChannel=='185':
            Freq = '4.925'
        if sChannel=='187':
            Freq = '4.935'
        if sChannel=='188':
            Freq = '4.94'
        if sChannel=='189':
            Freq = '4.945'
        if sChannel=='192':
            Freq = '4.96'
        if sChannel=='196':
            Freq = '4.98'
        if sChannel=='16':
            Freq = '5.08'
        if sChannel=='34':
            Freq = '5.17'
        if sChannel=='36':
            Freq = '5.18'
        if sChannel=='38':
            Freq = '5.19'
        if sChannel=='40':
            Freq = '5.20'
        if sChannel=='42':
            Freq = '5.21'
        if sChannel=='44':
            Freq = '5.22'
        if sChannel=='46':
            Freq = '5.23'
        if sChannel=='48':
            Freq = '5.24'
        if sChannel=='52':
            Freq = '5.26'
        if sChannel=='56':
            Freq = '5.28'
        if sChannel=='60':
            Freq = '5.30'
        if sChannel=='64':
            Freq = '5.32'
        if sChannel=='100':
            Freq = '5.50'
        if sChannel=='104':
            Freq = '5.52'
        if sChannel=='108':
            Freq = '5.54'
        if sChannel=='112':
            Freq = '5.56'
        if sChannel=='116':
            Freq = '5.58'
        if sChannel=='120':
            Freq = '5.60'
        if sChannel=='124':
            Freq = '5.62'
        if sChannel=='128':
            Freq = '5.64'
        if sChannel=='132':
            Freq = '5.66'
        if sChannel=='136':
            Freq = '5.68'
        if sChannel=='140':
            Freq = '5.70'
        if sChannel=='149':
            Freq = '5.745'
        if sChannel=='153':
            Freq = '5.765'
        if sChannel=='154':
            Freq = '5.770'
        if sChannel=='155':
            Freq = '5.775'
        if sChannel=='156':
            Freq = '5.780'
        if sChannel=='157':
            Freq = '5.785'
        if sChannel=='158':
            Freq = '5.790'
        if sChannel=='159':
            Freq = '5.795'
        if sChannel=='160':
            Freq = '5.80'
        if sChannel=='161':
            Freq = '5.805'
        if sChannel=='162':
            Freq = '5.810'
        if sChannel=='163':
            Freq = '5.815'
        if sChannel=='164':
            Freq = '5.820'
        if sChannel=='165':
            Freq = '5.825'
    return Freq;
               

def GetIWList(cmdMode,SELECTED_IFACE,RETRY):
    if RETRY=="":
        __builtin__.AP_BSSIDList=[]
        __builtin__.AP_FREQList=[]
        __builtin__.AP_QUALITYList=[]
        __builtin__.AP_SIGNALList=[]
        __builtin__.AP_ENCKEYList=[]
        __builtin__.AP_ESSIDList=[]
        __builtin__.AP_MODEList=[]
        __builtin__.AP_CHANNELList=[]
        __builtin__.AP_ENCTYPEList=[]
    POPULATE=0
    if len(__builtin__.AP_BSSIDList)>0:
        Result=AskQuestion(fcolor.SGreen + "An existing list with [ " + fcolor.BRed + str(len(__builtin__.AP_BSSIDList)) + fcolor.SGreen + " ] records were found, " + fcolor.BGreen + "populate existing ?","Y/n","U","Y","1")
        if Result=="Y":
            POPULATE=1
        else:
            __builtin__.AP_BSSIDList=[]
            __builtin__.AP_FREQList=[]
            __builtin__.AP_QUALITYList=[]
            __builtin__.AP_SIGNALList=[]
            __builtin__.AP_ENCKEYList=[]
            __builtin__.AP_ESSIDList=[]
            __builtin__.AP_MODEList=[]
            __builtin__.AP_CHANNELList=[]
            __builtin__.AP_ENCTYPEList=[]
    cmdMode=cmdMode.upper()
    if cmdMode=="":
        cmdMode="ALL"
    Result=Run("ifconfig " + SELECTED_IFACE + " up","1")
    Result=printc (".","<$rs$>" + "Scanning for Access Point..Please wait..","")
    printl(Result,"1","")
    iwlistfile=appdir + "tmp/scan.lst"
    Result=Run("iwlist " + SELECTED_IFACE + " scanning > " + iwlistfile ,"0")
    printl(fcolor.BGreen + " [Completed]","1","")
    print ""
    statinfo = os.stat(iwlistfile)
    if statinfo.st_size==0:
        printc ("@",fcolor.SRed + "Scanning failed to get any access point..Retrying in 5 seconds..","5")
        GetIWList(cmdMode,SELECTED_IFACE,"1")
        return
    f = open( iwlistfile, "r" )
    __builtin__.AP_BSSID=""
    __builtin__.AP_FREQ=""
    __builtin__.AP_QUALITY=""
    __builtin__.AP_SIGNAL=""
    __builtin__.AP_ENCKEY=""
    __builtin__.AP_ESSID=""
    __builtin__.AP_MODE=""
    __builtin__.AP_CHANNEL=""
    __builtin__.AP_ENCTYPE=""
    if POPULATE=="1":
        printc (".","Populating current list...","")
    for line in f:
        line=line.replace("\n","").lstrip().rstrip()
        if line.find("Cell ")!=-1:
            if __builtin__.AP_BSSID!="" and __builtin__.AP_MODE!="":
                if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="ON":
                    __builtin__.AP_ENCTYPE="WEP"
                if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="OFF":
                    __builtin__.AP_ENCTYPE="OPEN"
                if __builtin__.AP_ENCTYPE=="WPA2/WPA":
                    __builtin__.AP_ENCTYPE=="WPA/WPA2"
                ADD=""
                if cmdMode=="ALL-S" and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="":
                    ADD="1"
                if cmdMode=="ALL":
                    ADD="1"
                if cmdMode=="WPA-S" and __builtin__.AP_ENCTYPE.find("WPA")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WPA" and __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                    ADD="1"
                if cmdMode=="WEP-S" and __builtin__.AP_ENCTYPE.find("WEP")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="WEP" and __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                    ADD="1"
                if cmdMode=="OPN-S" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
                    ADD="1"
                if cmdMode=="OPN" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                    ADD="1"
                if str(POPULATE)=="1":
                    if any(__builtin__.AP_BSSID in s for s in __builtin__.AP_BSSIDList):
                        ADD="0"
                if ADD=="1":
                    if int(__builtin__.AP_QUALITY[:2])<=35:
                        SNLColor=fcolor.IRed
                        BSNLColor=fcolor.BIRed
                    if int(__builtin__.AP_QUALITY[:2])>35 and int(__builtin__.AP_QUALITY[:2])<55:
                        SNLColor=fcolor.IYellow
                        BSNLColor=fcolor.BIYellow
                    if int(__builtin__.AP_QUALITY[:2])>=55:
                        SNLColor=fcolor.IGreen
                        BSNLColor=fcolor.BIGreen
                    if __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.IPink + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    if __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.IBlue + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    if __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                        __builtin__.AP_ENCTYPE=fcolor.ICyan + __builtin__.AP_ENCTYPE
                        __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
                    __builtin__.AP_BSSIDList.append(str(__builtin__.AP_BSSID))
                    __builtin__.AP_FREQList.append(str(__builtin__.AP_FREQ))
                    __builtin__.AP_QUALITYList.append(SNLColor + str(__builtin__.AP_QUALITY))
                    __builtin__.AP_SIGNALList.append(SNLColor + str(__builtin__.AP_SIGNAL))
                    __builtin__.AP_ENCKEYList.append(str(__builtin__.AP_ENCKEY))
                    __builtin__.AP_ESSIDList.append(str(BSNLColor + __builtin__.AP_ESSID))
                    __builtin__.AP_MODEList.append(str(__builtin__.AP_MODE))
                    __builtin__.AP_CHANNELList.append(str(__builtin__.AP_CHANNEL))
                    __builtin__.AP_ENCTYPEList.append(str(__builtin__.AP_ENCTYPE))
                __builtin__.AP_BSSID=""
                __builtin__.AP_FREQ=""
                __builtin__.AP_QUALITY=""
                __builtin__.AP_CHANNEL=""
                __builtin__.AP_SIGNAL=""
                __builtin__.AP_ENCKEY=""
                __builtin__.AP_ESSID=""
                __builtin__.AP_MODE=""
                __builtin__.AP_ENCTYPE=""
            POS=line.index('Address:')
            if POS>-1:
                POS=POS+9
                __builtin__.AP_BSSID=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Channel:")!=-1:
            POS=line.index('Channel:')
            if POS>-1:
                POS=POS+8
                __builtin__.AP_CHANNEL=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Frequency:")!=-1:
            POS=line.index('Frequency:')
            if POS>-1:
                POS=POS+10
                __builtin__.AP_FREQ=str(line[POS:])
                POS=__builtin__.AP_FREQ.index(' (')
                if POS>-1:
                    __builtin__.AP_FREQ=str(__builtin__.AP_FREQ[:POS])
        if __builtin__.AP_BSSID!="" and line.find("Quality=")!=-1:
            POS=line.index('Quality=')
            if POS>-1:
                POS=POS+8
                __builtin__.AP_QUALITY=str(line[POS:])
                POS=__builtin__.AP_QUALITY.index(' ')
                if POS>-1:
                    __builtin__.AP_QUALITY=str(__builtin__.AP_QUALITY[:POS])
        if __builtin__.AP_BSSID!="" and line.find("Signal level=")!=-1:
            POS=line.index('Signal level=')
            if POS>-1:
                POS=POS+13
                __builtin__.AP_SIGNAL=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Encryption key:")!=-1:
            POS=line.index('Encryption key:')
            if POS>-1:
                POS=POS+15
                __builtin__.AP_ENCKEY=str(line[POS:]).upper()
        if __builtin__.AP_BSSID!="" and line.find("ESSID:")!=-1:
            POS=line.index('ESSID:')
            if POS>-1:
                POS=POS+6
                __builtin__.AP_ESSID=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("Mode:")!=-1:
            POS=line.index('Mode:')
            if POS>-1:
                POS=POS+5
                __builtin__.AP_MODE=str(line[POS:])
        if __builtin__.AP_BSSID!="" and line.find("WPA2 Version")!=-1:
            if __builtin__.AP_ENCTYPE!="": 
                if __builtin__.AP_ENCTYPE.find("WPA2")==-1:
                    __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "/WPA2"
            else:
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "WPA2"
        if __builtin__.AP_BSSID!="" and line.find("WPA Version")!=-1:
            if __builtin__.AP_ENCTYPE!="": 
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "/WPA"
            else:
                __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE + "WPA"
        __builtin__.AP_ENCTYPE=__builtin__.AP_ENCTYPE.replace("\n","")
        if __builtin__.AP_ENCTYPE=="WPA2/WPA":
            __builtin__.AP_ENCTYPE="WPA/WPA2"
    f.close()
    if __builtin__.AP_BSSID!="" and __builtin__.AP_MODE!="":
        if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="ON":
            __builtin__.AP_ENCTYPE="WEP"
        if __builtin__.AP_ENCTYPE=="" and __builtin__.AP_ENCKEY=="OFF":
            __builtin__.AP_ENCTYPE="OPEN"
        if __builtin__.AP_ENCTYPE=="WPA2/WPA":
            __builtin__.AP_ENCTYPE=="WPA/WPA2"
        ADD=""
        if cmdMode=="ALL-S" and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="":
            ADD="1"
        if cmdMode=="ALL":
            ADD="1"
        if cmdMode=="WPA-S" and __builtin__.AP_ENCTYPE.find("WPA")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WPA" and __builtin__.AP_ENCTYPE.find("WPA")!=-1:
            ADD="1"
        if cmdMode=="WEP-S" and __builtin__.AP_ENCTYPE.find("WEP")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="WEP" and __builtin__.AP_ENCTYPE.find("WEP")!=-1:
            ADD="1"
        if cmdMode=="OPN-S" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1 and __builtin__.AP_ESSID.find("\\x")==-1 and __builtin__.AP_ESSID!="" and len(__builtin__.AP_ESSID)>2:
            ADD="1"
        if cmdMode=="OPN" and __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
            ADD="1"
        if ADD=="1":
            if int(__builtin__.AP_QUALITY[:2])<=35:
                SNLColor=fcolor.IRed
                BSNLColor=fcolor.BIRed
            if int(__builtin__.AP_QUALITY[:2])>35 and int(__builtin__.AP_QUALITY[:2])<55:
                SNLColor=fcolor.IYellow
                BSNLColor=fcolor.BIYellow
            if int(__builtin__.AP_QUALITY[:2])>=55:
                SNLColor=fcolor.IGreen
                BSNLColor=fcolor.BIGreen
            if __builtin__.AP_ENCTYPE.find("WPA")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.IPink + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            if __builtin__.AP_ENCTYPE.find("OPEN")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.IBlue + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            if __builtin__.AP_ENCTYPE.find("WEP")!=-1:
                __builtin__.AP_ENCTYPE=fcolor.ICyan + __builtin__.AP_ENCTYPE
                __builtin__.AP_BSSID=SNLColor + __builtin__.AP_BSSID
            __builtin__.AP_BSSIDList.append(str(__builtin__.AP_BSSID))
            __builtin__.AP_FREQList.append(str(__builtin__.AP_FREQ))
            __builtin__.AP_QUALITYList.append(SNLColor + str(__builtin__.AP_QUALITY))
            __builtin__.AP_SIGNALList.append(SNLColor + str(__builtin__.AP_SIGNAL))
            __builtin__.AP_ENCKEYList.append(str(__builtin__.AP_ENCKEY))
            __builtin__.AP_ESSIDList.append(str(BSNLColor + __builtin__.AP_ESSID))
            __builtin__.AP_MODEList.append(str(__builtin__.AP_MODE))
            __builtin__.AP_CHANNELList.append(str(__builtin__.AP_CHANNEL))
            __builtin__.AP_ENCTYPEList.append(str(__builtin__.AP_ENCTYPE))
        __builtin__.AP_BSSID=""
        __builtin__.AP_FREQ=""
        __builtin__.AP_QUALITY=""
        __builtin__.AP_CHANNEL=""
        __builtin__.AP_SIGNAL=""
        __builtin__.AP_ENCKEY=""
        __builtin__.AP_ESSID=""
        __builtin__.AP_MODE=""
        __builtin__.AP_ENCTYPE=""

def ConvertPackets(Display):
    spacing=""   # tabspacefull
    if IsFileDirExist(__builtin__.PacketDumpFileBak)=="F":
        GetFileDetail(__builtin__.PacketDumpFileBak)
        
        statinfo = os.stat(__builtin__.PacketDumpFileBak)
        ADDMSG=fcolor.SWhite + "[Packet size : " + str(__builtin__.FileSize) + "]"
        __builtin__.CurrentPacket=__builtin__.PacketDumpFileBak
        if statinfo.st_size>3145728:
            ADDMSG=ADDMSG + fcolor.SRed + "  (File > 3mb, will take some time to complete.)" 
        if Display!="":
            printl (spacing + fcolor.SGreen + "Converting Captured Packets...TCPDump, " + str(ADDMSG) + fcolor.SGreen,"0","")
        ps=subprocess.Popen("tcpdump -r " + str(__builtin__.PacketDumpFileBak) + " -e -vvv -t -nn > " + str(__builtin__.TCPDumpFileBak), shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        if Display!="":
            printl (spacing + fcolor.SGreen + "Converting Captured Packets...TShark, " + str(ADDMSG),"0","")
        ps=subprocess.Popen("tshark -r " + str(__builtin__.PacketDumpFileBak) + " -n -o column.format:'Time','%Cus:frame.time_epoch','ESSID','%Cus:wlan_mgt.ssid','Time','%Cus:frame.time_epoch','FN','%Cus:frame.number','SN','%Cus:wlan.seq','Duration','%Cus:wlan.duration','FCType','%Cus:wlan.fc.type','FCSub','%Cus:wlan.fc.type_subtype','FC','%Cus:wlan.fc','Protocol','%Cus:frame.protocols','DataRate','%Cus:radiotap.datarate','Pwr','%Cus:radiotap.dbm_antsignal','Freq','%Cus:radiotap.channel.freq','SA','%Cus:wlan.sa','DA','%Cus:wlan.da','TA','%Cus:wlan.ta','RA','%Cus:wlan.ra','BSSID','%Cus:wlan.bssid','FLen','%Cus:frame.len','DLen','%Cus:data.len','WEPKey','%Cus:wlan.wep.key','WEPIV','%Cus:wlan.wep.iv','WEPIVS','%Cus:wlan.wep.icv','TKIP','%Cus:wlan.tkip.extiv','Proto','%p','info','%i' > " + str(__builtin__.TSharkFileBak), shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait()
    __builtin__.SHOWRESULT=3
    RewriteNewPacket()
    __builtin__.SHOWRESULT=0
    if Display!="":
        printl (spacing + fcolor.BGreen + "Packet Conversion Done..","0","")

def RephaseLine(line):
    line=line.replace("Control frame,Control frame Control Wrapper,","Control ").replace("0xef74,0xd1b6","0xef74/d1b6").replace(" (No Data)","").replace("(No Data)","").replace("QoS CF-Ack + CF-Poll","QOS_CF-Ack+CF-Poll")
    line=line.replace("Beacon frame","Beacon").replace("QoS Null function","QoS_Null").replace("QoS Data","QoS_Data").replace("Probe Request","Probe_Request").replace("Probe Response","Probe_Response").replace(" (RA)","").replace(" (TA)","").replace("802.11 Block Ack Req","802.11-Block-Ack-Req").replace("Block Ack Req","Block-Ack-Req").replace("802.11 Block Ack","802.11-Block-Ack").replace("Fragmented IEEE 802.11 frame","Fragmented_Frame").replace("Unrecognized (Reserved frame)","Unrecognized").replace(" (No data)","").replace(" (Control-frame)","").replace("Association Response","Association_Response").replace("Association Request","Association_Request").replace("Null function","Null_Function").replace(" (Reserved frame)","").replace("Measurement Pilot","Measurement_Pilot").replace(" (BSSID)","").replace("Action No Ack","Action-No-Ack").replace("Data frame","Data").replace("Management frame","Management").replace(",Control frame Control Wrapper,Power-Save poll","Power-Save").replace("Control frame","Control").replace("CF-End + CF-Ack","CF-End+CF-Ack").replace("[Malformed Packet]","<Malformed>").replace("Control Wrapper","Control_Wrapper").replace("Aruba Management","Aruba_Management")
    line=line.replace("QOS_DATA + CF-ACKNOWLEDGEMENT","QoS_Data+CF-Ack").replace("QoS_Data + CF-Poll","QoS_Data+CF-Poll").replace("Reassociation Request","Reassociation_Request").replace("Reassociation Response","Reassociation_Response").replace("Disassociation Request","Disassociation_Request").replace("Disassociation Response","Disassociation_Response").replace("Authenticaition Request","Authenticaition_Request").replace("Authenticaition Response","Authenticaition_Response").replace("Deauthenticaition Request","Deauthenticaition_Request").replace("Deauthenticaition Response","Deauthenticaition_Response").replace("Power-Save poll","Power-Save-Poll").replace("QoS CF","Qos_CF")
    line=line.replace("Key (Message 1 of 4)","KeyMSG-1/4").replace("Key (Message 2 of 4)","KeyMSG-2/4").replace("Key (Message 3 of 4)","KeyMSG-3/4").replace("Key (Message 4 of 4)","KeyMSG-4/4").replace("EAP Request, ","EAP_REQ\t").replace("EAP Response, ","EAP_RSP\t").replace(" + ","+")
    line=line.replace("Expanded Type, WPS, WSC_DONE","ET_WPS_WSC_DONE").replace("Expanded Type, WPS, M1","ET_WPS_M1").replace("Expanded Type, WPS, M2","ET_WPS_M2").replace("Expanded Type, WPS, M3","ET_WPS_M3").replace("Expanded Type, WPS, M4","ET_WPS_M4").replace("Expanded Type, WPS, M5","ET_WPS_M5").replace("Expanded Type, WPS, M6","ET_WPS_M6").replace("Expanded Type, WPS, M7","ET_WPS_M7").replace("Expanded Type, WPS, M8","ET_WPS_M8").replace("Expanded Type, WPS","ET_WPS")
    line=line.replace("\n","").replace("\r","").replace(", Flag","\tFlag").replace(", ","\t")
    line=line.replace(" frame ","\t")
    line=line.replace(" ","\t")
    line=line + "\t.\t.\t."
    line=str(line).lstrip().rstrip()
    return line

def RewriteNewPacket():
    spacing="" # tabspacefull
    linecount=0;lineblock=0
    if IsFileDirExist(__builtin__.TSharkFileBak)=="F":
        DATASTR="F.Num" + "\t" + "Seq.No" + "\t" + "Date/Time" + "\t" + "Duration" + "\t" + "F.Type" + "\t" + "F.SubType" + "\t" + "FCF" + "\t" + "Protocol" + "\t" + "DataRate" + "\t" + "Signal" + "\t" + "Freq" + "\t" + "Src.MAC" + "\t" + "Dst.MAC" + "\t" + "SA" + "\t" + "DA" + "\t" + "TA" + "\t" + "RA" + "\t" + "BSSID" + "\t" + "F.Len" + "\t" + "Len" + "\t" + "WEP.Key" + "\t" + "WEP.IV" + "\t" + "WEP.ICV" + "\t" + "TKIP.IV" + "\t" + "N.Type" + "\t" + "Command" + "\t" + "Flags" + "\n" 
        open(__builtin__.TSharkFileBak2,"w").write(DATASTR)
        Result=GetFileLine(__builtin__.TSharkFileBak,"1")
        with open(__builtin__.TSharkFileBak,"r") as f:
            for line in f:
                linecount += 1;lineblock += 1
                if __builtin__.SHOWRESULT==3 and lineblock==100:
                    completed=Percent(linecount / float(__builtin__.TotalLine),2)
                    printl (spacing + fcolor.SGreen + "Rewriting Result...TShark - " + str(completed),"0","")
                    lineblock=0
                tmplist=[]
                lineini=line 
                WriteLine=0
                pos=0
                if len(line)>60:
                    if line.find(" ")!=-1:
                        pos=line.index(' ')
                if pos==20:
                    DT_Date=line[:20]
                    line=line[21:]
                    pos=line.find(DT_Date)
                    if pos!=-1:
                       pos=pos-1
                       DT_ESSID=line[:pos]
                       pos=pos+22
                       line=line[pos:]
                       WriteLine=1
                if WriteLine==1:
                    line=RephaseLine(line)
                    tmplist=line.split("\t")
                    if len(tmplist)==25:
                        printc ("x","","")
                
                    if len(tmplist)>25:
                        CColor=fcolor.SRed
                        DT_FN=tmplist[0]				# Frame Number
                        DT_SN=tmplist[1]				# Seq Number
                        if len(DT_Date)==20:
                            DT_Date=ConvertEpoch(DT_Date)	# Frame Date/Time
                            CColor=fcolor.SGreen
                        DT_SSID=""
                        DT_Duration=tmplist[2]				# Duration
                        DT_FType=GetFrameType(tmplist[3])		# Framce Control Type
                        DT_FSubType=GetFrameSubType(tmplist[4])		# Framce Control SubType
                        DT_FCF=tmplist[5] 				# Frame Control Field
                        DT_FProtocol=tmplist[6]				# Frame Protocols
                        DT_DataRate=tmplist[7] + " Mb/s"		# Datarate
                        DT_Signal=tmplist[8] + "dB"			# Signal
                        DT_Freq=tmplist[9] + " MHz"			# Frequency
                        DT_SA=AdjustMAC(str(tmplist[10]))		# Src Address
                        DT_DA=AdjustMAC(str(tmplist[11]))		# Dst Address
                        DT_TA=AdjustMAC(str(tmplist[12]))		# Transmission Address
                        DT_RA=AdjustMAC(str(tmplist[13]))		# Recieving Address
                        DT_BSSID=AdjustMAC(str(tmplist[14]))		# BSSID    
                        DT_SRCMAC=""
                        DT_DSTMAC=""
                        if RemoveUnwantMAC(DT_TA)!="" and RemoveUnwantMAC(DT_RA)!="":
                            DT_SRCMAC=DT_TA
                            DT_DSTMAC=DT_RA
                        if RemoveUnwantMAC(DT_TA)=="" and RemoveUnwantMAC(DT_RA)!="" and RemoveUnwantMAC(DT_SA)=="" and RemoveUnwantMAC(DT_DA)=="":
                            DT_SRCMAC="FF:FF:FF:FF:FF:FF"
                            DT_DSTMAC=DT_RA
                        if RemoveUnwantMAC(DT_TA)!="" and RemoveUnwantMAC(DT_RA)=="" and RemoveUnwantMAC(DT_SA)=="" and RemoveUnwantMAC(DT_DA)=="":
                            DT_SRCMAC=DT_TA
                            DT_DSTMAC="FF:FF:FF:FF:FF:FF"
                        if RemoveUnwantMAC(DT_TA)!="" and RemoveUnwantMAC(DT_RA)!="" and RemoveUnwantMAC(DT_SA)=="" and RemoveUnwantMAC(DT_DA)=="":
                            DT_SRCMAC=DT_TA
                            DT_DSTMAC=DT_RA
                        if RemoveUnwantMAC(DT_SA)!="" and RemoveUnwantMAC(DT_DA)=="" and RemoveUnwantMAC(DT_TA)=="" and RemoveUnwantMAC(DT_RA)=="":
                            DT_SRCMAC=DT_SA
                            DT_DSTMAC=DT_DA
                        if RemoveUnwantMAC(DT_SA)!="" and RemoveUnwantMAC(DT_DA)!="":
                            DT_SRCMAC=DT_SA
                            DT_DSTMAC=DT_DA
                        if RemoveUnwantMAC(DT_SA)!="" and RemoveUnwantMAC(DT_TA)=="" and RemoveUnwantMAC(DT_RA)=="":
                            DT_SRCMAC=DT_SA
                            DT_DSTMAC=DT_DA
                        if RemoveUnwantMAC(DT_SA)!="" and RemoveUnwantMAC(DT_SA)!=RemoveUnwantMAC(DT_BSSID) and RemoveUnwantMAC(DT_DA)=="":
                            DT_SRCMAC=DT_SA
                            DT_DSTMAC=DT_BSSID
                        if RemoveUnwantMAC(DT_SA)=="" and RemoveUnwantMAC(DT_DA)=="" and RemoveUnwantMAC(DT_TA)=="" and RemoveUnwantMAC(DT_RA)=="":
                            DT_SRCMAC="XX:XX:XX:XX:XX:XX"
                            DT_DSTMAC="XX:XX:XX:XX:XX:XX"
                        DT_FLEN=tmplist[15]				# Frame Len
                        DT_LEN=tmplist[16]				# Data Len
                        DT_WEPKEY=tmplist[17]				# WEP KEY
                        DT_WEPIV=tmplist[18]				# WEP IV
                        DT_WEPICV=tmplist[19]				# WEP ICV
                        DT_TKIPIV=tmplist[20]				# TKIP EXTIV
                        DT_NTYPE=tmplist[21]				# 802.11
                        DT_NTYPE=str(DT_NTYPE).replace("IEEE ","")
                        DT_CMD=tmplist[22]				# FRAME TYPE
                        DT_FLAGS="";DT_FNA="";DT_SNA=""
                        cma=23
                        while cma<len(tmplist):
                            CMDA=tmplist[cma]		
                            if str(CMDA).find("Flags=")!=-1:
                                DT_FLAGS=CMDA
                                DT_FLAGS=DT_FLAGS[6:]
                            if str(CMDA).find("SN=")!=-1:
                                DT_SNA=CMDA
                                DT_SNA=DT_SNA[3:]
                            if str(CMDA).find("FN=")!=-1:
                                DT_FNA=CMDA
                                DT_FNA=DT_FNA[3:]
                            if str(CMDA).find("SSID=")!=-1:
                                DT_SSID=CMDA
                                DT_SSID=DT_SSID[5:]
                                if DT_SSID=="Broadcast":
                                    DT_SSID="<<Broadcast>>"
                            if DT_ESSID=="" and DT_SSID!="":
                                DT_ESSID=DT_SSID
                          
                            cma += 1
                        ToDisplay=0
                        if ToDisplay==1:
                            print fcolor.SGreen + "line : " + str(len(tmplist)) + "\n" + str(tmplist)
                            print fcolor.SWhite + "lineini : " + str(lineini)
                            print fcolor.SBlue + "line   : " + str(line)
                            print ""
                            print CColor + "00 DT_FN\t: " + str(DT_FN)
                            print "00 DT_FN\t: " + str(DT_FN)    
                            print "01 DT_SN\t: " + str(DT_SN)    
                            print "-- DT_Date\t: " + str(DT_Date)
                            print "02 DT_Duration\t: " + str(DT_Duration)
                            print "03 DT_FType\t: " + str(DT_FType)
                            print "04 DT_FSubType\t: " + str(DT_FSubType)
                            print "05 DT_FCF\t: " + str(DT_FCF)
                            print "06 DT_FProtocol\t: " + str(DT_FProtocol)
                            print "07 DT_DataRate\t: " + str(DT_DataRate)
                            print "08 DT_Signal\t: " + str(DT_Signal)
                            print "09 DT_Freq\t: " + str(DT_Freq)
                            print "10 DT_SA\t: " + str(DT_SA)
                            print "11 DT_DA\t: " + str(DT_DA)
                            print "12 DT_TA\t: " + str(DT_TA)
                            print "13 DT_RA\t: " + str(DT_RA)    
                            print "14 DT_BSSID\t: " + str(DT_BSSID)
                            print "-- DT_SRCMAC\t: " + str(DT_SRCMAC)
                            print "-- DT_DSTMAC\t: " + str(DT_DSTMAC)    
                            print "15 DT_FLEN\t: " + str(DT_FLEN)    
                            print "16 DT_LEN\t: " + str(DT_LEN)
                            print "17 DT_WEPKEY\t: " + str(DT_WEPKEY)
                            print "18 DT_WEPIV\t: " + str(DT_WEPIV)
                            print "19 DT_WEPICV\t: " + str(DT_WEPICV)
                            print "20 DT_TKIPIV\t: " + str(DT_TKIPIV)
                            print "-- DT_ESSID\t: " + str(DT_ESSID)
                            print "-- DT_SSID\t: " + str(DT_SSID)
                            print "21 DT_NTYPE\t: " + str(DT_NTYPE)
                            print "22 DT_CMD\t: " + str(DT_CMD)
                            print "-- DT_FLAGS\t: " + str(DT_FLAGS)
                            print "-- DT_FNA\t: " + str(DT_FNA)
                            print "-- DT_SNA\t: " + str(DT_SNA)
                            print "\n"
                            if CColor==fcolor.SRed:
                                printc ("x","","")
                    DATASTR=DT_FN + "\t" + DT_SN + "\t" + DT_Date + "\t" + DT_Duration + "\t" + DT_FType + "\t" + DT_FSubType + "\t" + DT_FCF + "\t" + DT_FProtocol + "\t" + DT_DataRate + "\t" + DT_Signal + "\t" + DT_Freq + "\t" + DT_SRCMAC+ "\t" + DT_DSTMAC+ "\t" + DT_SA+ "\t" + DT_DA + "\t" + DT_TA + "\t" + DT_RA + "\t" + DT_BSSID + "\t" + DT_FLEN + "\t" + DT_LEN + "\t" + DT_WEPKEY + "\t" + DT_WEPIV + "\t" + DT_WEPICV + "\t" + DT_TKIPIV + "\t" + DT_ESSID + "\t" + DT_NTYPE + "\t" + DT_CMD + "\t" + DT_FLAGS + "\n" 
                    open(__builtin__.TSharkFileBak2,"a+b").write(DATASTR)

def AdjustMAC(sMAC):
    sMAC=str(sMAC).upper().lstrip().rstrip()
    if sMAC=="":
        sMAC="XX:XX:XX:XX:XX:XX"
    return sMAC

def GetFrameType(FType):
    FType=str(FType).upper()
    if FType=="0":
        return "MGT" # Management
    if FType=="1":
        return "CTL" # Control
    if FType=="2":
        return "DTA" # Data
    if FType=="3":
        return "RSV" # Reserved
    return FType

def GetFrameSubType(subType):
    subType=str(subType).upper().replace("0X","")
    if subType=="00":
        return "Association_Request"
    if subType=="01":
        return "Association_Response"
    if subType=="02":
        return "Reassociation_Request"
    if subType=="03":
        return "Reassociation_Response"
    if subType=="04":
        return "Probe_Request"
    if subType=="05":
        return "Probe_Response"
    if subType=="08":
        return "Beacon"
    if subType=="09":
        return "ATIM"
    if subType=="0A":
        return "Disassociation"
    if subType=="0B":
        return "Authentication"
    if subType=="0C":
        return "Deauthentication"
    if subType=="0D":
        return "Action"
    if subType=="18":
        return "Block-Ack-Request"
    if subType=="19":
        return "Block-Ack"
    if subType=="1A":
        return "PS-Poll"
    if subType=="1B":
        return "RTS"
    if subType=="1C":
        return "CTS"
    if subType=="1D":
        return "ACK"
    if subType=="1E":
        return "CF-End"
    if subType=="1F":
        return "CF-End+CF-Ack"
    if subType=="20":
        return "Data"
    if subType=="21":
        return "Data+Ack"
    if subType=="22":
        return "Data+CF-Poll"
    if subType=="23":
        return "Data+CF_Ack+CF-Poll"
    if subType=="24":
        return "Null"
    if subType=="25":
        return "CF-Ack"
    if subType=="26":
        return "CF-Poll"
    if subType=="27":
        return "CF-Ack+CF-Poll"
    if subType=="28":
        return "QoS_Data"
    if subType=="29":
        return "QoS_Data+CF-Ack"
    if subType=="2A":
        return "QoS-Data+CF-Poll"
    if subType=="2B":
        return "QoS_Data+CF-Ack+CF-Poll"
    if subType=="2C":
        return "QoS_Null"
    if subType=="2D":
        return "Reserved"
    if subType=="2E":
        return "QoS+CF-Poll(ND)"
    if subType=="2F":
        return "QoS+CF-Ack(ND)"
    return subType
    

def ConvertEpoch(sTime):
    return datetime.datetime.fromtimestamp(float(sTime)).strftime('%Y-%m-%d %H:%M:%S')

def DeleteExistingPacketFiles():
    if IsFileDirExist(__builtin__.TCPDumpFileBak)=="F":
        os.remove(__builtin__.TCPDumpFileBak)
    if IsFileDirExist(__builtin__.TSharkFileBak_Std)=="F":
        os.remove(__builtin__.TSharkFileBak_Std)
    if IsFileDirExist(__builtin__.TSharkFileBak)=="F":
        os.remove(__builtin__.TSharkFileBak)
    if IsFileDirExist(__builtin__.TSharkFileBak2)=="F":
        os.remove(__builtin__.TSharkFileBak2)

def AnalyseTCPnTShark():
    __builtin__.SHOWRESULT=3
    spacing="" # tabspacefull
    printl (spacing + fcolor.SGreen + "Analysing Packets...TShark","0","")
    AnalyseTShark("")
    printl (spacing + fcolor.SGreen + "Analysing Packets...TCPDump","0","")
    AnalyseTCPDump("")
    printl (spacing + fcolor.BGreen + "Conversion & Analysing Done","0","")

def AnalysePacketCapture():
    if __builtin__.LOAD_PKTCAPTURE=="Yes":
        if __builtin__.PCapProc!="":
            KillSubProc(str(__builtin__.PCapProc))
        DeleteExistingPacketFiles()
        if IsFileDirExist(__builtin__.PacketDumpFileBak)=="F":
            os.remove(__builtin__.PacketDumpFileBak)
        if IsFileDirExist(__builtin__.PacketDumpFile)=="F":
            os.rename(__builtin__.PacketDumpFile,__builtin__.PacketDumpFileBak)
        RunPacketCapture()
        ConvertPackets("1")
        __builtin__.SHOWRESULT=3
        spacing="" # tabspacefull
        printl (spacing + fcolor.SGreen + "Analysing Packets...TShark","0","")
        AnalyseTShark("")
        printl (spacing + fcolor.BGreen + "Conversion & Analysing Done","0","")

def DisplayResponse(DisplayStr,spacing):
    print spacing + fcolor.SWhite + "Selected ==> " + fcolor.BYellow + str(DisplayStr)
    return

def ConvertByte(ibytes):
    import math
    if ibytes!=0:
        lst=['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
        i = int(math.floor(math.log(ibytes, 1024)))
        if i >= len(lst):
            i = len(lst) - 1
        return ('%.2f' + " " + lst[i]) % (ibytes/math.pow(1024, i))
    else:
        return "0 Byte"

def GetFileDetail(FName):
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(FName)
    __builtin__.FileModified=ConvertDateFormat(time.ctime(mtime),"%c")
    __builtin__.FileCreated=ConvertDateFormat(time.ctime(ctime),"%c")
    __builtin__.FileSize=ConvertByte(float(size))

def FormatNumber(sStr):
    return '{0:04}'.format(int(sStr))

def GetAllFiles():
    x=0
    while x<len(__builtin__.searchdir):
        __builtin__.lookupdir=__builtin__.searchdir[x]
        __builtin__.ExtList= ['txt','log','db','pcap','cap','ini']
        FFilter="*"
        SearchFiles(__builtin__.lookupdir,__builtin__.ExtList,FFilter)
        if len(__builtin__.FoundFiles)>0:
            __builtin__.AutoComplete=__builtin__.AutoComplete + __builtin__.FoundFiles
        x += 1

def RefreshAutoComplete(additional):
    __builtin__.AutoComplete=[]
    __builtin__.CommandList=['end','analyzer','analyzer2','analyzer3','enc','probe','about','help','logs','ips','ids','show','open','display','backup','wireshark','live','-f','lookup','mac','name','iwlist','dump','dump1','dump2','wash','list','list1','list2','list3','list4','filter','threshold','contain','ignore','clear','load','save','merge','-r','-w','cap','pcap','txt','db','log','new','reload','mymac','info','information','data','rm','ls','mon','attack','atk','monitor','back','exit','start','vgood','good','average','poor','unknown','opn','wep','wpa','wpa2','history']
    GetAllFiles()
    MyInternal=[DBFile1,DBFile2,DBFile3,DBFile4,DBFile5,DBFile6,EncDBFile,FilenameHeader + "Attacks.log",FilenameHeader + "Cautious.log",FilenameHeader + "Suspicious.log",'mac-oui.db']
    MYMAC=[__builtin__.SELECTED_IFACE_MAC,__builtin__.SELECTED_MON_MAC,__builtin__.SELECTED_MANIFACE_MAC]
    __builtin__.AutoComplete.extend(__builtin__.CommandList)
    __builtin__.AutoComplete=__builtin__.AutoComplete+__builtin__.ListInfo_BSSID + __builtin__.ListInfo_STATION + __builtin__.ListInfo_ESSID + MYMAC + MyInternal + __builtin__.searchdir
    __builtin__.AutoComplete=__builtin__.AutoComplete+__builtin__.MonitoringMACList + __builtin__.MonitoringNameList + __builtin__.ANALYSIS_MAC + __builtin__.ANALYSIS_IGNORE + __builtin__.ANALYSIS_TYPE + __builtin__.List_AttackingMAC + __builtin__.List_MonitoringMAC #+ __builtin__.List_AllMAC
    if __builtin__.ExtReadOut!="":
        addlist=[]
        tmpstr=str(__builtin__.ExtReadOut).replace("\t"," ").replace("\n"," ")
        addlist=[]
        addlist=tmpstr.split(" ")
        __builtin__.AutoComplete=__builtin__.AutoComplete+addlist
    if additional!="":
        addlist=[]
        addlist=additional.split("\n")
        addlist3=additional.split("\t")
        __builtin__.AutoComplete=__builtin__.AutoComplete+addlist
    list(set(__builtin__.AutoComplete))
    __builtin__.AutoComplete.sort()
    x=len(__builtin__.AutoComplete)-1
    while x>0:
        if len(__builtin__.AutoComplete[x])<2:
            __builtin__.AutoComplete.pop(x)
        x=x-1
    __builtin__.AutoComplete.sort()
    RemoveUnwantedAutoComplete()
    readline.parse_and_bind("tab: Complete")
    readline.set_completer(Complete)

def Complete(text, state):
    for cmd in __builtin__.AutoComplete:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1

def RemoveUnwantedAutoComplete():
    x=1
    while x<readline.get_current_history_length()+1:
        if int(len(readline.get_history_item(x)))<2 or readline.get_history_item(x)==".." or readline.get_history_item(x)=="...":
            readline.remove_history_item(x-1)
        x +=1

def GetInput():
    RemoveUnwantedAutoComplete()
    printl (fcolor.CReset,"0","")
    usr_resp=raw_input("CMD > ")
    if usr_resp!="":
        return usr_resp
    else:
        GetInput()
        return

def ReadCommand():
    __builtin__.CURRENT_LOC="ANALYSIS"
    RefreshAutoComplete("")
    RunCmd=""
    printl (fcolor.CReset,"0","")
    usr_resp=raw_input("CMD > ")
    RemoveUnwantedAutoComplete()
    usr_resp_n=str(usr_resp).lstrip().rstrip()
    usr_resp=str(usr_resp).upper().lstrip().rstrip().replace("\n","").replace("\r","")
    usrcmd=usr_resp.split(" ")
    usrcmd_n=usr_resp_n.split(" ")
    RECON_CMD=0
    spacing = "" # tabspacefull
    if usr_resp=="END" or usr_resp=="EXIT" or usr_resp=="BACK":
        DisplayResponse(usr_resp,"")
        return
    if usr_resp=="." or usr_resp==".." or usr_resp=="...":
        if usr_resp=="...":
            x=1;RECON_CMD=1
            CmdHistory="";RemoveUnwantedAutoComplete()
            while x<readline.get_current_history_length() + 1:
                if readline.get_history_item(x)!="":
                    CmdHistory=CmdHistory+readline.get_history_item(x) + "\n"
                x +=1
            CmdHistory=CmdHistory[:-1]
            if CmdHistory=="":
                print spacing + fcolor.SRed + "No command history found."
            else:
                print fcolor.BBlue + "Command History [" + str(x-1) + "]"
                print fcolor.SGreen + str(CmdHistory)
        elif __builtin__.LASTCMD=="" or __builtin__.LASTCMDLOG=="":
            print spacing + fcolor.SRed + "No last command found."
        else:
            if usr_resp==".":
                print spacing + fcolor.SGreen + "Executing last command - " + fcolor.BYellow + str(__builtin__.LASTCMD)
                usr_resp=str(__builtin__.LASTCMD).upper()
                usr_resp_n=__builtin__.LASTCMD
                usrcmd=usr_resp.split(" ")
            if usr_resp=="..":
                print fcolor.BBlue + "Command Logs"
                print fcolor.SGreen + str(__builtin__.LASTCMDLOG)
    if usr_resp=="ENC":
        RECON_CMD=1
        if __builtin__.ENCRYPTED_PASS=="":
            os.system("stty -echo")
            password=raw_input(spacing + fcolor.BGreen + "Enter your password : ")
            print ""
            os.system("stty echo")
            __builtin__.ENCRYPTED_PASS=Hashing(password)
        secret=str(__builtin__.ENCRYPTED_PASS)
        cipher = AES.new(secret)
        with open(EncDBFile,"r") as secretfile:
            EncStr=secretfile.read()
        decoded = DecodeAES(cipher, EncStr)
        if decoded.split('\n', 1)[0]!=__builtin__.ENCRYPTED_PASS:
            print spacing + fcolor.BRed + "You have entered an invalid password.."
            __builtin__.ENCRYPTED_PASS=""
        else:
            decodeds = '\n'.join(decoded.split('\n')[1:]) 
            print fcolor.CReset + fcolor.SWhite + decodeds
    if usr_resp=="ABOUT":
        RECON_CMD=1
        AboutApplication()
    if usrcmd[0]=="PROBE":
        RECON_CMD=1
        if len(usrcmd)==1:
            print spacing + fcolor.BBlue + "[PROBE] Function"
            print spacing + fcolor.SWhite + "Probe function is use to probe for a specified or multiple SSID Names."
            print spacing + fcolor.BWhite + "Examples :"
            print spacing + fcolor.SWhite + "          PROBE <ESSID-1>\t\t " + fcolor.SGreen + " - Probe for <ESSID-1>"
            print spacing + fcolor.SWhite + "          PROBE <ESSID-1> <ESSID-2>\t\t " + fcolor.SGreen + " - Probe for <ESSID-1> & <ESSID-2>\n"
        else:
            x=1
            PROBE_FOR=""
            while x<len(usrcmd):
                PROBE_FOR=PROBE_FOR + fcolor.BYellow + usrcmd_n[x] + fcolor.SWhite + " / "
                x += 1
            PROBE_FOR=PROBE_FOR[:-3]
            print tabspacefull + fcolor.BBlue + "Probing For : " + str(PROBE_FOR)
            x=1
            while x<len(usrcmd):
                print tabspacefull + fcolor.BBlue + "Probing For : " + str(usrcmd_n[x])
                ProbeESSID(usrcmd_n[x])
                x += 1
    if usr_resp=="LOGS":
        RECON_CMD=1
        OptDisplayLogs()
    if usr_resp=="HELP" or usr_resp=="?":
        RECON_CMD=1
        print spacing +fcolor.BBlue + "Interactive Mode Help"
        print spacing +fcolor.BWhite + "INFO / INFORMATION".ljust(25) + fcolor.SGreen + " - Display information of file, interfaces & setting"
        print spacing +fcolor.BWhite + "LOAD FILTER".ljust(25) + fcolor.SGreen + " - Load existing filter configuration (Config is preloaded in startup)"
        print spacing +fcolor.BWhite + "LOAD <file>".ljust(25) + fcolor.SGreen + " - Load an existing pcap file for analysis."
        print spacing +fcolor.BWhite + "LOAD NEW".ljust(25) + fcolor.SGreen + " - Load the current active captured pcap file"
        print spacing +fcolor.BWhite + "RELOAD".ljust(25) + fcolor.SGreen + " - Reload the previous captured pcap file for analysis."
        print spacing +fcolor.BWhite + "SAVE CONFIG".ljust(25) + fcolor.SGreen + " - Save setting to configuration file"
        print spacing +fcolor.BWhite + "SAVE FILTER".ljust(25) + fcolor.SGreen + " - Save filtered configuration"
        print spacing +fcolor.BWhite + "SAVE DATA".ljust(25) + fcolor.SGreen + " - Save pcap, raw result & filtered result files"
        print spacing +fcolor.BWhite + "LOOKUP".ljust(25) + fcolor.SGreen + " - Lookup for MAC/Name in active list & database"
        print spacing +fcolor.BWhite + "LOOKUP MAC".ljust(25) + fcolor.SGreen + " - Lookup for MAC address specified"
        print spacing +fcolor.BWhite + "LOOKUP NAME".ljust(25) + fcolor.SGreen + " - Lookup for SSID/Probe Name specidied"
        print spacing +fcolor.BWhite + "SHOW DUMP".ljust(25) + fcolor.SGreen + " - Show TCPDump & TShark result files"
        print spacing +fcolor.BWhite + "SHOW DUMP1".ljust(25) + fcolor.SGreen + " - Show TCPDump result file"
        print spacing +fcolor.BWhite + "SHOW DUMP2".ljust(25) + fcolor.SGreen + " - Show TShark result file"
        print spacing +fcolor.BWhite + "SHOW LIST".ljust(25) + fcolor.SGreen + " - Helps on <SHOW LIST>"
        print spacing +fcolor.BWhite + "SHOW LIST1".ljust(25) + fcolor.SGreen + " - Show TShark analysed listing"
        print spacing +fcolor.BWhite + "SHOW LIST2".ljust(25) + fcolor.SGreen + " - Show TShark analysed listing with filter"
        print spacing +fcolor.BWhite + "SHOW LIST3".ljust(25) + fcolor.SGreen + " - Show TShark analysed listing of interest (Based on IDS Sensitivity)"
        print spacing +fcolor.BWhite + "SHOW LIST4".ljust(25) + fcolor.SGreen + " - Show TShark analysed listing of interest (Based on Standard Threshold " + str(__builtin__.THRESHOLD) + ")"
        print spacing +fcolor.BWhite + "FILTER IGNORE *".ljust(25) + fcolor.SGreen + " - Hide Probe/Beacon/Acknowledgement type on result file. Type [FILTER] for detail"
        print spacing +fcolor.BWhite + "FILTER IGNORE -*".ljust(25) + fcolor.SGreen + " - Remove Probe/Beacon/Acknowledgement type filter on result file"
        print spacing +fcolor.BWhite + "FILTER IGNORE <type>".ljust(25) + fcolor.SGreen + " - Hide the <type> on result file"
        print spacing +fcolor.BWhite + "FILTER CONTAIN <string>".ljust(25) + fcolor.SGreen + " - Set filter string for the result file"
        print spacing +fcolor.BWhite + "FILTER CONTAIN -".ljust(25) + fcolor.SGreen + " - Remove all search filter string"
        print spacing +fcolor.BWhite + "FILTER MAC <MAC.Addr>".ljust(25) + fcolor.SGreen + " - Set MAC to search the result file"
        print spacing +fcolor.BWhite + "FILTER MAC -".ljust(25) + fcolor.SGreen + " - Remove all MAC filtering detail"
        print spacing +fcolor.BWhite + "SHOW FILTER".ljust(25) + fcolor.SGreen + " - Show the filtered items"
        print spacing +fcolor.BWhite + "MYMAC".ljust(25) + fcolor.SGreen + " - Show the MAC addresses of your interfaces use"
        print spacing +fcolor.BWhite + "WIRESHARK".ljust(25) + fcolor.SGreen + " - Open captured pcap file with wireshark"
        print spacing +fcolor.BWhite + "WIRESHARK LIVE".ljust(25) + fcolor.SGreen + " - Live sniffing with Wireshark using " + str(__builtin__.SELECTED_MON)
        print spacing +fcolor.BWhite + "WIRESHARK <file>".ljust(25) + fcolor.SGreen + " - Open the specified <file> with Wireshark"
        print spacing +fcolor.BWhite + "OPEN <file>".ljust(25) + fcolor.SGreen + " - Open the specified text file"
        print spacing +fcolor.BWhite + "LIST PCAP/TXT/LOG/DB".ljust(25) + fcolor.SGreen + " - List out the PCAP,Txt,DB or Log files in the designated directories. Type [LS] for detail."
        print spacing +fcolor.BWhite + "RM <files>".ljust(25) + fcolor.SGreen + " - Remove specified files, type [RM] for detail."
        print spacing +fcolor.BWhite + "MERGE -r <1> <2> -w <out>".ljust(25) + fcolor.SGreen + " - Merge two or more pcap files. Type [MERGE] for detail"
        print spacing +fcolor.BWhite + "BACKUP <file>".ljust(25) + fcolor.SGreen + " - Backup is use to backup the log or db files. Type [BACKUP] for detail."
        print spacing +fcolor.BWhite + "SET IDS".ljust(25) + fcolor.SGreen + " - Set sensitivity of current IDS detection threshold. Type [SET] for detail."
        print spacing +fcolor.BWhite + "CLEAR".ljust(25) + fcolor.SGreen + " - Clear screen"
        print spacing +fcolor.BWhite + "LOGS".ljust(25) + fcolor.SGreen + " - Display History Logs"
    if usrcmd[0]=="IPS":
        if len(usrcmd)==1:
            RECON_CMD=1
            ShowIntrusionPrevention("1")
            print spacing + fcolor.SGreen + "\nNote - You can also use 'IPS <MAC Address>' to directly launch the station deauth to the specified MAC"
        if len(usrcmd)==2:
            RECON_CMD=1
            ShowIntrusionPrevention(usrcmd[1])
    if usr_resp=="MENU":
        RECON_CMD=1
        GetOptionCommands("")
       
    if usrcmd[0]=="IDS":
        print spacing + fcolor.BBlue + "Running IDS..."
        RECON_CMD=1
        tmp=__builtin__.SAVE_ATTACKPKT
        tmp2=__builtin__.SHOW_SUSPICIOUS_LISTING
        __builtin__.SAVE_ATTACKPKT="No"
        __builtin__.SAVE_SUSPICIOUS_LISTING="No"
        ShowAnalysedListing("SHOW LIST3_QUIET")
        ShowIDSDetection("")
        __builtin__.SAVE_ATTACKPKT=tmp
        __builtin__.SAVE_SUSPICIOUS_LISTING=tmp2
        if len(__builtin__.OfInterest_List)==0:
            print spacing + fcolor.SRed + "No suspicious activity found.."
    if usrcmd[0]=="DISPLAY":
        if len(usrcmd)==1:
            RECON_CMD=1
            OptOutputDisplay("")
        else:
            if usrcmd[1].isdigit()==True and int(usrcmd[1])<10:
                RECON_CMD=1
                OptOutputDisplay(usrcmd[1])
    if usrcmd[0]=="OPEN":
        RECON_CMD=1
        if len(usrcmd)<2:
            print spacing + fcolor.BBlue + "[OPEN] Function"
            print spacing + fcolor.SWhite + "Open function allow user to open a specified file with default text viewer and wireshark."
            print spacing + fcolor.BWhite + "Examples :"
            print spacing + fcolor.SWhite + "          OPEN /SYWorks/Saved/AnalysedPacket.txt " + fcolor.SGreen + " - Open the specified file"
            print spacing + fcolor.SWhite + "          OPEN Attack_Captured.cap\t\t " + fcolor.SGreen + " - Open the pcap file with Wireshark"
        else:
            FName=str(usr_resp_n)[5:]
            FileExist=0
            rfile=SearchFileOnDir(FName)
            if rfile!="":
                FName=rfile
                FileExist=1
            if FileExist==1:
                if str(__builtin__.FileExt).upper()==".PCAP" or str(__builtin__.FileExt).upper()==".CAP":
                    print fcolor.SGreen + spacing + "[" + str(__builtin__.FileExt).upper().replace(".","") + "] extension detected, Redirecting as " + fcolor.BYellow + "WIRESHARK " + str(FName)
                    usr_resp_n="wireshark " + FName
                    usr_resp=usr_resp_n.upper()
                else:
                    print fcolor.BBlue + spacing  + "Load Text File - " + fcolor.BYellow + str(FName)
                    Explore(FName,"")
            else:
                DisplayFileNotFound(FName)
                Rund=""
    if usrcmd[0]=="BACKUP":
        RECON_CMD=1
        if len(usrcmd)<2:
            print spacing + fcolor.BBlue + "[BACKUP] Function"
            print spacing + fcolor.SWhite + "Backup function is use to backup the selected file and rewite the existing file as new."
            print spacing + fcolor.BWhite + "Examples :"
            print spacing + fcolor.SWhite + "          BACKUP /SYWorks/Database/Cautious.log" + fcolor.SGreen + " - Backup the specified file"
        else:
            FName=str(usr_resp_n)[7:]
            FileExist=0
            rfile=SearchFileOnDir(FName)
            if rfile!="":
                FName=rfile
                FileExist=1
            if FileExist==1:
                statinfo = os.stat(FName)
                if statinfo.st_size==0:
                    printc ("i",fcolor.BWhite + "The selected file [ " + fcolor.BRed + FName + fcolor.BWhite + " ] is empty, no backup needed.","")
                else:
                    ExtLen=len(__builtin__.FileExt)
                    FNameOnly=str(__builtin__.FileName)[:-ExtLen]
                    NewFileName=FNameOnly+"_BK_" + str(datetime.date.today()).replace("-","").replace("/","") + __builtin__.FileExt
                    NewFileNamePath=str(__builtin__.FilePath) + NewFileName
                    if IsFileDirExist(NewFileNamePath)=="F":
                        cp=1
                        while cp<9999:
                            NewFileName=FNameOnly+"_BK_" + str(datetime.date.today()).replace("-","").replace("/","") + "_" + str(cp) + __builtin__.FileExt
                            NewFileNamePath=str(__builtin__.FilePath) + NewFileName
                            if IsFileDirExist(NewFileNamePath)!="F":
                                cp=9999
                            cp += 1
                    printc (" ",fcolor.BYellow + "The selected file [ " + fcolor.BRed + FName + fcolor.BYellow + " ] will be saved as [ " + fcolor.BRed + NewFileName + fcolor.BYellow + " ]","")
                    printc (" ",fcolor.BWhite + "The selected file [ " + fcolor.BRed + FName + fcolor.BWhite + " ] will be " + fcolor.BRed + "EMPTIED" + fcolor.BWhite + " after backup.","")
                    usr_resp=AskQuestion("Continue ?","Y/n","U","Y","")
                    if usr_resp=="Y":
                        os.rename(FName,NewFileNamePath)
                        open(FName,"w").write("")
                        printc ("i","File Backuped - " + fcolor.BRed + str(NewFileNamePath),"")
                    else:
                        printc ("i","Backup Aborted.","")
            else:
                DisplayFileNotFound(FName)
                Rund=""
    if usrcmd[0]=="WIRESHARK":
        RECON_CMD=1
        if len(usrcmd)>1 and usrcmd[1]=="?":
            print spacing + fcolor.BBlue + "[WIRESHARK] Function"
            print spacing + fcolor.SWhite + "[WIRESHARK] function contain 3 options as listed below."
            print spacing + fcolor.BWhite + "Examples :"
            print spacing + fcolor.SWhite + "           WIRESHARK ?\t\t" + fcolor.SGreen + " - This help screen"
            print spacing + fcolor.SWhite + "           WIRESHARK\t\t" + fcolor.SGreen + " - Using Wireshark to open current loaded captured packets"
            print spacing + fcolor.SWhite + "           WIRESHARK <file>\t" + fcolor.SGreen + " - Using Wireshark to open the specified pcap file"
            print spacing + fcolor.SWhite + "           WIRESHARK -F\t\t" + fcolor.SGreen + " - Using Wireshark to open current load captured packets with MAC filters"
            print spacing + fcolor.SWhite + "           WIRESHARK -F <file>\t" + fcolor.SGreen + " - Using Wireshark to open the specified pcap file with MAC filters"
            print spacing + fcolor.SWhite + "           WIRESHARK LIVE\t" + fcolor.SGreen + " - Using Wireshark to sniff the current wireless traffic"
            RECON_CMD=1
        else:
            if IsProgramExists("wireshark")==True:
                Rund="wireshark -r " + str(__builtin__.CurrentPacket) + " > /dev/null 2>&1 &"
                if len(usrcmd)==1:
                    print fcolor.BBlue + spacing + "Open Current Captured Packets With Wireshark - " + fcolor.BYellow + str(__builtin__.CurrentPacket)
                    Rund="wireshark -r " + str(__builtin__.CurrentPacket) + " > /dev/null 2>&1 &"
                else:
                    if usrcmd[1]=="LIVE":
                        print fcolor.BBlue + spacing + "Live Capturing With Wireshark"
                        Rund="wireshark -i " + str(__builtin__.SELECTED_MON) + " -k -w " + str(__builtin__.WiresharkCap) + " > /dev/null 2>&1 &"
                    elif usrcmd[1]=="-F":
                        if len(__builtin__.ANALYSIS_MAC)!=0:
                            PCapFileToUse=__builtin__.CurrentPacket
                            if len(usrcmd)>2:
                                FName=str(usr_resp_n)[13:]
                                FileExist=0
                                rfile=SearchFileOnDir(FName)
                                if rfile!="":
                                    PCapFileToUse=rfile
                                else:
                                    DisplayFileNotFound(PCapFileToUse)
                                    Rund=""
                                    PCapFileToUse=""
                            if PCapFileToUse!="":
                                xm=0
                                fmac="";dfmac=""
                                while xm<len(__builtin__.ANALYSIS_MAC):
                                    fmac=fmac + "wlan.addr==" + str(__builtin__.ANALYSIS_MAC[xm]) + " or "
                                    dfmac=dfmac + str(__builtin__.ANALYSIS_MAC[xm]) + " / "
                                    xm += 1
                                fmac=fmac[:-4]
                                dfmac=dfmac[:-3]
                                print fcolor.BBlue + spacing + "Opening PCap Wireshark " + fcolor.BYellow + str(PCapFileToUse) + fcolor.BBlue + " - MAC filtered : " + fcolor.BRed + str(dfmac)
                                Rund="wireshark -r " + str(PCapFileToUse) + " -R '" +  str(fmac) + "' " + " > /dev/null 2>&1 &"
                        else:
                            print fcolor.BRed + spacing + "There is current no filter MAC specified. Type [FILTER MAC] for detail."
                            Rund=""
                    else:
                        FName=str(usr_resp_n)[10:]
                        FileExist=0
                        rfile=SearchFileOnDir(FName)
                        if rfile!="":
                            FName=rfile
                            FileExist=1
                        if FileExist==1:
                            print fcolor.BBlue + spacing + "Reading Packet File With Wireshark - " + fcolor.BYellow + str(FName)
                            Rund="wireshark -r " + str(FName) + " > /dev/null 2>&1 &"
                        else:
                            DisplayFileNotFound(FName)
                            Rund=""
                if Rund!="":    
                    result=os.system(Rund)
                    if result==0:
                        print fcolor.SGreen + spacing + "Wireshark loaded."
                    else:
                        print fcolor.SRed + spacing + "Wireshark failed to load."
                else:
                    print fcolor.SRed + spacing + "Operation aborted !"
            else:
                print fcolor.BRed + spacing + "Wireshark is not found. Operation aborted."
            print "\n" + spacing + fcolor.SGreen + "Type [Wireshark ?] for helps on Wireshark function."
    if usrcmd[0]=="LOOKUP":
        RECON_CMD=1
        MSG1=spacing + fcolor.BWhite + "Example :\n"
        MSG2=spacing + fcolor.SWhite + "          LOOKUP ?\t\t\t" + fcolor.SGreen + " - This help screen\n"
        MSG3=spacing + fcolor.SWhite + "          LOOKUP\t\t\t" + fcolor.SGreen + " - Launch the interactive lookup function (MAC/Name)\n"
        MSG4=spacing + fcolor.SWhite + "          LOOKUP MAC 00:01:02:03:04:05\t" + fcolor.SGreen + " - Search the actve SSID/Station and database for the MAC address\n"
        MSG5=spacing + fcolor.SWhite + "          LOOKUP MAC *:01:02:*\t\t" + fcolor.SGreen + " - Searching of MAC containing ':01:02:'\n"
        MSG6=spacing + fcolor.SWhite + "          LOOKUP NAME SYWorks\t\t" + fcolor.SGreen + " - Search the actve SSID/Station and database for the Name\n"
        MSG7=spacing + fcolor.SWhite + "          LOOKUP NAME SY*\t\t" + fcolor.SGreen + " - Searching of names starting with 'SY'\n"
        MSG8=spacing + fcolor.SWhite + "          LOOKUP ?\t\t\t" + fcolor.SGreen + " - For help on Lookup function\n"
        if len(usrcmd)<2:
                print spacing + fcolor.BBlue + "[LOOKUP] Function"
                print spacing + fcolor.SGreen + "Type [Lookup ?] for other options on Lookup function.\n"
                OptInfoDisplay("","")
        else:
            if usrcmd[1]=="?":
                print spacing + fcolor.BBlue + "[LOOKUP] Function"
                print spacing + fcolor.SWhite + "Lookup allow user to search the active SSID/Station listing or Database for the MAC address or SSID/Probe Name specified"
                print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 + MSG6 + MSG7
            if usrcmd[1]=="MAC":
                if len(usrcmd)<3:
                    print spacing + fcolor.BBlue + "[LOOKUP MAC] Function"
                    print spacing + fcolor.SWhite + "[Lookup MAC] is use to search for the MAC address detail found on active list and database."
                    print MSG1 + MSG4 + MSG5 + MSG8
                else:
                    sMAC=usrcmd[2]
                    tmac=str(sMAC).replace("*","").replace("-","").replace(":","")
                    if len(tmac)<13 and IsHex(tmac)==True:
                        print spacing + fcolor.BGreen + "Searching for MAC Address " + fcolor.BYellow + sMAC + fcolor.BGreen + "..."
                        LookupMAC(sMAC)
                        ProcessOptInfoDisplay()
                    else:
                        print spacing + fcolor.BRed + "Invalid MAC Address specified !"
            if usrcmd[1]=="NAME":
                if len(usrcmd)<3:
                    print spacing + fcolor.BBlue + "[LOOKUP NAME] Function"
                    print spacing + fcolor.SWhite + "[Lookup NAME] is use to search for the SSID Name/Probe detail found on active SSID/Station list and database"
                    print MSG1 + MSG6 + MSG7 + MSG8
                else:
                    print spacing + fcolor.BGreen + "Searching for SSID/Probe Name " + fcolor.BYellow + usrcmd[2] + fcolor.BGreen + "..."
                    LookupName(usrcmd[2])
                    ProcessOptInfoDisplay()
    
    if usrcmd[0]=="START":
        MSG1 =spacing + fcolor.BWhite + "Examples :\n"
        MSG2 =spacing + fcolor.SWhite + "          START ?\t\t\t" + fcolor.SGreen + " - This help screen\n"
        MSG3 =spacing + fcolor.SWhite + "          START IWLIST\t\t\t" + fcolor.SGreen + " - Run 'iwlist' to enrich Access Point detail\n"
        MSG4 =spacing + fcolor.SWhite + "          START DUMP\t\t\t" + fcolor.SGreen + " - Run 'Airodump-NG' to gather Access Point/Station Detail\n"
        MSG5 =spacing + fcolor.SWhite + "          START WASH\t\t\t" + fcolor.SGreen + " - Run 'Wash' to gather WPS enabled Access Points\n"
        if len(usrcmd)==1 or usrcmd[1]=="?":
            RECON_CMD=1
            print spacing + fcolor.BBlue + "[START] Function"
            print spacing + fcolor.SWhite + "[Start] with the combination of other command will launch the specified builtin application."
            print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 
        if len(usrcmd)==2:
            if usrcmd[1]=="IWLIST":
                RECON_CMD=1
                print spacing + fcolor.BBlue + "Started 'iwlist'."
                RunIWList()
            if usrcmd[1]=="DUMP":
                RECON_CMD=1
                print spacing + fcolor.BBlue + "Started 'airodump-ng'."
                RunAirodump()
            if usrcmd[1]=="WASH":
                RECON_CMD=1
                print spacing + fcolor.BBlue + "Started 'wash'."
                RunWash()
    if usrcmd[0]=="SHOW":
        MSG1 =spacing + fcolor.BWhite + "Examples :\n"
        MSG2 =spacing + fcolor.SWhite + "          SHOW ?\t\t\t" + fcolor.SGreen + " - This help screen\n"
        MSG3 =spacing + fcolor.SWhite + "          SHOW LIST\t\t\t" + fcolor.SGreen + " - Help screen for SHOW LIST\n"
        MSG4 =spacing + fcolor.SWhite + "          SHOW LIST1\t\t\t" + fcolor.SGreen + " - Catagorised Listing of analysed packets\n"
        MSG5 =spacing + fcolor.SWhite + "          SHOW LIST2\t\t\t" + fcolor.SGreen + " - Filtered Catagorised Listing of analysed packets <'Filter' function applies>.\n"
        MSG6 =spacing + fcolor.SWhite + "          SHOW LIST3\t\t\t" + fcolor.SGreen + " - Display only those record listing of hits the IDS threshold.\n"
        MSG7 =spacing + fcolor.SWhite + "          SHOW LIST4\t\t\t" + fcolor.SGreen + " - Display only those record listing of hits the standard threshold of " + str(__builtin__.THRESHOLD) + ".\n"
        MSG8 =spacing + fcolor.SWhite + "          SHOW DUMP ?\t\t\t" + fcolor.SGreen + " - Help screen for SHOW DUMP\n"
        MSG9 =spacing + fcolor.SWhite + "          SHOW DUMP\t\t\t" + fcolor.SGreen + " - Display the converted frame data with TCPDump & TShark. <'Filter' function applies>\n"
        MSG10 =spacing + fcolor.SWhite + "          SHOW DUMP1\t\t\t" + fcolor.SGreen + " - Display the converted frame data with TCPDump. <'Filter' function applies>\n"
        MSG11=spacing + fcolor.SWhite + "          SHOW DUMP2\t\t\t" + fcolor.SGreen + " - Display the converted frame data with TShark. <'Filter' function applies>\n"
        MSG12=spacing + fcolor.SWhite + "          SHOW FILTER ?\t\t\t" + fcolor.SGreen + " - Help screen for SHOW FILTER <Type 'Filter' for filter setting>'\n"
        MSG13=spacing + fcolor.SWhite + "          SHOW FILTER\t\t\t" + fcolor.SGreen + " - Display the list of filters set\n"
        MSG14=spacing + fcolor.SWhite + "          SHOW THRESHOLD\t\t" + fcolor.SGreen + " - Display the setting for standard detection threshold.\n"
        MSG15=spacing + fcolor.SWhite + "          SHOW IDS\t\t\t" + fcolor.SGreen + " - Display IDS sensitvity setting. See also [IDS] and [SET IDS]\n"
        MSG16=spacing + fcolor.SWhite + "          SHOW DISPLAY\t\t\t" + fcolor.SGreen + " - Display Active SSID/Station detail.\n"
        MSG0 ="\n" + spacing + fcolor.BYellow + "<'Filter' function applies>\n" + spacing + fcolor.SWhite + "If filter items are specified in 'FILTER MAC', 'FILTER CONTAIN' & 'FILTER IGNORE', output of 'SHOW LIST2', 'SHOW DUMP|1|2' will base on these filter criteria. Type [Filter ?] for other related filter options."
        MSG01=spacing + fcolor.SGreen + "Type [Show Dump ?] for other options on Show Dump function.\n"
        MSG02=spacing + fcolor.SGreen + "Type [Filter ?] for usage of Filter and other filter related functions."
        if len(usrcmd)==1 or usrcmd[1]=="?":
            RECON_CMD=1
            print spacing + fcolor.BBlue + "[SHOW] Function"
            print spacing + fcolor.SWhite + "[Show] is use with combination of other command to display information specified."
            print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 + MSG6 + MSG7 + MSG8 + MSG9 + MSG10 + MSG11 + MSG12 + MSG13 + MSG14 + MSG15 + MSG16+ MSG0
        if len(usrcmd)==2:
            if usrcmd[1]=="THRESHOLD":
                RECON_CMD=1
                print fcolor.SGreen + "CURRENT THRESHOLD : " + fcolor.BYellow + str(__builtin__.THRESHOLD)
            if usrcmd[1]=="IDS":
                RECON_CMD=1
                SetIDS_Sensitivity("0")
            if usrcmd[1]=="DISPLAY":
                RECON_CMD=1
                HarvestingProcess("1")
                HarvestingProcess("2")
                HarvestingProcess("3")
            if usrcmd[1]=="LIST":
                RECON_CMD=1
                print spacing + fcolor.BBlue + "[SHOW LIST] Function"
                print spacing + fcolor.SWhite + "[SHOW LIST] will display the detailed listing of analysed packets in a catagorised display showing the Source MAC, Dest MAC and number of specific packet types captured."
                print spacing + fcolor.SWhite + "It contain 3 type of listing options. [SHOW LIST1], [SHOW LIST2] & [SHOW LIST3].\n"
                print MSG1 + MSG3 + MSG4 + MSG5 + MSG6  + MSG7 + MSG0 
                print "\n" + spacing + fcolor.BCyan + "Shortcodes Use:"
                print spacing + fcolor.BYellow + "DTA  " + fcolor.SWhite + "- Data".ljust(30) + fcolor.BYellow + "D86  " + fcolor.SWhite + "- Data (Len:86)".ljust(30) + fcolor.BYellow + "D94  " + fcolor.SWhite + "- Data (Len:94)".ljust(30) + fcolor.BYellow + "D98  " + fcolor.SWhite + "- Data (Len:98)".ljust(30) 
                print spacing + fcolor.BYellow + "AUTH " + fcolor.SWhite + "- Authentication".ljust(30) + fcolor.BYellow + "DATH " + fcolor.SWhite + "- Deauthentication".ljust(30)  + fcolor.BYellow + "ASC  " + fcolor.SWhite + "- Association".ljust(30) + fcolor.BYellow + "DASC " + fcolor.SWhite + "- Deassociation".ljust(30) 
                print spacing + fcolor.BYellow + "RASC " + fcolor.SWhite + "- Reassociation".ljust(30) + fcolor.BYellow + "RTS  " + fcolor.SWhite + "- Request-To-Send".ljust(30) + fcolor.BYellow + "CTS  " + fcolor.SWhite + "- Clear-To-Send".ljust(30) + fcolor.BYellow + "ACK  " + fcolor.SWhite + "- Acknowledgement".ljust(30) 
                print spacing + fcolor.BYellow + "WPS  " + fcolor.SWhite + "- WPS".ljust(30) + fcolor.BYellow + "BCN  " + fcolor.SWhite + "- Beacon".ljust(30) + fcolor.BYellow + "RPN  " + fcolor.SWhite + "- Probe Response".ljust(30) + fcolor.BYellow + "RQX  " + fcolor.SWhite + "- Probe Request".ljust(30)
                print spacing + fcolor.BYellow + "NULL " + fcolor.SWhite + "- Null Function".ljust(30) + fcolor.BYellow + "QOS  " + fcolor.SWhite + "- QoS Data".ljust(30)   + fcolor.BYellow + "EPL  " + fcolor.SWhite + "- EAPOL Protocol".ljust(30) + fcolor.BYellow + "WPS  " + fcolor.SWhite + "- EAP Protocol".ljust(30)
            if usrcmd[1]=="LIST1" or usrcmd[1]=="LIST2"  or usrcmd[1]=="LIST3" or usrcmd[1]=="LIST4" or usrcmd[1]=="LIST1A" or usrcmd[1]=="LIST2A"  or usrcmd[1]=="LIST3A" or usrcmd[1]=="LIST4A":
                RECON_CMD=1
                ShowAnalysedListing(usr_resp)
        if len(usrcmd)==2 or len(usrcmd)==3:
            if usrcmd[1]=="DUMP":
                RECON_CMD=1
                if len(usrcmd)>2 and usrcmd[2]=="?":
                    print spacing + fcolor.BBlue + "[SHOW DUMP] Function"
                    print spacing + fcolor.SWhite + "[SHOW DUMP] displays the converted information of the captured/loaded pcap file. The are 2 options of display: [SHOW DUMP1] & [SHOW DUMP2]. Using the [SHOW DUMP] without '?' will launch both SHOW DUMP1 & 2 options."
                    print MSG1 + MSG8 + MSG9 + MSG10 + MSG11 + MSG0
                else:
                    __builtin__.SHOWRESULT=1
                    print spacing + fcolor.BBlue + "Showing Both TCPDump & TShark Converted Packets Dump"
                    print MSG01
                    LineBreak()
                    AnalyseTCPDump("1")
                    LineBreak()
                    AnalyseTShark("1")
                    LineBreak()
                    __builtin__.SHOWRESULT=0
            if usrcmd[1]=="DUMP1" or usrcmd[1]=="DUMP2" or usrcmd[1]=="DUMP1A" or usrcmd[1]=="DUMP2A":
                RECON_CMD=1
                print MSG01
                if usrcmd[1]=="DUMP1" or usrcmd[1]=="DUMP2":
                    __builtin__.SHOWRESULT=1
                if usrcmd[1]=="DUMP1A" or usrcmd[1]=="DUMP2A":
                    __builtin__.SHOWRESULT=2
                if usrcmd[1]=="DUMP1" or usrcmd[1]=="DUMP1A":
                    AnalyseTCPDump("1")
                if usrcmd[1]=="DUMP2" or usrcmd[1]=="DUMP2A":
                    AnalyseTShark("1")
                LineBreak()
                __builtin__.SHOWRESULT=0
            if usrcmd[1]=="FILTER":
                RECON_CMD=1
                if len(usrcmd)>2 and usrcmd[2]=="?":
                    print spacing + fcolor.BBlue + "[SHOW FILTER] Function"
                    print spacing + fcolor.SWhite + "[SHOW FILTER] display the 3 filter criterias that were set. These 3 filter criteria are [MAC] address, [CONTAIN] string and [IGNORE] type filtering."
                    print MSG1 + MSG12 + MSG13 + "\n" + MSG02
                else:
                    if len(__builtin__.ANALYSIS_SEARCH)==0 and len(__builtin__.ANALYSIS_IGNORE)==0  and len(__builtin__.ANALYSIS_MAC)==0:
                        print fcolor.BRed + spacing + "No filtering options found."
                        print  MSG02
                    else:
                        print fcolor.BBlue + spacing + "List of Filtering Criteria"
                        DisplayAnalysisFilters()
                        print "\n" + MSG02
    if usrcmd[0]=="ANALYZER" or usrcmd[0]=="ANALYZER2" or usrcmd[0]=="ANALYZER3":
        x=0;DisplayCt=0
        tmpANALYZER=[]
        RECON_CMD=1
        print spacing + fcolor.BBlue + "[ANALYZER] - For Advanced User"
        print spacing + fcolor.SWhite + "Analyzer is use to display those analyzed packets and list of those MAC addresses with frame type hits the threshold limit. This will be subsequently use to add new detection much easier. Using [ANALYZER2] will filter those match in MAC Filter List and ignore [BEACON] & [PROBE] and [ANALYZER3] will ignore only [BEACON] & [PROBE]."
        print fcolor.BWhite + "\nSN   " + fcolor.BGreen + "Source MAC".ljust(19) + fcolor.BPink + "Destination MAC".ljust(19) + fcolor.BWhite + "BSSID".ljust(19) + fcolor.BYellow + "Protocol".ljust(10) + fcolor.BBlue + "Frame Type".ljust(20) + fcolor.BGreen + "LEN".ljust(8) + fcolor.BCyan + "Flags".ljust(12) + fcolor.BRed + "Counts"
        while x<len(__builtin__.List_ANALYZER):
            tmpANALYZER=__builtin__.List_ANALYZER[x].split("\t")
            if int(tmpANALYZER[7])>=int(__builtin__.THRESHOLD):
                if usrcmd[0]=="ANALYZER":
                    ToDisplay=1
                if usrcmd[0]=="ANALYZER2" or usrcmd[0]=="ANALYZER3":
                    ToDisplay=0
                    if tmpANALYZER[4]!="BEACON" and str(tmpANALYZER[4]).find("PROBE")==-1:
                        ToDisplay=1
                        if usrcmd[0]=="ANALYZER2":
                            ToDisplay=0
                            if len(__builtin__.ANALYSIS_MAC)>0:
                                ToDisplay=0
                                yc=0
                                while yc < len(__builtin__.ANALYSIS_MAC):
                                    tmpsearch=str(__builtin__.ANALYSIS_MAC[yc]).upper()
                                    if str(tmpANALYZER[0]).find(tmpsearch)!=-1 or str(tmpANALYZER[1]).find(tmpsearch)!=-1 or str(tmpANALYZER[2]).find(tmpsearch)!=-1:
                                        ToDisplay=1
                                        yc=len(__builtin__.ANALYSIS_MAC)
                                    else:
                                        ToDisplay=0
                                    yc += 1
                            else:
                                ToDisplay=1
 
                if ToDisplay==1:
                    DisplayCt += 1
                    print fcolor.SWhite + str(DisplayCt).ljust(5) + fcolor.SGreen + str(tmpANALYZER[0]).ljust(19) + fcolor.SPink + str(tmpANALYZER[1]).ljust(19) + fcolor.SWhite + str(tmpANALYZER[2]).ljust(19) + "" + fcolor.SYellow + str(tmpANALYZER[3]).ljust(10) + fcolor.SBlue + str(tmpANALYZER[4]).ljust(20) + fcolor.SGreen + str(tmpANALYZER[5]).ljust(8) + fcolor.SCyan + str(tmpANALYZER[6]).ljust(12) + fcolor.SRed + str(tmpANALYZER[7])
            x=x+1
        print fcolor.SGreen + "\nFound : " + fcolor.BYellow + str(DisplayCt).ljust(5) + fcolor.SGreen + "Total : " + fcolor.SWhite + str(x)
        if usrcmd[0]=="ANALYZER2":
            DisplayAnalysisMACFilter("")
         
    if usrcmd[0]=="SET":
        MSG1 =spacing + fcolor.BWhite + "Examples :\n"
        MSG2 =spacing + fcolor.SWhite + "          SET ?\t\t\t" + fcolor.SGreen + " - This help screen\n"
        MSG3 =spacing + fcolor.SWhite + "          SET THRESHOLD <num>\t" + fcolor.SGreen + " - Set default IDS Threshold - Current : " + str(__builtin__.THRESHOLD) + " [Related - SHOW THRESHOLD]\n"
        MSG4 =spacing + fcolor.SWhite + "          SET IDS\t\t" + fcolor.SGreen + " - Set IDS Sensitivity. [Related - SHOW IDS, IDS]\n"
        MSG5 =spacing + fcolor.SWhite + "          SET IDS 4\t\t" + fcolor.SGreen + " - Set IDS Sensitivity Option number 4 \n"
        if len(usrcmd)==1 or usrcmd[1]=="?" or len(usrcmd)==2:
            RECON_CMD=1
            print spacing + fcolor.BBlue  + "[SET] Function"
            print spacing + fcolor.SWhite + "[SET] is use with combination of other command for various configuration."
            print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 
        if len(usrcmd)>=2:
            if usrcmd[1]=="THRESHOLD":
                if len(usrcmd)==3 and str(usrcmd[2]).isdigit()==True:
                    RECON_CMD=1
                    __builtin__.THRESHOLD=str(usrcmd[2])
                    print fcolor.SGreen + "THRESHOLD : " + fcolor.BYellow + str(__builtin__.THRESHOLD)
            if usrcmd[1]=="IDS":
                RECON_CMD=1
                if len(usrcmd)==3 and str(usrcmd[2]).isdigit()==True:
                    if int(usrcmd[2])>0 and int(usrcmd[2])<5:
                        SetIDS_Sensitivity(usrcmd[2])
                    else:
                        print fcolor.BRed + "IDS Sensitivity Setting is between range 1 to 4 !!"
                else:
                    SetIDS_Sensitivity("")
    if usrcmd[0]=="FILTER":
        MSG1 =spacing + fcolor.BWhite + "Examples :\n"
        MSG2 =spacing + fcolor.SWhite + "          FILTER ?\t\t\t" + fcolor.SGreen + " - This help screen\n"
        MSG3 =spacing + fcolor.SWhite + "          FILTER MAC ?\t\t\t" + fcolor.SGreen + " - Help screen for FILTER MAC\n"
        MSG4 =spacing + fcolor.SWhite + "          FILTER MAC 00:01:02:03:04:05\t" + fcolor.SGreen + " - Adding the specified MAC to filtering list\n"
        MSG5 =spacing + fcolor.SWhite + "          FILTER MAC - 00:01:02:03:04:05" + fcolor.SGreen + " - Removing the specified MAC from the list\n"
        MSG6 =spacing + fcolor.SWhite + "          FILTER MAC -\t\t\t" + fcolor.SGreen + " - Removing all MAC Filter\n"
        MSG7 =spacing + fcolor.SWhite + "          FILTER CONTAIN ?\t\t" + fcolor.SGreen + " - Help screen for FILTER CONTAIN\n"
        MSG8 =spacing + fcolor.SWhite + "          FILTER CONTAIN AUTHENTICATION\t" + fcolor.SGreen + " - Adding the specified String to filtering list\n"
        MSG9 =spacing + fcolor.SWhite + "          FILTER CONTAIN - DEAUTH\t" + fcolor.SGreen + " - Removing the specified String from the list\n"
        MSG10=spacing + fcolor.SWhite + "          FILTER CONTAIN -\t\t" + fcolor.SGreen + " - Removing all string found the the CONTAIN Filtering list\n"
        MSG11=spacing + fcolor.SWhite + "          FILTER IGNORE ?\t\t" + fcolor.SGreen + " - Help screen for FILTER IGNORE\n"
        MSG12=spacing + fcolor.SWhite + "          FILTER IGNORE PROBE\t\t" + fcolor.SGreen + " - Adding the specified string to ignored filter list\n"
        MSG13=spacing + fcolor.SWhite + "          FILTER IGNORE - PROBE\t\t" + fcolor.SGreen + " - Removing the specified string from ignored filter list\n"
        MSG14=spacing + fcolor.SWhite + "          FILTER IGNORE -\t\t" + fcolor.SGreen + " - Removing all string found the the IGNORE Filtering list\n"
        MSG15=spacing + fcolor.SWhite + "          FILTER IGNORE *\t\t" + fcolor.SGreen + " - Adding Probe Request/Response, Beacon, Acknowledgement to the IGNORE list\n"
        MSG16=spacing + fcolor.SWhite + "          FILTER IGNORE -*\t\t" + fcolor.SGreen + " - Removing Probe Request/Response, Beacon, Acknowledgement from the IGNORE list\n"
        MSG17 ="\n" + spacing + fcolor.BWhite + "Other Related :\n"
        MSG18 =spacing + fcolor.SWhite + "          SHOW FILTER\t\t\t" + fcolor.SGreen + " - Show the current filter list\n"
        MSG19 =spacing + fcolor.SWhite + "          LOAD FILTER\t\t\t" + fcolor.SGreen + " - Load configuration from file\n"
        MSG20 =spacing + fcolor.SWhite + "          SAVE FILTER\t\t\t" + fcolor.SGreen + " - Save current configuration to file\n"
        MSG21 =spacing + fcolor.SWhite + "          CLEAR FILTER\t\t\t" + fcolor.SGreen + " - Clear all filters list\n"
        MSG0 =spacing + fcolor.SGreen + "Type [Filter ?] for usage of Filter and other filter related functions."
        if len(usrcmd)==1 or usrcmd[1]=="?":
            RECON_CMD=1
            print spacing + fcolor.BBlue  + "[FILTER] Function"
            print spacing + fcolor.SWhite + "[Filter] is use with combination of other command for setting/removing filter criteria with will affect on 'SHOW LIST2', 'SHOW DUMP|1|2'."
            print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 + MSG6 + MSG7 + MSG8 + MSG9 + MSG10 + MSG11 + MSG12 + MSG13 + MSG14 + MSG15 + MSG16 + MSG17 + MSG18 + MSG19+ MSG20+ MSG21
            if len(__builtin__.ANALYSIS_SEARCH)==0 and len(__builtin__.ANALYSIS_IGNORE)==0  and len(__builtin__.ANALYSIS_MAC)==0:
                print fcolor.BRed + spacing + "No filtering criteria found."
            else:
                print fcolor.BCyan + spacing + "Current Filtering Criteria"
                DisplayAnalysisFilters()
        if len(usrcmd)>=2:
            if usrcmd[1]=="MAC":
               RECON_CMD=1
               MACHELP=""
               if usrcmd[1]=="MAC" and len(usrcmd)==2:
                   MACHELP=1
               if len(usrcmd)>2 and usrcmd[2]=="?":
                   MACHELP=1
               if MACHELP==1:
                   print spacing + fcolor.BBlue  + "[FILTER MAC] Function"
                   print spacing + fcolor.SWhite + "[FILTER MAC] with the combination of other command allow user to add/remove/clear MAC address of the [MAC] filtering list. With the MAC specified in the MAC list, analysed result will only display those MAC address found on the list. Without any MAC address on the list, application will list all result."
                   print MSG1 + MSG2 + MSG3 + MSG4 + MSG5 + MSG6
                   print ""
                   if len(__builtin__.ANALYSIS_MAC)==0:
                       print fcolor.BRed + spacing + "No MAC Filter Found."
                   else:
                       print fcolor.BCyan + spacing + "Current MAC Filtering Criteria"
                       DisplayAnalysisMACFilter("")
               else:
                   ACCEPTEDMAC=""
                   REJECTEDMAC=""
                   if usrcmd[2]=="-":
                       if len(usrcmd)==3:
                           __builtin__.ANALYSIS_MAC=[]
                           print spacing + fcolor.BBlue + "MAC Filtering Cleared."
                           print MSG0
                       else:
                           yc=3
                           while yc<len(usrcmd):
                               xc=0
                               REMOV=""
                               while xc<len(__builtin__.ANALYSIS_MAC):
                                   if __builtin__.ANALYSIS_MAC[xc]==usrcmd[yc]:
                                       __builtin__.ANALYSIS_MAC.remove (usrcmd[yc])
                                       ACCEPTEDMAC=ACCEPTEDMAC + (usrcmd[yc]) + " / "
                                       REMOV=1
                                   xc +=1
                               if REMOV=="":
                                   REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                               yc +=1
                           if ACCEPTEDMAC!="":
                               print spacing + fcolor.BBlue + "MAC Address Removed: " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                           if REJECTEDMAC!="":
                               print spacing + fcolor.SRed + "MAC Not Removed    : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                           DisplayAnalysisMACFilter("")
                           print "\n" + MSG0
                   else:
                       yc=2
                       while yc<len(usrcmd):
                           if len(usrcmd[yc])<18 and IsHex(usrcmd[yc])==True:
                               __builtin__.ANALYSIS_MAC.append (usrcmd[yc])
                               ACCEPTEDMAC=ACCEPTEDMAC + (usrcmd[yc]) + " / "
                           else:
                               REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                           yc += 1
                       if ACCEPTEDMAC!="":
                           print spacing + fcolor.BBlue + "MAC Address Added  : " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                       if REJECTEDMAC!="":
                           print spacing + fcolor.SRed + "MAC Not Added      : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                       DisplayAnalysisMACFilter("")
                       print "\n" + MSG0
            if usrcmd[1]=="CONTAIN":
               RECON_CMD=1
               MACHELP=""
               if usrcmd[1]=="CONTAIN" and len(usrcmd)==2:
                   MACHELP=1
               if len(usrcmd)>2 and usrcmd[2]=="?":
                   MACHELP=1
               if MACHELP==1:
                   print spacing + fcolor.BBlue  + "[FILTER CONTAIN] Function"
                   print spacing + fcolor.SWhite + "[FILTER CONTAIN] with the combination of other command allow user to add/remove/clear string as filtering criteria. With the string specified in the CONTAIN list, analysed result will only display those string found on the list. Without any string on the list, application will list all result."
                   print MSG1 + MSG7 + MSG8 + MSG9 + MSG10
                   print ""
                   if len(__builtin__.ANALYSIS_SEARCH)==0:
                       print fcolor.BRed + spacing + "No String Filter Found."
                   else:
                       print fcolor.BCyan + spacing + "Current String Filtering Criteria"
                       DisplayAnalysisSearchFilter("")
               else:
                   ACCEPTEDMAC=""
                   REJECTEDMAC=""
                   if usrcmd[2]=="-":
                       if len(usrcmd)==3:
                           __builtin__.ANALYSIS_SEARCH=[]
                           print spacing + fcolor.BBlue + "String Filtering Cleared."
                           print MSG0
                       else:
                           yc=3
                           while yc<len(usrcmd):
                               xc=0
                               REMOV=""
                               while xc<len(__builtin__.ANALYSIS_SEARCH):
                                   if __builtin__.ANALYSIS_SEARCH[xc]==usrcmd[yc]:
                                       __builtin__.ANALYSIS_SEARCH.remove (usrcmd[yc])
                                       ACCEPTEDMAC=ACCEPTEDMAC + (usrcmd[yc]) + " / "
                                       REMOV=1
                                   xc +=1
                               if REMOV=="":
                                   REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                               yc +=1
                           if ACCEPTEDMAC!="":
                               print spacing + fcolor.BBlue + "String Removed     : " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                           if REJECTEDMAC!="":
                               print spacing + fcolor.SRed + "String Not Removed : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                           DisplayAnalysisSearchFilter("")
                           print "\n" + MSG0
                   else:
                       yc=2
                       while yc<len(usrcmd):
                           if str(__builtin__.ANALYSIS_SEARCH).find(usrcmd[yc])==-1:
                               __builtin__.ANALYSIS_SEARCH.append (usrcmd[yc])
                               ACCEPTEDMAC=ACCEPTEDMAC + (usrcmd[yc]) + " / "
                           else:
                               REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                           yc += 1
                       if ACCEPTEDMAC!="":
                           print spacing + fcolor.BBlue + "String Added       : " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                       if REJECTEDMAC!="":
                           print spacing + fcolor.SRed + "String Not Added   : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                       DisplayAnalysisSearchFilter("")
                       print "\n" + MSG0
            if usrcmd[1]=="IGNORE":
               RECON_CMD=1
               MACHELP=""
               if usrcmd[1]=="IGNORE" and len(usrcmd)==2:
                   MACHELP=1
               if len(usrcmd)>2 and usrcmd[2]=="?":
                   MACHELP=1
               if MACHELP==1:
                   print spacing + fcolor.BBlue  + "[FILTER IGNORE] Function"
                   print spacing + fcolor.SWhite + "[FILTER IGNORE] with the combination of other command allow user to add/remove/clear frame type to be ignored. With the criteria specified in the IGNORE list, analysed result will not display any record containing the string on the IGNORE list. Without any string on the list, application will list all result."
                   print MSG1 + MSG11 + MSG12 + MSG13 + MSG14+ MSG15 + MSG16
                   print ""
                   if len(__builtin__.ANALYSIS_IGNORE)==0:
                       print fcolor.BRed + spacing + "No Ignore String Filter Found."
                   else:
                       print fcolor.BCyan + spacing + "Current Ignore Filtering Criteria"
                       DisplayAnalysisIgnoreFilter("")
               else:
                   ACCEPTEDMAC=""
                   REJECTEDMAC=""
                   if usrcmd[2]=="-":
                       if len(usrcmd)==3:
                           __builtin__.ANALYSIS_IGNORE=[]
                           print spacing + fcolor.BBlue + "Ignore Filtering Cleared."
                           print MSG0
                       else:
                           yc=3
                           while yc<len(usrcmd):
                               xc=0
                               REMOV=""
                               while xc<len(__builtin__.ANALYSIS_IGNORE):
                                   if __builtin__.ANALYSIS_IGNORE[xc]==usrcmd[yc]:
                                       __builtin__.ANALYSIS_IGNORE.remove (usrcmd[yc])
                                       ACCEPTEDMAC=ACCEPTEDMAC + (usrcmd[yc]) + " / "
                                       REMOV=1
                                   xc +=1
                               if REMOV=="":
                                   REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                               yc +=1
                           if ACCEPTEDMAC!="":
                               print spacing + fcolor.BBlue + "Ignore Removed     : " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                           if REJECTEDMAC!="":
                               print spacing + fcolor.SRed + "Ignore Not Removed : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                           DisplayAnalysisIgnoreFilter("")
                           print "\n" + MSG0
                   else:
                       if usrcmd[2]!="*" and usrcmd[2]!="-*":
                           yc=2
                           while yc<len(usrcmd):
                               xc=0
                               REMOV=""
                               while xc<len(__builtin__.ANALYSIS_IGNORE):
                                   if __builtin__.ANALYSIS_IGNORE[xc]==usrcmd[yc]:
                                       REMOV=1
                                       REJECTEDMAC=REJECTEDMAC+ (usrcmd[yc]) + " / "
                                   xc +=1
                               if REMOV=="":
                                   __builtin__.ANALYSIS_IGNORE.append (usrcmd[yc])
                                   ACCEPTEDMAC=ACCEPTEDMAC+ (usrcmd[yc]) + " / "
                               yc +=1
                           if ACCEPTEDMAC!="":
                               print spacing + fcolor.BBlue + "Ignore String Added: " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                           if REJECTEDMAC!="":
                               print spacing + fcolor.SRed + "Ignore Not Added   : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                           DisplayAnalysisIgnoreFilter("")
                           print "\n" + MSG0
                       else:
                           if usrcmd[2]=="*":
                               yc=0
                               while yc<len(__builtin__.ANALYSIS_TYPE):
                                   ATYPE=__builtin__.ANALYSIS_TYPE[yc]
                                   xc=0
                                   REMOV=""
                                   while xc<len(__builtin__.ANALYSIS_IGNORE):
                                       if __builtin__.ANALYSIS_IGNORE[xc]==ATYPE:
                                           REMOV=1
                                           REJECTEDMAC=REJECTEDMAC+ (ATYPE) + " / "
                                       xc += 1
                                   if REMOV=="":
                                       __builtin__.ANALYSIS_IGNORE.append (ATYPE)
                                       ACCEPTEDMAC=ACCEPTEDMAC + (ATYPE) + " / "
                                   yc +=1
                               if ACCEPTEDMAC!="":
                                   print spacing + fcolor.BBlue + "Ignore String Added: " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                               if REJECTEDMAC!="":
                                   print spacing + fcolor.SRed + "Ignore Not Added   : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                               DisplayAnalysisIgnoreFilter("")
                               print "\n" + MSG0
                           if usrcmd[2]=="-*":
                               yc=0
                               while yc<len(__builtin__.ANALYSIS_TYPE):
                                   ATYPE=__builtin__.ANALYSIS_TYPE[yc]
                                   xc=0
                                   REMOV=""
                                   while xc<len(__builtin__.ANALYSIS_IGNORE):
                                       if __builtin__.ANALYSIS_IGNORE[xc]==ATYPE:
                                           REMOV=1
                                           __builtin__.ANALYSIS_IGNORE.remove (ATYPE)
                                           ACCEPTEDMAC=ACCEPTEDMAC + (ATYPE) + " / "
                                       xc += 1
                                   if REMOV=="":
                                       REJECTEDMAC=REJECTEDMAC + (ATYPE) + " / "
                                   yc +=1
                               if ACCEPTEDMAC!="":
                                   print spacing + fcolor.BBlue + "Ignore Removed     : " + fcolor.BWhite + ACCEPTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BWhite)
                               if REJECTEDMAC!="":
                                   print spacing + fcolor.SRed + "Ignore Not Removed : " + fcolor.BRed + REJECTEDMAC[:-3].replace("/",fcolor.SWhite + "/" + fcolor.BRed)
                               DisplayAnalysisIgnoreFilter("")
                               print "\n" + MSG0
    if usr_resp=="CLEAR FILTER":
        RECON_CMD=1;
        __builtin__.ANALYSIS_SEARCH=[]
        __builtin__.ANALYSIS_IGNORE=[]
        __builtin__.ANALYSIS_MAC=[]
        print fcolor.BBlue + spacing + "All Filters Cleared."
    if usrcmd[0]=="MERGE":
        RECON_CMD=1
        usrcmd=usr_resp.split(" ")
        usrcmd_n=usr_resp_n.split(" ")
        if len(usrcmd)<5 or str(usr_resp).find("-R")==-1 or str(usr_resp).find("-W")==-1:
            print spacing + fcolor.BBlue + "[MERGE] Function"
            print spacing + fcolor.SWhite + "Merge allow user to merge two or more pcap files into one pcap file."
            print spacing + fcolor.BWhite + "Example :"
            print spacing + fcolor.SWhite + "          MERGE -R <read files> -W <output file>\t\t  " + fcolor.SGreen + " - Merge <read files> to <output file>"
            print spacing + fcolor.SWhite + "          MERGE -R ATTACK_2014*.CAP -W ATTACK_2014_JOIN.CAP\t  " + fcolor.SGreen + " - Merge all files beginning with ATTACK_20140415_00 and save to ATTACK_20140415.CAP"
            print spacing + fcolor.SWhite + "          MERGE -R FILE1.CAP FILE2.CAP -W RESULT.CAP\t\t  " + fcolor.SGreen + " - Merge FILE1 & FILE2 and save as RESULT.CAP\n"
            print spacing + fcolor.BWhite + "Notes :"
            print spacing + fcolor.BRed   + "          Do not specified the directory to use.. PCap files will only be use in the following directory"
            print spacing + fcolor.SWhite + "          " + fcolor.BYellow + savedir + fcolor.SWhite + " , " + fcolor.BYellow + mondir + fcolor.SWhite + " , " + fcolor.BYellow + attackdir + "\n"
        else:
            STATUS=""
            READFILES=[]
            READFILES_DISPLAY=""
            FILETOREAD=""
            OUTPUTFILE=""
            DIRUSE=""
            ERR=""
            __builtin__.ExtList= ['pcap','cap']
            if IsProgramExists("mergecap")==False:
               print spacing + fcolor.BRed + "Application [Mergecap] does not exist !!!.. Merging aborted.."
               ERR="1"
               x=len(usrcmd)
            else:
                x=1
            while x<len(usrcmd):
                if usrcmd[x]=="-R":
                    STATUS="READ"
                if usrcmd[x]=="-W":
                    STATUS="WRITE"
                if STATUS=="READ":
                    while x<len(usrcmd) and usrcmd[x]!="-W" and ERR=="":
                        x=x+1
                        FName=usrcmd_n[x]
                        FileExist=0
                        if usrcmd[x]=="-W":
                            STATUS="WRITE"
                        if str(FName).find("*")==-1 and STATUS=="READ":
                            rfile=SearchFileOnDir(FName)
                            if rfile!="":
                                if str(__builtin__.FileExt).upper()==".CAP" or str(__builtin__.FileExt).upper()==".PCAP":
                                    SplitFileDetail(rfile)
                                    DIRUSE=__builtin__.FilePath
                                    __builtin__.lookupdir=DIRUSE
                                    READFILES.append (FName)
                                    READFILES_DISPLAY=READFILES_DISPLAY + str(rfile) + ","
                                    FILETOREAD=FILETOREAD + str(DIRUSE) + str(FName) + " "
                                else:
                                    print spacing + fcolor.BRed + "File specified must be a CAP or PCAP file !!!"
                                    ERR="1"
                            else:
                                ERR="1"
                                DisplayFileNotFound(FName)
                        else:
                             if usrcmd[x]!="-W" and STATUS=="READ":
                                 if usrcmd[x][-4:]==".CAP" or usrcmd[x][-5:]==".PCAP":
                                     if usrcmd[x][-4:]==".CAP":
                                         FFilter=usrcmd_n[x][:-4]
                                     if usrcmd[x][-5:]==".PCAP":
                                         FFilter=usrcmd_n[x][:-5]
                                     FFilter=str(FFilter).replace("*","") + "*"
                                     SearchFiles(attackdir,__builtin__.ExtList,FFilter)
                                     DIRUSE=attackdir
                                     if len(__builtin__.FoundFiles)<0:
                                         DIRUSE=mondir
                                         SearchFiles(mondir,__builtin__.ExtList,FFilter)
                                         if len(__builtin__.FoundFiles)<0:
                                             DIRUSE=savedir
                                             SearchFiles(savedir,__builtin__.ExtList,FFilter)
                                     if len(__builtin__.FoundFiles)>0:
                                         __builtin__.lookupdir=DIRUSE
                                         FILETOREAD=FILETOREAD + str(DIRUSE) + usrcmd_n[x]
                                         SearchFiles(DIRUSE,__builtin__.ExtList,FFilter)
                                         y=0
                                         while y<len(__builtin__.FoundFiles):
                                             SplitFileDetail(__builtin__.FoundFiles[y])
                                             READFILES.append (__builtin__.FoundFiles[y])
                                             y=y+1
                                         READFILES_DISPLAY=ArrangeFileDisplay(__builtin__.FoundFiles)
                                     else:
                                        DisplayFileNotFound(usrcmd_n[x])
                                        ERR=1
                                 else:
                                    print spacing + fcolor.BRed + "File specified must be a CAP or PCAP file !!!"
                                    ERR="1"
                if STATUS=="WRITE":
                    while x<len(usrcmd) and ERR=="" and OUTPUTFILE=="":
                        x=x+1
                        FName=usrcmd_n[x]
                        OUTPUTFILE=str(FName)
                x += 1
            if OUTPUTFILE=="" and ERR=="":
                print spacing + fcolor.BRed + "You did not specified the output file. Type [MERGE] for detail."
                ERR=1
            if str(READFILES).find("'" + OUTPUTFILE + "'")!=-1:
                ERR=1
                print spacing + fcolor.BRed + "The specified output file [ " + fcolor.BYellow + str(OUTPUTFILE) + fcolor.BRed + " ] must not be one of the source file."
            if OUTPUTFILE!="" and ERR=="" and OUTPUTFILE.find("*")!=-1:
                ERR=1
                print spacing + fcolor.BRed + "The specified output file [ " + fcolor.BYellow + str(OUTPUTFILE) + fcolor.BRed + " ] must not contain wildcard."
            if OUTPUTFILE!="" and ERR=="":
                if IsFileDirExist(DIRUSE + OUTPUTFILE)=="F":
                    print spacing + fcolor.BRed + "The specified output file [ " + fcolor.BYellow + str(OUTPUTFILE) + fcolor.BRed + " ] already exist in [ " + fcolor.BYellow + DIRUSE + fcolor.BRed + " ]"
                    usr_resp=AskQuestion(fcolor.SGreen + "Replace the existing file ?","y/N","U","N","")
                    print ""
                    if usr_resp!="Y":
                        print spacing + fcolor.BRed + "Merging aborted !!"
                        ERR=1
            if len(READFILES)>1 and ERR=="":
                READFILES_DISPLAY=ArrangeFileDisplay(READFILES)
                print spacing + fcolor.BBlue + "The following " + str(len(READFILES)) + " files on [ " + fcolor.BYellow + str(DIRUSE) + fcolor.BBlue + " ] will be merged and save to [ " + fcolor.BYellow + str(OUTPUTFILE) + fcolor.BBlue + " ]."
                print READFILES_DISPLAY
                print spacing + fcolor.BBlue + "\nDirectory Use  [ " + fcolor.BYellow + str(DIRUSE) + fcolor.BBlue + " ]"
                print spacing + fcolor.BBlue + "Files to Merge [ " + fcolor.BYellow + str(len(READFILES)) + fcolor.BBlue + " ]"
                print spacing + fcolor.BBlue + "Output File    [ " + fcolor.BYellow + str(OUTPUTFILE) + fcolor.BBlue + " ]\n"
                usr_resp=AskQuestion(fcolor.SGreen + "Proceed with merge ?","Y/n","U","Y","")
                print ""
                if usr_resp!="Y":
                    print spacing + fcolor.BRed + "Merging aborted !!"
                else:
                    printl (spacing + fcolor.SGreen + "Merging... Please wait...","0","")
                    Rund="mergecap -a " + str(FILETOREAD) + " -w " +  str(DIRUSE) + str(OUTPUTFILE) # + " > /dev/null 2>&1 &"
##                    print "Rund : " + str(Rund)
                    ps=subprocess.Popen(Rund , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
                    ps.wait()
                    readout=str(ps.stdout.read())
                    ps.stdout.close()
                    if readout=="":
                        printl (spacing + fcolor.SGreen + "Merging Completed..","0","")
                    else:
                        printl (spacing + fcolor.BRed + "Merging Failed..","0","")
                    print ""
                    if IsFileDirExist(DIRUSE + OUTPUTFILE)=="F":
                        GetFileDetail(DIRUSE + OUTPUTFILE)
                        print spacing + fcolor.BWhite + "Output File   : " + fcolor.BYellow +  str(DIRUSE + OUTPUTFILE)
                        print spacing + fcolor.BWhite + "Size / Date   : " + fcolor.BYellow +  str(__builtin__.FileSize) + fcolor.BWhite + "  /  " + fcolor.BYellow +  str(__builtin__.FileCreated) + "\n"
                        
                        if IsProgramExists("wireshark")==True:
                            usr_resp=AskQuestion(fcolor.SGreen + "Do want want to view the file in Wireshark ?","Y/n","U","Y","")
                            if usr_resp=="Y":
                               result=os.system("wireshark " + str(DIRUSE + OUTPUTFILE) + " > /dev/null 2>&1 &")
                        usr_resp=AskQuestion(fcolor.SGreen + "Do you want delete the " + fcolor.BRed + str(len(READFILES)) + fcolor.SGreen + " files use to merge ? ","y/N","U","N","")
                        if usr_resp=="Y":
                            x=0
                            while x<len(READFILES):
                                printl (spacing + fcolor.SRed + "Deleting " + fcolor.BRed + str(DIRUSE) + str(READFILES[x]) + fcolor.SRed + "...","0","")
                                DelFile (DIRUSE + READFILES[x],"")
                                x += 1
                            printl (tabspacefull + fcolor.BRed + "Files deleted !!","0","")
                            print ""
                    else:
                        print spacing + fcolor.BRed + "Output file [ " + fcolor.BYellow + DIRUSE + OUTPUTFILE + fcolor.BRed  + " not found !!"
            
    if usrcmd[0]=="LOAD":
        RECON_CMD=1
        usrcmd=usr_resp.split(" ")
        if len(usrcmd)<2:
            print spacing + fcolor.BBlue + "[LOAD] Function"
            print spacing + fcolor.SWhite + "Allow user to load existing [pcap] file, existing packets that currently captured or load the filter configuration file."
            print spacing + fcolor.BWhite + "Example :"
            print spacing + fcolor.SWhite + "          LOAD FILTER\t\t\t  " + fcolor.SGreen + " - Load the saved filter configuration file"
            print spacing + fcolor.SWhite + "          LOAD NEW\t\t\t  " + fcolor.SGreen + " - Load existing captured packets."
            print spacing + fcolor.SWhite + "          LOAD /SYWorks/Saved/MyPacket.cap" + fcolor.SGreen + " - Load the specified pcap file."
            print spacing + fcolor.BWhite + "Related :"
            print spacing + fcolor.SWhite + "          RELOAD\t\t\t  " + fcolor.SGreen + " - Reload the previous captured PCAP file."
        else:
            if usrcmd[1]=="NEW":
                 print fcolor.BBlue + spacing  + "Load Current Captured PCAP file"
                 PrevData=__builtin__.LOAD_PKTCAPTURE
                 __builtin__.LOAD_PKTCAPTURE="Yes"
                 AnalysePacketCapture()
                 __builtin__.LOAD_PKTCAPTURE=PrevData
                 printl (spacing + fcolor.BGreen + "Current captured packets file successfully loaded and analysed.\n","0","")
            elif usrcmd[1]=="FILTER":
                print spacing + fcolor.BBlue + "Filter Configuration"
                LoadPktConfig()
                CHANGES=""
                if len(__builtin__.ANALYSIS_SEARCH)!=0 or len(__builtin__.ANALYSIS_IGNORE)!=0  or len(__builtin__.ANALYSIS_MAC)!=0:
                    CHANGES="with the following options"
                print spacing + fcolor.SGreen + "Analysis filters loaded " + CHANGES
                DisplayAnalysisFilters()
            elif usrcmd[1]!="":
                FName=str(usr_resp_n)[5:]
                FileExist=0
                rfile=SearchFileOnDir(FName)
                if rfile!="":
                    FName=rfile
                    FileExist=1
                if FileExist==1:
                    print fcolor.BBlue + spacing  + "Load PCAP File - " + fcolor.SYellow + str(FName)
                    __builtin__.PacketDumpFileBak2=__builtin__.PacketDumpFileBak
                    __builtin__.PacketDumpFileBak=FName
                    DeleteExistingPacketFiles()
                    ConvertPackets("1")
                    AnalyseTCPnTShark()
                    printl (spacing + fcolor.BGreen + str(__builtin__.FileName) + " successfully loaded and analysed.","0","")
                    print ""
                    print spacing + fcolor.SWhite + "You may now use SHOW LIST,SHOW DUMP to view the result."
                    print spacing + fcolor.SWhite + "To reload the previously captured PCAP, use [RELOAD] command."
                    __builtin__.PacketDumpFileBak=__builtin__.PacketDumpFileBak2
                else:
                    print fcolor.SRed + spacing + "Specified file " + fcolor.BRed + str(FName) + fcolor.SRed + " not found."
                    Rund=""
    if usrcmd[0]=="RELOAD":
        RECON_CMD=1;
        print fcolor.BBlue + spacing  + "Reload Previous Captured PCAP file - " + fcolor.BYellow + str(__builtin__.PacketDumpFileBak)
        DeleteExistingPacketFiles()
        ConvertPackets("1")
        AnalyseTCPnTShark()
        printl (spacing + fcolor.BGreen +  "Previous captured packets successfully loaded and analysed.","0","")
        print ""
        print spacing + fcolor.SWhite + "You may now use SHOW LIST,SHOW DUMP to view the result."
          
    if usr_resp=="MYMAC":
        RECON_CMD=1
        print tabspacefull + fcolor.BBlue + "Your Interface MAC Addresses"
        DisplayMyMAC()
    if usr_resp=="INFO" or usr_resp=="INFORMATION":
        RECON_CMD=1
        InfoColor=fcolor.SGreen
        lblColor=fcolor.SWhite
        print spacing + fcolor.BBlue + "Data Packets Information "
        if IsFileDirExist(__builtin__.CurrentPacket)=="F":
            GetFileDetail(__builtin__.CurrentPacket)
            print spacing + lblColor + "Currently Loaded   : " + fcolor.SCyan +  str(__builtin__.CurrentPacket).ljust(50) + lblColor + " Size : " + fcolor.SCyan +  str(__builtin__.FileSize).ljust(15) + lblColor + " Created : " + fcolor.SCyan +  str(__builtin__.FileCreated).ljust(23) + lblColor + "" 
        else:
            print spacing + lblColor + "Currently Loaded   : " + fcolor.BRed +  "Does not exist"
        if IsFileDirExist(__builtin__.PacketDumpFileBak)=="F":
            GetFileDetail(__builtin__.PacketDumpFileBak)
            print spacing +lblColor + "Last Captured Data : " + fcolor.SYellow + str(__builtin__.PacketDumpFileBak).ljust(50) + lblColor + " Size : " + fcolor.SYellow +  str(__builtin__.FileSize).ljust(15) + lblColor + " Created : " + fcolor.SYellow +  str(__builtin__.FileCreated).ljust(23) + lblColor + " "
        else:
            print spacing +lblColor + "Last Captured Data : " + fcolor.BRed + "Does not exist"
        if IsFileDirExist(__builtin__.PacketDumpFile)=="F":
            GetFileDetail(__builtin__.PacketDumpFile)
            print spacing + lblColor + "Active Capturing   : " + fcolor.SPink +  str(__builtin__.PacketDumpFile).ljust(50) + lblColor + " Size : " + fcolor.SPink +  str(__builtin__.FileSize).ljust(15) + lblColor + " Created : " + fcolor.SPink +  str(__builtin__.FileCreated).ljust(23) + lblColor + "" 
        else:
            print spacing + lblColor + "Active Capturing   : " + fcolor.BRed +  "Does not exist"
        print ""
        print spacing + fcolor.BBlue + "Interfaces Information "
        print spacing + lblColor + "Selected Interface : " +  fcolor.SCyan + str(__builtin__.SELECTED_IFACE_MAC).ljust(20) + fcolor.BWhite + " [ " + fcolor.BRed + str(__builtin__.SELECTED_IFACE) + fcolor.BWhite + " ]"
        print spacing + lblColor + "Managed Interface  : " +  fcolor.SYellow + str(__builtin__.SELECTED_MANIFACE_MAC).ljust(20) + fcolor.BWhite + " [ " + fcolor.BRed + str(__builtin__.SELECTED_MANIFACE) + fcolor.BWhite + " ]"
        print spacing + lblColor + "Monitor Interface  : " +  fcolor.SPink + str(__builtin__.SELECTED_MON_MAC).ljust(20) + fcolor.BWhite + " [ " + fcolor.BRed + str(__builtin__.SELECTED_MON) + fcolor.BWhite + " ]"
        print ""
        print spacing + fcolor.BBlue + "Filtering Information "
        FILTERSTR="";yc=0
        while yc<len(__builtin__.ANALYSIS_IGNORE):
            FILTERSTR=FILTERSTR + InfoColor + __builtin__.ANALYSIS_IGNORE[yc] + StdColor + " / "
            yc += 1
        if FILTERSTR!="":
            FILTERSTR=str(FILTERSTR)[:-3]
        print spacing + lblColor + "Hidden Packet Type : " + InfoColor + str(FILTERSTR) 
        FILTERSTR="";yc=0
        while yc<len(__builtin__.ANALYSIS_SEARCH):
            FILTERSTR=FILTERSTR + InfoColor + __builtin__.ANALYSIS_SEARCH[yc] + StdColor + " / "
            yc += 1
        if FILTERSTR!="":
            FILTERSTR=str(FILTERSTR)[:-3]
        print spacing + lblColor + "Search Filter      : " + InfoColor + str(FILTERSTR) 
        FILTERSTR="";yc=0
        while yc<len(__builtin__.ANALYSIS_MAC):
            FILTERSTR=FILTERSTR + InfoColor + __builtin__.ANALYSIS_MAC[yc] + StdColor + " / "
            yc += 1
        if FILTERSTR!="":
            FILTERSTR=str(FILTERSTR)[:-3]
        print spacing + lblColor + "Search MAC         : " + InfoColor + str(FILTERSTR) 
        
    if usrcmd[0]=="CLEAR":
        if len(usrcmd)==1:
            RECON_CMD=1
            os.system('clear')
        else:
            if usrcmd[1]=="HISTORY":
                RECON_CMD=1
                readline.clear_history();__builtin__.LASTCMD="";__builtin__.LASTCMDLOG=""
                print fcolor.BBlue + "Commands history cleared.."                
    if usr_resp=="SAVE" or usr_resp=="SAVE ?":
        RECON_CMD=1
        print spacing + fcolor.BBlue + "[SAVE] Function"
        print spacing + fcolor.SWhite + "Save function allow user to save application configuration, filter criteria and captured captured pcap file and analyzed result."
        print spacing + fcolor.BWhite + "Example :"
        print spacing + fcolor.SWhite + "          SAVE CONFIG\t\t\t" + fcolor.SGreen + " - Save application configuration"
        print spacing + fcolor.SWhite + "          SAVE FILTER\t\t\t" + fcolor.SGreen + " - Save the filtering criteras"
        print spacing + fcolor.SWhite + "          SAVE DATA\t\t\t" + fcolor.SGreen + " - Save the current loaded pcap file and analyzed result."
    if usr_resp=="SAVE CONFIG":
        RECON_CMD=1;
        print fcolor.BBlue + tabspacefull + "Saving Config.."
        SaveConfig("1")
    if usr_resp[:11]=="SAVE FILTER":
        RECON_CMD=1;
        SavePktConfig()
        CHANGES=""
        if len(__builtin__.ANALYSIS_SEARCH)!=0 or len(__builtin__.ANALYSIS_IGNORE)!=0  or len(__builtin__.ANALYSIS_MAC)!=0:
            CHANGES="with the following changes"
        print spacing + fcolor.BGreen + "Analysis filters saved " + CHANGES
        DisplayAnalysisFilters()
    if usr_resp=="SAVE DATA":
        RECON_CMD=1
        print fcolor.BBlue + "Packet/Result Saving"
        print spacing + fcolor.SWhite + "This option allow you to make copy the captured 'cap' file and the converted/filtered result files."
        print spacing + fcolor.SWhite + "All files will be saved to " + fcolor.BWhite + str(savedir)
        print ""
        __builtin__.SHOWRESULT=3
        FName=Now().replace(":","").replace(" ","_")
        FName=FName
        print fcolor.BGreen + tabspacefull + "Files will to : " + fcolor.BYellow + savedir
        usr_resp=AskQuestion("Enter the prefix filename to save without any extension","Default = " + str(FName) ,"",str(FName),"1")
        FName=usr_resp.replace(":","").replace(" ","_").replace("\\","_").replace("/","_")
        print ""
        SrcFName=os.path.basename(__builtin__.CurrentPacket)
        SrcDir=os.path.dirname(__builtin__.CurrentPacket) + "/"
        NewCapFile=FName + ".cap"
        NewFilteredCapFile=FName + "_Filtered.cap"
        shutil.copy2(__builtin__.CurrentPacket, savedir + NewCapFile)
        print tabspacefull + fcolor.SGreen + "Pcap file saved to " + fcolor.SRed + savedir + NewCapFile
        SrcFName=str(__builtin__.TCPDumpFileBak).replace(tmpdir,"")
        CopyFile(tmpdir, savedir, SrcFName,"")
        NewDumpFile1=FName + "_TCPDump_Result.txt"
        os.rename(savedir + SrcFName,savedir + NewDumpFile1)
        print tabspacefull + fcolor.SGreen + "Converted TCPDump result saved to " + fcolor.SRed + savedir + NewDumpFile1
        SrcFName=str(__builtin__.TSharkFileBak).replace(tmpdir,"")
        CopyFile(tmpdir, savedir, SrcFName,"")
        NewDumpFile2=FName + "_TShark_Result.txt"
        os.rename(savedir + SrcFName,savedir + NewDumpFile2)
        print tabspacefull + fcolor.SGreen + "Converted TShark result saved to " + fcolor.SRed + savedir + NewDumpFile2
        if len(__builtin__.ANALYSIS_SEARCH)!=0 or len(__builtin__.ANALYSIS_IGNORE)!=0  or len(__builtin__.ANALYSIS_MAC)!=0:
            __builtin__.SavedTCPDumpFile=savedir + FName + "_TCPDump_Filtered.txt"
            printl (tabspacefull + fcolor.SGreen + "Saving filtered TCPDump file...","0","")
            open(__builtin__.SavedTCPDumpFile,"w").write("")
            __builtin__.SHOWRESULT=3
            AnalyseTCPDump("")
            printl (tabspacefull + fcolor.SGreen + "Filtered TCPDump result file saved to " + fcolor.SRed +  str(__builtin__.SavedTCPDumpFile),"0","")
            print ""
            __builtin__.SavedTSharkFile=savedir + FName + "_TShark_Filtered.txt"
            printl (tabspacefull + fcolor.SGreen + "Saving filtered TShark filte...","0","")
            open(__builtin__.SavedTSharkFile,"w").write("")
            AnalyseTShark("")
            printl (tabspacefull + fcolor.SGreen + "Filtered TShark result file saved to " + fcolor.SRed +  str(__builtin__.SavedTSharkFile),"0","")
            print ""
            if len(__builtin__.ANALYSIS_MAC)!=0:
                xm=0
                fmac="";dfmac=""
                while xm<len(__builtin__.ANALYSIS_MAC):
                    fmac=fmac + "wlan.addr==" + str(__builtin__.ANALYSIS_MAC[xm]) + " or "
                    dfmac=dfmac + str(__builtin__.ANALYSIS_MAC[xm]) + ","
                    xm += 1
                fmac=fmac[:-4]
                dfmac=dfmac[:-1]
                printl (tabspacefull + fcolor.SGreen + "Saving MAC filtered pcap file...","0","")
                ps=subprocess.Popen("tshark -r " + str(__builtin__.CurrentPacket) + " -R '" +  str(fmac) + "' -w " + savedir + NewFilteredCapFile + "" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
                printl (tabspacefull + fcolor.SGreen + "Filtered PCap file saved " + fcolor.SRed +  str(savedir + NewFilteredCapFile) + fcolor.SGreen + " - MAC filtered : " + str(dfmac) ,"0","")
        else:
            print tabspacefull + fcolor.SRed + "No filter found.. Saving of filtered result files bypassed.."
        print ""
        __builtin__.SHOWRESULT=3
        usr_resp=AskQuestion(fcolor.SGreen + "Do you want to explore the saved directory - " + fcolor.BGreen + savedir,"y/N","U","N","1")
        if usr_resp=="Y":
            Explore(savedir,"")
    if usrcmd[0]=="RM":
        FILETODELETE=[]
        if len(usrcmd)==1 or usrcmd[1]=="?":
            RECON_CMD=1
            print spacing + fcolor.BBlue + "[RM] Function"
            print spacing + fcolor.SWhite + "RM is a function that is use to delete the specified file after the command RM."
            print spacing + fcolor.BWhite + "Example :"
            print spacing + fcolor.SWhite + "          RM ATTACK_2014*.cap\t\t  " + fcolor.SGreen + " - Delete the specified files found in the first found directory." 
            print spacing + fcolor.SWhite + "          RM MONITOR_20140415.cap\t  " + fcolor.SGreen + " - Delete the specified file found in the first found directory." 
            print spacing + fcolor.SWhite + "          LIST PCAP *2014*\t\t  " + fcolor.SGreen + " - Delete file containing the word '2014' in PCAP directory " + str(savedir)
            print spacing + fcolor.SWhite + "          LIST DB Cautious_BK.log\t\t  " + fcolor.SGreen + " - Delete 'Cautious_BK.log' in " + str(dbdir)
        else:
            if len(usrcmd)>1:
                x=1
                rDir=ReturnSpecifiedDir(usrcmd[1])
                if rDir!="":
                    x=2
                else:
                    SplitFileDetail(usrcmd_n[x])
                    if __builtin__.FilePath!="" and __builtin__.FilePath!="/":
                        __builtin__.lookupdir=__builtin__.FilePath
                    else:
                        FName=SearchFileOnDir(usrcmd_n[x])
                        SplitFileDetail(FName)
                        if __builtin__.FilePath!="":
                            __builtin__.lookupdir=__builtin__.FilePath
                    if usrcmd_n[x].find("*")!=-1:
                        FFilter=usrcmd_n[x]
                        SplitFileDetail(usrcmd_n[x])
                        FFilter=__builtin__.FileNameOnly
                        if __builtin__.FileExt=="":
                            __builtin__.ExtList=['pcap','cap']
                        else:
                            __builtin__.ExtList=[str(__builtin__.FileExt).replace(".","")]
                        SearchFiles(attackdir,__builtin__.ExtList,FFilter)
                        __builtin__.lookupdir=attackdir
                        if len(__builtin__.FoundFiles)<=0:
                            __builtin__.lookupdir=mondir
                            SearchFiles(mondir,__builtin__.ExtList,FFilter)
                            if len(__builtin__.FoundFiles)<=0:
                                __builtin__.lookupdir=savedir
                                SearchFiles(savedir,__builtin__.ExtList,FFilter)
                                if len(__builtin__.FoundFiles)<=0:
                                    __builtin__.lookupdir=dbdir
                                    SearchFiles(dbdir,__builtin__.ExtList,FFilter)
                RECON_CMD=1
                while x<len(usrcmd_n):
                    if usrcmd[x].find("*")!=-1:
                        FFilter=usrcmd_n[x]
                        SplitFileDetail(usrcmd_n[x])
                        FFilter=__builtin__.FileNameOnly
                        SearchFiles(__builtin__.lookupdir,__builtin__.ExtList,FFilter)
                        if len(__builtin__.FoundFiles)>0:
                            y=0
                            while y<len(__builtin__.FoundFiles):
                                FILETODELETE=AddIfNotDuplicate(__builtin__.FoundFiles[y], FILETODELETE)
                                y += 1
                        else:
                            print fcolor.SRed + "Specific file [ " + fcolor.BRed + str(FFilter) + fcolor.SRed + " not found in directory."
                    else:
                        SplitFileDetail(usrcmd_n[x])
                        FName=__builtin__.FileName
                        if IsFileDirExist(__builtin__.lookupdir + FName)=="F":
                            FILETODELETE=AddIfNotDuplicate(usrcmd_n[x], FILETODELETE)       # FILETODELETE.append ()
                        else:
                            DisplayFileNotFound(usrcmd_n[x])
                    x += 1
                if len(FILETODELETE)!=0:
                    FILETODELETE_DISPLAY=ArrangeFileDisplay(FILETODELETE)
                    print spacing + fcolor.BBlue + "The following " + str(len(FILETODELETE)) + " files on [ " + fcolor.BYellow + str(__builtin__.lookupdir) + fcolor.BBlue + " ] will be deleted !!!"
                    print FILETODELETE_DISPLAY + "\n"
                    usr_resp=AskQuestion(fcolor.SGreen + "Do you want delete the " + fcolor.BRed + str(len(FILETODELETE)) + fcolor.SGreen + " files ? ","y/N","U","N","")
                    if usr_resp=="Y":
                        x=0
                        while x<len(FILETODELETE):
                            printl (spacing + fcolor.SRed + "Deleting " + fcolor.BRed + str(__builtin__.lookupdir) + str(FILETODELETE[x]) + fcolor.SRed + "...","0","")
                            DelFile (__builtin__.lookupdir + FILETODELETE[x],"")
                            x += 1
                        printl (tabspacefull + fcolor.BRed + "Files deleted !!","0","")
                        print ""
                    else:
                        print spacing + fcolor.BRed + "Delete Aborted !!"
                else:
                    print spacing + fcolor.BRed + "No file found !!"
    if usrcmd[0]=="LIST":
        if len(usrcmd)==1 or usrcmd[1]=="?":
            RECON_CMD=1
            print spacing + fcolor.BBlue + "[LIST] Function"
            print spacing + fcolor.SWhite + "LIST together with [PCAP], [TXT], [DB], [LOG], [ATK], [ATTACK], [MON] or [MONITOR] allow user to list out the files found on the speficied directories."
            print spacing + fcolor.SWhite + "User may also use wildcard in to filter their search."
            print spacing + fcolor.BWhite + "Example :"
            print spacing + fcolor.SWhite + "          LIST PCAP\t\t  " + fcolor.SGreen + " - List PCAP files in " + str(savedir)
            print spacing + fcolor.SWhite + "          LIST PCAP MY_FILE*\t  " + fcolor.SGreen + " - List PCAP files in " + str(savedir) + " which starting with 'MY_FILE'"
            print spacing + fcolor.SWhite + "          LIST PCAP *MY_FILE*\t  " + fcolor.SGreen + " - List PCAP files in " + str(savedir) + " which containing with 'MY_FILE'"
            print spacing + fcolor.SWhite + "          LIST TXT\t\t  " + fcolor.SGreen + " - List text files in " + str(savedir)
            print spacing + fcolor.SWhite + "          LIST LOG\t\t  " + fcolor.SGreen + " - List logging files in " + str(dbdir)
            print spacing + fcolor.SWhite + "          LIST DB\t\t  " + fcolor.SGreen + " - List Database files in " + str(dbdir)
            print spacing + fcolor.SWhite + "          LIST ATK / ATTACK\t  " + fcolor.SGreen + " - List Attacks PCAP files in " + str(attackdir)
            print spacing + fcolor.SWhite + "          LIST MON / MONITOR\t  " + fcolor.SGreen + " - List Monitoring PCAP files in " + str(mondir)
            print spacing + fcolor.BWhite + "Notes :"
            print spacing + fcolor.BRed   + "          Do not specified the directory and file extension in the wildcard search."
        else:
            rDir=ReturnSpecifiedDir(usrcmd[1])
            if rDir!="":
                RECON_CMD=1
                print fcolor.BBlue + "Lookup Directory : " + fcolor.BYellow + __builtin__.lookupdir
                FFilter=""
                if len(usrcmd)==3:
                    SplitFileDetail(usrcmd_n[2])
                    FFilter=__builtin__.FileNameOnly
                    if __builtin__.FileExt!="":
                        __builtin__.ExtList= [__builtin__.FileExt]                        
                SearchFiles(__builtin__.lookupdir,__builtin__.ExtList,FFilter)
                if len(__builtin__.FoundFiles)>0:
                    ListFiles=ArrangeFileDisplay(__builtin__.FoundFiles)
                    print fcolor.SGreen + str(ListFiles)
                    print fcolor.SWhite + str(len(__builtin__.FoundFiles)) + " file(s) listed."
                else:
                    print fcolor.SGreen + "No specific file found in directory."
    if RECON_CMD==0 and len(usr_resp)>0 and usr_resp!="." and usr_resp!=".." and usr_resp!="...":
        if IsProgramExists(usrcmd_n[0])==True or IsProgramExists(usrcmd_n[0])==False:
            print fcolor.SBlue + "Running External Command : " + fcolor.BYellow + str(usr_resp_n) + fcolor.SWhite
            if usrcmd[0]=="CD" and len(usrcmd)>1:
                os.chdir(usr_resp_n[3:])
                print fcolor.SBlue + "New Directory            : " + fcolor.BYellow + str(os.getcwd()) + fcolor.SWhite
            else:
                print fcolor.SBlue + "Current Directory        : " + fcolor.BYellow + str(os.getcwd()) + fcolor.SWhite
                original_sigint=signal.getsignal(signal.SIGINT)
                signal.signal(signal.SIGINT,signal.SIG_IGN)
                ps=subprocess.Popen(usr_resp_n, shell=True, stdout=subprocess.PIPE)	
                __builtin__.ExtReadOut=str(ps.stdout.read())
                if str(__builtin__.ExtReadOut).replace("\n","")!="":
                    RunCmd=1
                    print fcolor.SWhite + __builtin__.ExtReadOut
                ps.wait();ps.stdout.close()
                if __builtin__.DISABLE_BREAK=="No":
                    signal.signal(signal.SIGINT,original_sigint)
            RECON_CMD=1
    if usr_resp!="" and usr_resp!="CLEAR" and usr_resp!="." and usr_resp!="..":
        if RECON_CMD==0:
            print spacing + fcolor.SRed + "Unrecognized Command ! Key in HELP for assistance."
        else:
            if usr_resp!="HELP":
                __builtin__.LASTCMD=usr_resp_n
                __builtin__.LASTCMDLOG=__builtin__.LASTCMDLOG + fcolor.SGreen + Now() + "\t- " + fcolor.BYellow + str(usr_resp_n) + "\n"
        if RunCmd!=1:
            print ""
    ReadCommand()
    return

def AddIfNotDuplicate(sName,sList):
    tmpList=[]
    tmpList=sList
    if str(tmpList).find("'" + sName + "'")==-1:
        tmpList.append (sName)
    return tmpList

def ReturnSpecifiedDir(sName):
    if sName=="CAP" or sName=="PCAP" or sName=="TXT" or sName=="LOG" or sName=="DB" or sName=="MONITOR" or sName=="MON" or sName=="ATTACK" or sName=="ATK":
        __builtin__.lookupdir=""
        if sName=="CAP" or sName=="PCAP" or sName=="TXT":
            __builtin__.lookupdir=savedir
        if sName=="LOG" or sName=="DB":
            __builtin__.lookupdir=dbdir
        if sName=="ATTACK" or sName=="ATK":
            __builtin__.lookupdir=attackdir
        if sName=="MONITOR" or sName=="MON":
            __builtin__.lookupdir=mondir
        if sName=="CAP" or sName=="PCAP" or sName=="MON" or sName=="MONITOR" or sName=="ATK" or sName=="ATTACK":
            __builtin__.ExtList= ['pcap','cap']
        if sName=="TXT":
            __builtin__.ExtList= ['txt']
        if sName=="LOG":
            __builtin__.ExtList= ['log']
        if sName=="DB":
           __builtin__.ExtList= ['db']
        return __builtin__.lookupdir
    return ""

def DisplayFileNotFound(FName):
    print fcolor.SRed + spacing + "Specified file " + fcolor.BRed + str(FName) + fcolor.SRed + " not found."

def SplitFileDetail(fpath):
    __builtin__.FilePath=""
    __builtin__.FileName=""
    __builtin__.FileNameOnly=""
    __builtin__.FileExt=""
    __builtin__.FilePath=os.path.dirname(fpath) + "/"
    __builtin__.FileName=os.path.basename(fpath)
    tmpstr,__builtin__.FileExt=os.path.splitext(fpath)
    __builtin__.FileNameOnly=tmpstr

def SearchFileOnDir(FName):
    SplitFileDetail(FName)
    if IsFileDirExist(FName)!="F":
        for dir in __builtin__.searchdir:
            SplitFileDetail(dir + FName)
            if IsFileDirExist(dir + FName)=="F":
                FName=dir + FName
                return FName
    else:
        return FName
    return ""

def ArrangeFileDisplay(sFileList):
    x=0;mxlen=0;rDisplay="";MxCol=7
    while x<len(sFileList):
        clen=len(sFileList[x])
        if clen>mxlen:
            mxlen=clen
        x += 1
    mxlen=mxlen + 25
    SW=GetScreenWidth()
    SW=SW+25
    if int(mxlen)*int(MxCol)>int(SW):
        MxCol=6
        if int(mxlen)*int(MxCol)>int(SW):
            MxCol=5
            if int(mxlen)*int(MxCol)>int(SW):
                MxCol=4
                if int(mxlen)*int(MxCol)>int(SW):
                   MxCol=3
                   if int(mxlen)*int(MxCol)>int(SW):
                      MxCol=2
                      if int(mxlen)*int(MxCol)>int(SW):
                          MxCol=1
    x=0
    c=1
    while x<len(sFileList):
        fn=sFileList[x]
        GetFileDetail(__builtin__.lookupdir + fn)
        fn="*FG*" + fn + "*FW*" + " [" + str(__builtin__.FileSize) + "]"
        if c>int(MxCol):
            rDisplay=rDisplay + "\n"
            c=1
        rDisplay=rDisplay + fn.ljust(mxlen)
        x += 1;c += 1
    rDisplay=rDisplay.replace("*FG*",fcolor.SGreen).replace("*FW*",fcolor.SWhite)
    return rDisplay

def DisplayAnalysisFilters():
    DisplayAnalysisMACFilter("")
    DisplayAnalysisSearchFilter("")
    DisplayAnalysisIgnoreFilter("")

def GetEncryptionType(FistMAC,SecondMAC):
    ReturnEncryption=""
    MACUse=FistMAC
    foundloc=FindMACIndex(FistMAC,ListInfo_BSSID)
    if foundloc==-1:
        foundloc=FindMACIndex(SecondMAC,ListInfo_BSSID)
        MACUse=SecondMAC
    if foundloc!=-1:
        if str(ListInfo_BSSID[foundloc])==str(MACUse):
            ReturnEncryption=str(ListInfo_Privacy[foundloc]) + "\t" + str(ListInfo_Cipher[foundloc]) + "\t" + str(ListInfo_Auth[foundloc])+ "\t" + str(ListInfo_WPS[foundloc]) + "\t" + str(ListInfo_WPSVer[foundloc]) + "\t" + str(ListInfo_WPSLock[foundloc])+ "\t" + str(MACUse)
    else:
        ReturnEncryption="\t\t\t\t\t\t\t\t"
    return ReturnEncryption

def GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,Loc):
    EncryptionType=[]
    Result=GetEncryptionType(ToBSSID,FrMAC)
    EncryptionType=str(Result).split("\t")
    if EncryptionType[Loc]=="":
        Result=GetEncryptionType(ToMAC,ToBSSID)
        EncryptionType=str(Result).split("\t")
    return EncryptionType[Loc]

def GetWPSInfo(FrMAC,ToMAC,ToBSSID):
    EncryptionType=[]
    Result=GetEncryptionType(ToBSSID,FrMAC)
    EncryptionType=str(Result).split("\t")
    if EncryptionType[0]=="":
        Result=GetEncryptionType(ToMAC,ToBSSID)
        EncryptionType=str(Result).split("\t")
    if EncryptionType[3]=="Yes":
        return "Ver - " + str(EncryptionType[4]) + " / Lock? : " + str(EncryptionType[5])
    else:
        return ""

def ArrangeSignalReport(FrMAC,ToMAC,Spacer,lblColor):
    Report=""
    if ToMAC!="Not Associated" and FrMAC!="Not Associated":
        FrMacType="Station"
        ToMacType="Station"
        foundloc=FindMACIndex(FrMAC,ListInfo_BSSID)
        if foundloc!=-1:
            FrMacType="Access Point"
        foundloc=FindMACIndex(ToMAC,ListInfo_BSSID)
        if foundloc!=-1:
            ToMacType="Access Point"
         
        Report=lblColor + Spacer + str(FrMacType) + " [" + FrMAC + "] is near to you than you are to the " + str(ToMacType) + " [" + ToMAC + "]"
    return Report

def ArrangeSignalLocation(FrColor,FrMAC,FrSignal,ToColor,ToMAC,ToSignal,Spacer,lblColor,ToDisplay):
    OutputTxt=""
    if str(FrSignal)!="" and str(ToSignal)!="" and len(str(FrSignal))>0 and len(str(ToSignal))>0 and str(FrSignal)!="-1" and str(ToSignal)!="-1":
        if FrSignal[:1]=="-" and ToSignal[:1]=="-" and ToMAC!="Not Associated" and FrMAC!="Not Associated":
            FrSig=FrSignal[1:];ToSig=ToSignal[1:];
            if  int(FrSig)<int(ToSig):
                OutputTxt=fcolor.BIGray + "Your Location" + lblColor + "   >   " + FrColor + FrMAC +  lblColor + "   >   " + ToColor + ToMAC 
                Report=ArrangeSignalReport(FrMAC,ToMAC,"",fcolor.SYellow)
            if  int(FrSig)>int(ToSig):
                OutputTxt=fcolor.BIGray + "Your Location" + lblColor + "   >   " + ToColor + ToMAC  + lblColor + "   >   " + FrColor + FrMAC 
                Report=ArrangeSignalReport(ToMAC,FrMAC,"", fcolor.SYellow)
            if  int(FrSig)==int(ToSig):
                OutputTxt=fcolor.BIGray + "Your Location" + lblColor + "   >   " + FrColor + FrMAC + lblColor + "   =   " + ToColor + ToMAC
                Report=ArrangeSignalReport(FrMAC,ToMAC,"", fcolor.SYellow)
            OutputTxt=lblColor + Spacer + "Location : " + OutputTxt 
            if Report!="":
                OutputTxt=OutputTxt + "\n" + lblColor + Spacer + "         : " + Report
            if ToDisplay=="1":
                print OutputTxt
            else:
                return OutputTxt + "\n"
    return OutputTxt

def DisplayMACSInformation(FrMAC,ToMAC,ToBSSID):
    ColorFrMAC=fcolor.BGreen
    ColorToMAC=fcolor.BRed
    ColorToBSSID=fcolor.BCyan
    ColorBStd=fcolor.SGreen
    FrMACOUI=DisplayOUIDetail(FrMAC,ColorFrMAC)
    ToMACOUI=DisplayOUIDetail(ToMAC,ColorToMAC)
    ToBSSIDOUI=DisplayOUIDetail(ToBSSID,ColorToBSSID)
    __builtin__.MSG_IDSDetection=""
    FrMACSignal=GetSignal(FrMAC)
    ToMACSignal=GetSignal(ToMAC)
    ToBSSIDSignal=GetSignal(ToBSSID)
    if ToMAC==ToBSSID:
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + ColorBStd + "     From MAC   [ " + ColorFrMAC + str(FrMAC) + ColorBStd + " ] ==> To MAC [ " + ColorToBSSID + str(ToBSSID) + ColorBStd + " ]- Access Point MAC.\n"
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(FrMACOUI) 
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(ToBSSIDOUI)
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd2 + "  Signal   [ " + ColorFrMAC + str(FrMAC) + ColorStd2 + " ] = " + ColorFrMAC + str(GetSignalData(FrMAC)) + ColorStd2 + " ==>  [ " + ColorToBSSID + str(ToBSSID) + ColorStd2 + " ] = " + ColorToBSSID  + str(GetSignalData(str(ToBSSID))) + "\n"
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + ArrangeSignalLocation(ColorFrMAC,FrMAC,str(FrMACSignal),ColorToBSSID,ToBSSID,str(ToBSSIDSignal),"       ",ColorStd2,"")
    else:
        if FrMAC==ToBSSID:
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd + "From BSSID [ " + ColorToBSSID + str(ToBSSID) + ColorStd2 + " ] ==> To MAC [ " + ColorToMAC + str(ToMAC) + ColorStd + " ].\n"
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(ToBSSIDOUI)
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(ToMACOUI)
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd2 + "  Signal   [ " + ColorToBSSID + str(ToBSSID) + ColorStd2 + " ] = " + ColorBStd + str(GetSignalData(ToBSSID)) + ColorStd2 + " ==>  [ " + ColorToMAC + str(ToMAC) + ColorStd2 + " ] = " + ColorToMAC  + str(GetSignalData(str(ToMAC))) + "\n"
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + str(ArrangeSignalLocation(ColorToBSSID,ToBSSID,ToBSSIDSignal,ColorToMAC,ToMAC,str(ToMACSignal),"       ",ColorStd2,""))
        else:
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd + "From MAC   [ " + ColorFrMAC + str(FrMAC) + ColorStd + " ] ==> To MAC [" + ColorToMAC + str(ToMAC) + ColorStd + " ], Related BSSID [ " + ColorToBSSID + str(ToBSSID) + ColorStd + " ]\n"
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(FrMACOUI)
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(ToMACOUI)
            __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(ToBSSIDOUI)
            if ToMAC[:6]!="33:33:" and ToMAC[:6]!="FF:FF:" and ToMAC[:9]!="01:80:C2:" and ToMAC[:9]!="01:00:5E:":
                __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd2 + "  Signal   [ " + ColorFrMAC + str(FrMAC) + ColorBStd + " ] = " + ColorFrMAC + str(GetSignalData(FrMAC)) + ColorStd2 + " ==>  [ " + ColorToMAC + str(ToMAC) + ColorStd + " ] = " + ColorToMAC  + str(GetSignalData(str(ToMAC))) + "\n"
                __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + ArrangeSignalLocation(ColorFrMAC,FrMAC,str(FrMACSignal),ColorToMAC,ToMAC,str(ToMACSignal),"       ",ColorStd2,"")
            else:
                __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + ColorStd2 + "  Signal   [ " + ColorFrMAC + str(FrMAC) + ColorStd2 + " ] = " + ColorBStd + str(GetSignalData(FrMAC)) + ColorStd2 + " ==>  [ " + ColorToBSSID + str(ToBSSID) + ColorStd2 + " ] = " + ColorToBSSID  + str(GetSignalData(str(ToBSSID))) + "\n"
                __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + ArrangeSignalLocation(ColorFrMAC,FrMAC,str(FrMACSignal),ColorToBSSID,ToBSSID,str(ToBSSIDSignal),"       ",ColorStd2,"")
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(DisplayESSIDDetail(ToBSSID,ColorToBSSID))
        __builtin__.MSG_IDSDetection = __builtin__.MSG_IDSDetection + "     " + str(DisplaySSIDDetail(ToBSSID)) + "\n"
    
    return str(__builtin__.MSG_IDSDetection)

def DisplayAttackMsg(WarningCount,MSG,MSG2, DataCt, NotesInfo1,NotesInfo2,NotesInfo3):
   if len(str(WarningCount))==1:
     spacer="  "
   if len(str(WarningCount))==2:
     spacer=" "
   RTNMSG= fcolor.SWhite + "[" + fcolor.BRed + str(WarningCount) + fcolor.SWhite + "]" + spacer + fcolor.BGreen + "Possible Attack : [ " + fcolor.BRed + str(MSG) + fcolor.BGreen + " ] Detected !!!\n"
   if MSG2!="":
       RTNMSG= RTNMSG + fcolor.BGreen + "                     : " + str(MSG2) + "\n"
   RTNMSG= RTNMSG + fcolor.BGreen + "               Packets : " + fcolor.BRed + str(DataCt) + fcolor.SWhite + "\n"
   if NotesInfo1!="":
       RTNMSG=RTNMSG + fcolor.BGreen + "                 Notes : " + fcolor.SWhite + "" + str(NotesInfo1) + "\n"
   if NotesInfo2!="":
       RTNMSG=RTNMSG + fcolor.BGreen + "                       : " + fcolor.SWhite + "" + str(NotesInfo2) + "\n"
   if NotesInfo3!="":
       RTNMSG=RTNMSG + fcolor.BGreen + "                       : " + fcolor.SWhite + "" + str(NotesInfo3) + "\n"
   return RTNMSG

def SaveFilteredMAC(MACList,sFile,sDir):
    xm=0
    spacing=""
    SaveFile=""
    DateTime=str(Now()).replace(":","").replace("/","").replace("-","").replace(" ","_")
    rsFile=sFile.replace("*","")
    if sFile[-1:]=="*":
        SaveFile=sDir + rsFile + "_" + DateTime + ".cap"
    if sFile[:1]=="*":
        SaveFile=sDir + DateTime + "_" + rsFile + ".cap"
    
    fmac="";dfmac=""
    while xm<len(MACList):
        fmac=fmac + "wlan.addr==" + str(MACList[xm]) + " or "
        dfmac=dfmac + str(MACList[xm]) + " / "
        xm += 1
    fmac=fmac[:-4]
    dfmac=dfmac[:-3]
    printl (spacing + fcolor.SGreen + "Saving MAC filtered pcap file..." + fcolor.BRed + SaveFile,"0","")
    ps=subprocess.Popen("tshark -r " + str(__builtin__.CurrentPacket) + " -R '" +  str(fmac) + "' -w " + SaveFile + "" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    printl (spacing + fcolor.SGreen + "Filtered PCap file saved " + fcolor.SRed +  str(SaveFile) + fcolor.SGreen + " - MAC filtered : " + str(dfmac) ,"0","")
    print ""

def AddMACToList(MACAddr,MACList):
    if str(MACList).find(MACAddr)==-1:
        MACList.append (MACAddr)

def ShowIntrusionPrevention(CMD):
    if CMD=="1" or CMD!="":
        printc ("+", fcolor.BBlue + "Intrusion Prevention Setting - Station Deauth","")
    if IsFileDirExist(__builtin__.IPSScript)=="F":
        if CMD=="1" or CMD=="":
            usr_resp=AskQuestion("Enter Attacker MAC Address ","xx:xx:xx:xx:xx:xx","U","RETURN","")
        else:
            usr_resp=CMD
        if usr_resp=="RETURN":
            return
        if CheckMAC(usr_resp)=="":
            printc ("!",fcolor.SRed + "The MAC Address " + fcolor.BYellow + str(usr_resp) + fcolor.SRed + " is invalid !!\n","")
            if CMD=="1" and CMD=="":
                ShowIntrusionPrevention("")
                return
        else:
            IPSIFace=__builtin__.SELECTED_MON
            if CMD=="1" or CMD=="":
                AttackerMAC=usr_resp
                IPSLoop=AskQuestion("Enter the loopcount before IPS Stop : ",fcolor.SWhite + "<default = 9999999>","N",9999999,"0")
                RestTime=AskQuestion("Waiting time before another deauth  : ",fcolor.SWhite + "<default = 1 sec>","N",1,"0")
                print ""
                Result=AskQuestion("Proceed to DeAuth MAC " + fcolor.BRed + str(AttackerMAC) ,"Y/n","U","Y","1")
            else:
                AttackerMAC=usr_resp
                IPSIFace=__builtin__.SELECTED_MON
                IPSLoop=9999999
                RestTime=1
                Result="Y"
            if Result=="Y":
                printc ("i",fcolor.BGreen + "Station Deauth Launched..","")
                cmdLine="xterm -geometry 300x80+0+0 -iconic -bg black -fg white -fn 6x12 -title 'WAIDPS - Intrusion Prevention - " + str(AttackerMAC) + "' -e 'python " + str(__builtin__.IPSScript) + " " + str(IPSIFace) + " " + str(AttackerMAC) + " " + str(IPSLoop) + " " + str(RestTime) + "'"
                ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid)	
                __builtin__.IPS=ps.pid
            else:
                printc ("!",fcolor.SRed + "Operation aborted..\n","")
                return
    else:
        printc ("!",fcolor.BRed + "IPS DeAuth file not found !!","")
    return
        

def ShowIDSDetection(CMD):
    __builtin__.MSG_IDSDetection =""
    __builtin__.MSG_IDSDetectionOverAll =""
    __builtin__.List_AttackingMAC=[]
    WarningCount=0
    if len(__builtin__.OfInterest_List)>0:
        x=0
        tmpInterestList=[]
        while x<len(__builtin__.OfInterest_List):
            tmpInterestList=str(__builtin__.OfInterest_List[x]).split("\t")
            MSG_ATTACK=""
            FrMAC=tmpInterestList[0]
            ToMAC=tmpInterestList[1]
            ToBSSID=tmpInterestList[2]
            GET_DATAARP=tmpInterestList[3]
            GET_DATA86=tmpInterestList[4]
            GET_DATA94=tmpInterestList[5]
            GET_DATA98=tmpInterestList[6]
            GET_AUTH=tmpInterestList[7]
            GET_DEAUTH=tmpInterestList[8]
            GET_DEAUTH_AC=tmpInterestList[9]
            GET_ASSOC=tmpInterestList[10]
            GET_DISASSOC=tmpInterestList[11]
            GET_REASSOC=tmpInterestList[12]
            GET_RTS=tmpInterestList[13]
            GET_CTS=tmpInterestList[14]
            GET_ACK=tmpInterestList[15]
            GET_EAPOL_STD=tmpInterestList[16]
            GET_EAPOL_START=tmpInterestList[17]
            GET_WPS=tmpInterestList[18]
            GET_BEACON=tmpInterestList[19]
            GET_PRQX=tmpInterestList[20]
            GET_PRESP=tmpInterestList[21]
            GET_NULL=tmpInterestList[22]
            GET_QOS=tmpInterestList[23]
            YOURMAC=tmpInterestList[24]
            GET_PROBE=tmpInterestList[25]
            tGET_PROBE=RemoveColor(GET_PROBE)
            tGET_PROBE=tGET_PROBE.replace(" / <<Broadcast>> / "," / ").replace(" / <<Broadcast>>","").replace("<<Broadcast>> / ","")
            GET_PROBEList=[]
            GET_PROBEList=tGET_PROBE.split(" / ")
            if str(GET_PROBE).find("\\")!=-1 or FrMAC!=ToBSSID:
                GET_PROBEList=[]
            NotesInfo1="";NotesInfo2="";NotesInfo3=""
            DetailInfo=fcolor.BBlue + "     [Details]\n"
#or int(GET_DATA86)>int(__builtin__.THRESHOLD_DATA86) or int(GET_DATA94)>int(__builtin__.THRESHOLD_DATAARP) or int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) or int(GET_DEAUTH_AC)>int(__builtin__.THRESHOLD_DEAUTH) or int(GET_DEAUTH)>int(__builtin__.THRESHOLD_DEAUTH_AC) or int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) or int(GET_DISASSOC)>int(__builtin__.THRESHOLD_DISASSOC) or int(GET_REASSOC)>int(__builtin__.THRESHOLD_REASSOC) or  int(GET_EAPOL_STD)>int(__builtin__.THRESHOLD_EAPOL_STD) int(GET_EAPOL_START)>int(__builtin__.THRESHOLD_EAPOL_START) or int(GET_WPS)>int(__builtin__.THRESHOLD_WPS) or int(GET_QOS)>int(__builtin__.THRESHOLD_QOS) or len(GET_PROBEList)>0:
            Breaks=DrawLine("-",fcolor.CReset + fcolor.Black,"","1")
            AddMACToList(FrMAC,List_AttackingMAC)
            AddMACToList(ToMAC,List_AttackingMAC)
            AddMACToList(ToBSSID,List_AttackingMAC)
            if int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)<int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Association Flood"
               NotesInfo1="The data pattern match those persistent associating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS Pin bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with association request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_ASSOC)<int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Authentication Flood"
               NotesInfo1="The data pattern match those persistent authenticating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS Pin bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with association request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Association/Authentication Flood"
               NotesInfo1="The data pattern match those persistent associating/authenticating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS Pin bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with association request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DATAARP)>int(__builtin__.THRESHOLD_DATAARP):	# ARP 
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DATAARP
               NotesInfo1="The data pattern match those used in Aireplay-NG ARP-Replay Request Attack."
               ATTACK_TYPE="WEP - ARP-Replay Request"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WEP":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WEP" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DATA98)>int(__builtin__.THRESHOLD_DATA98):	# CHOPCHOP - GUESSING PROCESS
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DATA98
               NotesInfo1="The data pattern match those used in Aireplay-NG KoreK Chopchop Attack."
               ATTACK_TYPE="WEP - KoreK Chopchop"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WEP":
                   NotesInfo2="The KoreK Chopchop attacks will usually come before an ARP-Replay Request after it obtained the decrypted WEP byte"
                   NotesInfo3="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WEP" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               ToMAC="FF:FF:FF:FF:FF:FF"
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if len(GET_PROBEList)>1 and ToMAC=="FF:FF:FF:FF:FF:FF":		# ROGUE AP
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_BEACON
               NotesInfo1="The response pattern match those used in Rogue Access Point."
               ATTACK_TYPE="Rogue Access Point"
               NotesInfo2="Do note that if SSID Name looks similar, it may not a Rogue Access Point due to malformed packets"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="OPN":
                   NotesInfo3=fcolor.BRed + "Rogue AP in most cases will be an Open network and response to probe request by devices. Current AP match the profile."
               tGET_PROBE=RemoveColor(tGET_PROBE)
               tGET_PROBE=ReplaceSlash(tGET_PROBE,fcolor.BBlue,fcolor.SWhite)
               GET_PROBE=GET_PROBE.replace(" / ", fcolor.SWhite + " / " + fcolor.BBlue)
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] broadcasted itself as [ " + fcolor.BBlue + tGET_PROBE + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               ToMAC="FF:FF:FF:FF:FF:FF"
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_QOS)>int(__builtin__.THRESHOLD_QOS):	# TKIPTUN-NG
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_QOS 
               NotesInfo1="The data pattern match those used in TKIPTUN-NG Attacks."
               ATTACK_TYPE="TKIPTUN-NG Injection"
               PrivacyInfo=GetPrivacyInfo(ToMAC,ToBSSID,ToBSSID,0)
               if PrivacyInfo=="WPA" or PrivacyInfo=="WPA2":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA/WPA2" + "\n"
                   CipherInfo=GetPrivacyInfo(ToMAC,ToBSSID,ToBSSID,1)
                   if str(CipherInfo).find("TKIP")!=-1:
                       NotesInfo3="The Cipher of the BSSID also Match Attack Criteria : " + fcolor.BYellow + str(CipherInfo) + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] <Fake MAC> injecting to Station [ " + fcolor.BRed + ToMAC + fcolor.BGreen + " ] ==> BSSID [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(ToMAC,ToBSSID,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DEAUTH_AC)>int(__builtin__.THRESHOLD_DEAUTH_AC):	# DEAUTH - A
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DEAUTH_AC
               NotesInfo1="The data pattern match those used in Aireplay-NG Deauthenticate Request."
               ATTACK_TYPE="Deauthentication Attack"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WPA" or PrivacyInfo=="WPA2":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA/WPA2" + "\n\n"
                   ATTACK_TYPE="Deauthentication - WPA Handshake"
               if ToMAC!="FF:FF:FF:FF:FF:FF":
                   sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is calling deauthentication to [ " + fcolor.BCyan + ToMAC + fcolor.BGreen + " ]"
               else:
                   sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is calling deauthentication to all stations"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_WPS)>int(__builtin__.THRESHOLD_WPS) and FrMAC!=ToBSSID:	# REAVER - WPS
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_WPS
               ATTACK_TYPE="WPS - PIN Bruteforce"
               NotesInfo1="The data pattern match those used in WPS Communication."
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if WPSInfo!="":
                   NotesInfo2="Usually a WPS Pin Brutefore will be slow and continuous.. Observe the pattern."
                   NotesInfo3="The Access Point has WPS [ " + str(WPSInfo) + " ] and Match Attack Criteria : " + fcolor.BYellow + "WPS" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] via WPS authentication"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_EAPOL_START)>int(__builtin__.THRESHOLD_EAPOL_START) and FrMAC!=ToBSSID and int(GET_EAPOL_START)>int(GET_WPS):	# REAVER - WPS - EAPOL START
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_EAPOL_START + " EAPOL Start" + fcolor.BGreen + " / " + fcolor.BRed + GET_WPS + " EAP Request "
               ATTACK_TYPE="WPS - PIN Bruteforce Attempting"
               NotesInfo1="The data pattern match those used in WPS Communication."
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if WPSInfo!="":
                   NotesInfo2="Having too much EAP Start request than EAP Message,it likely station failed to attack Access Point.. Observe the pattern."
                   NotesInfo3="The Access Point has WPS [ " + str(WPSInfo) + " ] and Match Attack Criteria : " + fcolor.BYellow + "WPS" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] via EAP Start / WPS authentication"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK)) #+ str(Breaks) + "\n"
            x += 1
    if int(WarningCount)>0 and __builtin__.SHOW_IDS=="Yes":
        BeepSound()
        CenterText(fcolor.BGIRed + fcolor.BWhite,"< < <<  WARNING !!! - ATTACKS DETECTED  >> > >      ")
        print ""
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll + "" + fcolor.BWhite + "Total Warning : " + fcolor.BRed + str(WarningCount) + "\n" + fcolor.SCyan + "Reported : " + str(Now()) + "\n"
        print str(__builtin__.MSG_IDSDetectionOverAll)
        WriteAttackLog(__builtin__.MSG_IDSDetectionOverAll + "\n")
        __builtin__.MSG_AttacksLogging=str(__builtin__.MSG_AttacksLogging) + str(__builtin__.MSG_IDSDetectionOverAll) + "\n"
        __builtin__.MSG_CombinationLogs=str(__builtin__.MSG_CombinationLogs) + str(__builtin__.MSG_IDSDetectionOverAll) + "\n"
        if __builtin__.SAVE_ATTACKPKT=="Yes":
            SaveFilteredMAC(List_AttackingMAC,"ATTACK*",attackdir)
        LineBreak()

def ShowAnalysedListing(usr_resp):
    spacing=""
    rtnDisplay=""
    ToDisplay=0
    OfInterestSensitive=""
    __builtin__.OfInterest_List=[]
    OfInterest=""
    if usr_resp!="":
        usr_resp=str(usr_resp).upper()
        tmpMACList=[]
        if usr_resp!="SHOW LIST3_QUIET":
            print ""
        TITLE_PROBE=""
        if usr_resp[-1:]=="A":
            TITLE_PROBE=" - Without Probe/SSID"
        if usr_resp[:10]=="SHOW LIST1":
            print spacing + fcolor.BBlue + "Analysed Result Listing"
        if usr_resp[:10]=="SHOW LIST2":
            print spacing + fcolor.BBlue + "Analysed Result Listing With Filters"
            DisplayAnalysisMACFilter("")
        if usr_resp[:10]=="SHOW LIST3":
            if usr_resp!="SHOW LIST3_QUIET":
                print spacing + fcolor.BBlue + "Analysed Result Listing Of Interest (Base on Sensitivty of IDS setting)"
        if usr_resp[:10]=="SHOW LIST4":
            print spacing + fcolor.BBlue + "Analysed Result Listing Of Interest (Base on Standard Threshold of " + str(__builtin__.THRESHOLD) + ")"
        if usr_resp!="SHOW LIST3_QUIET":
            __builtin__.SHOWRESULT=3
        else:
            __builtin__.SHOWRESULT=4
        if usr_resp!="SHOW LIST3_QUIET":
            printl ("","0","")
        __builtin__.SHOWRESULT=0
        x=0;y=0;DisplayCt=0
        RECON_CMD=1;
        COLOR1=fcolor.SGreen
        COLOR2=fcolor.SWhite
        COLOR3=fcolor.SPink
        COLOR4=fcolor.SBlue
        COLOR5=fcolor.SCyan
        COLOR6=fcolor.SYellow 
        COLOR7=fcolor.SRed 
        if usr_resp!="SHOW LIST3_QUIET":
            print ""
        TITLE= fcolor.CUnderline + fcolor.BGreen + "SN      Source MAC       "  + " " + fcolor.BPink + "Destination MAC  " + " " + fcolor.BBlue + "SSID MAC         " + " " + COLOR1  + fcolor.CUnderline + "ARP".ljust(5) + COLOR2  + fcolor.CUnderline + "D86".ljust(5)+ COLOR3  + fcolor.CUnderline + "D94".ljust(5)+COLOR4  + fcolor.CUnderline +  "D98".ljust(5)+ COLOR5  + fcolor.CUnderline +  "AUTH".ljust(5) + COLOR6  + fcolor.CUnderline + "DATH".ljust(5) + COLOR3  + fcolor.CUnderline + "D.AC".ljust(5) + COLOR7  + fcolor.CUnderline + "ASC".ljust(5)+ COLOR1  + fcolor.CUnderline + "DASC".ljust(5) + COLOR2 + fcolor.CUnderline + "RASC".ljust(5) + COLOR3  + fcolor.CUnderline + "RTS".ljust(5)+ COLOR4  + fcolor.CUnderline + "CTS".ljust(5)+ COLOR2  + fcolor.CUnderline + "ACK".ljust(5)+ COLOR3  + fcolor.CUnderline + "EPL".ljust(5)+  COLOR5 + fcolor.CUnderline + "EPS".ljust(5)+ COLOR1  + fcolor.CUnderline + "WPS".ljust(5)+ COLOR6  + fcolor.CUnderline + "BCN".ljust(5)+ COLOR7  + fcolor.CUnderline + "RQX".ljust(5)+ COLOR1 + fcolor.CUnderline  + "RPN".ljust(5)+ COLOR2 + fcolor.CUnderline  + "NULL".ljust(5) + COLOR3 + fcolor.CUnderline  + "QOS".ljust(5) + COLOR4 + fcolor.CUnderline + "Remarks" + fcolor.CReset 
        if usr_resp!="SHOW LIST3_QUIET":
            print TITLE
        SN=0;OfInterest=""
        while x<len(__builtin__.List_FrMAC):
            SN += 1
            FrMAC=__builtin__.List_FrMAC[x]
            ToMAC=__builtin__.List_ToMAC[x]
            ToBSSID=__builtin__.List_BSSID[x]
            GET_DATAARP=__builtin__.List_DataARP[x]
            GET_DATA86=__builtin__.List_Data86[x]
            GET_DATA98=__builtin__.List_Data98[x]
            GET_DATA94=__builtin__.List_Data94[x]
            GET_AUTH=__builtin__.List_Auth[x]
            GET_DEAUTH=__builtin__.List_Deauth[x]
            GET_DEAUTH_AC=__builtin__.List_Deauth_AC[x]
            GET_ASSOC=__builtin__.List_Assoc[x]
            GET_REASSOC=__builtin__.List_Reassoc[x]
            GET_DISASSOC=__builtin__.List_Disassoc[x]
            GET_RTS=__builtin__.List_RTS[x]
            GET_CTS=__builtin__.List_CTS[x]
            GET_ACK=__builtin__.List_ACK[x]
            GET_EAPOL_STD=__builtin__.List_EAPOL_STD[x]
            GET_EAPOL_START=__builtin__.List_EAPOL_START[x]
            GET_WPS=__builtin__.List_WPS[x]
            GET_BEACON=__builtin__.List_Beacon[x]
            GET_PRESP=__builtin__.List_PResp[x]
            GET_PRQX=__builtin__.List_PReq[x]
            GET_NULL=__builtin__.List_NULL[x]
            GET_QOS=__builtin__.List_QOS[x]
            GET_PROBE=str(__builtin__.List_ProbeName[x])[:-3]
            tGET_PROBE=RemoveColor(GET_PROBE)
            tGET_PROBE=tGET_PROBE.replace(" / <<Broadcast>> / "," / ").replace(" / <<Broadcast>>","").replace("<<Broadcast>> / ","")
            GET_PROBEList=[]
            GET_PROBEList=tGET_PROBE.split(" / ")
            if str(GET_PROBE).find("\\")!=-1 or FrMAC!=ToBSSID:
                GET_PROBEList=[]
            if len(GET_PROBEList)==2 and len(GET_PROBEList[0])==len(GET_PROBEList[1]):
                if str(GET_PROBEList[0])[:1].upper()==str(GET_PROBEList[1])[:1].upper() or str(GET_PROBEList[0])[-1:].upper()==str(GET_PROBEList[1])[-1:].upper():
                    GET_PROBEList=[]
            if len(GET_PROBEList)==3 and len(GET_PROBEList[0])==len(GET_PROBEList[1]) and len(GET_PROBEList[1])==len(GET_PROBEList[2]):
                if str(GET_PROBEList[0])[:1].upper()==str(GET_PROBEList[1])[:1].upper() or str(GET_PROBEList[0])[-1:].upper()==str(GET_PROBEList[1])[-1:].upper() or str(GET_PROBEList[1])[:1].upper()==str(GET_PROBEList[2])[:1].upper() or str(GET_PROBEList[1])[-1:].upper()==str(GET_PROBEList[2])[-1:].upper():
                    GET_PROBEList=[]
            if len(GET_PROBEList)==2 and len(GET_PROBEList[0])!=len(GET_PROBEList[1]):
                if len(GET_PROBEList[1])<5 or len(GET_PROBEList[1])<5:
                    if str(GET_PROBEList[0])[:1].upper()==str(GET_PROBEList[1])[:1].upper(): 
                        GET_PROBEList=[]
            
            THRESHOLD=int(__builtin__.THRESHOLD)
            ADDOFINTEREST=0
            ADDOFINTEREST_SENSITIVE=0
            if int(GET_DATAARP)>int(__builtin__.THRESHOLD_DATAARP) or int(GET_DATA86)>int(__builtin__.THRESHOLD_DATA86) or int(GET_DATA94)>int(__builtin__.THRESHOLD_DATA94) or int(GET_DATA98)>int(__builtin__.THRESHOLD_DATA98) or int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) or int(GET_DEAUTH)>int(__builtin__.THRESHOLD_DEAUTH) or int(GET_DEAUTH_AC)>int(__builtin__.THRESHOLD_DEAUTH_AC) or int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) or int(GET_DISASSOC)>int(__builtin__.THRESHOLD_DISASSOC) or int(GET_REASSOC)>int(__builtin__.THRESHOLD_REASSOC) or int(GET_EAPOL_STD)>int(__builtin__.THRESHOLD_EAPOL_STD) or int(GET_EAPOL_START)>int(__builtin__.THRESHOLD_EAPOL_START) or int(GET_WPS)>int(__builtin__.THRESHOLD_WPS) or int(GET_QOS)>int(__builtin__.THRESHOLD_QOS) or len(GET_PROBEList)>1:
                ADDOFINTEREST_SENSITIVE=1
            if int(GET_DATAARP)>THRESHOLD or int(GET_DATA86)>THRESHOLD  or int(GET_DATA94)>int(THRESHOLD) or int(GET_DATA98)>int(THRESHOLD) or int(GET_DATA94)>THRESHOLD or int(GET_AUTH)>THRESHOLD or int(GET_DEAUTH_AC)>THRESHOLD or int(GET_DEAUTH)>THRESHOLD or int(GET_ASSOC)>THRESHOLD or int(GET_DISASSOC)>THRESHOLD or int(GET_REASSOC)>THRESHOLD or int(GET_EAPOL_STD)>THRESHOLD  or int(GET_EAPOL_START)>THRESHOLD or int(GET_WPS)>THRESHOLD or int(GET_QOS)>THRESHOLD  or len(GET_PROBEList)>1:
                ADDOFINTEREST=1
               
            if GET_DATAARP=="0":
                GET_DATAARP="-"
            if GET_DATA86=="0":
                GET_DATA86="-"
            if GET_DATA94=="0":
                GET_DATA94="-"
            if GET_DATA98=="0":
                GET_DATA98="-"
            if GET_AUTH=="0":
                GET_AUTH="-"
            if GET_DEAUTH=="0":
                GET_DEAUTH="-"
            if GET_DEAUTH_AC=="0":
                GET_DEAUTH_AC="-"
            if GET_ASSOC=="0":
                GET_ASSOC="-"
            if GET_REASSOC=="0":
                GET_REASSOC="-"
            if GET_DISASSOC=="0":
                GET_DISASSOC="-"
            if GET_RTS=="0":
                GET_RTS="-"
            if GET_CTS=="0":
                GET_CTS="-"
            if GET_ACK=="0":
                GET_ACK="-"
            if GET_EAPOL_STD=="0":
                GET_EAPOL_STD="-"
            if GET_EAPOL_START=="0":
                GET_EAPOL_START="-"
            if GET_WPS=="0":
                GET_WPS="-"
            if GET_BEACON=="0":
                GET_BEACON="-"
            if GET_PRESP=="0":
                GET_PRESP="-"
            if GET_PRQX=="0":
                GET_PRQX="-"
            if GET_NULL=="0":
                GET_NULL="-"
            if GET_QOS=="0":
                GET_QOS="-"
            if usr_resp[:10]=="SHOW LIST1":
                ToDisplay=1
            if usr_resp[:10]=="SHOW LIST4" or usr_resp=="SHOW LIST3_QUIET":
                if ADDOFINTEREST==1:
                    ToDisplay=1
                if ADDOFINTEREST_SENSITIVE==0 and ADDOFINTEREST==0:
                    ToDisplay=0
            if usr_resp[:10]=="SHOW LIST3" or usr_resp=="SHOW LIST3_QUIET":
                if ADDOFINTEREST_SENSITIVE==1:
                    ToDisplay=1
                if ADDOFINTEREST_SENSITIVE==0 and ADDOFINTEREST==0:
                    ToDisplay=0
            if usr_resp[:10]=="SHOW LIST2":
                if len(__builtin__.ANALYSIS_MAC)>0:
                    ToDisplay=0
                    yc=0
                    while yc < len(__builtin__.ANALYSIS_MAC):
                        tmpsearch=str(__builtin__.ANALYSIS_MAC[yc]).upper()
                        if str(FrMAC).find(tmpsearch)!=-1 or str(ToMAC).find(tmpsearch)!=-1 or str(ToBSSID).find(tmpsearch)!=-1:
                            if str(tmpMACList).find(FrMAC)==-1:
                                tmpMACList.append (FrMAC)
                            if str(tmpMACList).find(ToMAC)==-1:
                                tmpMACList.append (ToMAC)
                            if str(tmpMACList).find(ToBSSID)==-1:
                                tmpMACList.append (ToBSSID)
                            ToDisplay=1
                            yc=len(__builtin__.ANALYSIS_MAC)
                        else:
                            ToDisplay=0
                        yc += 1
                else:
                    ToDisplay=1
            if ToDisplay==1:
                if ADDOFINTEREST==1:
                    OfInterest=OfInterest + str(SN) + ", "
                    ADDOFINTEREST=0
                if ADDOFINTEREST_SENSITIVE==1:
                    OfInterestSensitive=OfInterestSensitive + str(SN) + ", "
                    ADDOFINTEREST_SENSITIVE=0
                FMColor=fcolor.BGreen
                TMColor=fcolor.BPink
                YOURMAC=""
                if CheckContainMyMAC(FrMAC)==True or CheckContainMyMAC(ToMAC)==True:
                    YOURMAC=fcolor.SRed + "[Your MAC]"
                    if CheckContainMyMAC(FrMAC)==True:
                        FMColor=fcolor.BRed
                    if CheckContainMyMAC(ToMAC)==True:
                        TMColor=fcolor.BRed
                GET_PROBE=GET_PROBE.replace(" / ",fcolor.SWhite + " / " + COLOR4)
                if usr_resp!="SHOW LIST3_QUIET":
                    print fcolor.SWhite + str(SN).ljust(8) + FMColor + FrMAC + " " + TMColor + ToMAC + " " + fcolor.BBlue + ToBSSID + " " + COLOR1 + GET_DATAARP.ljust(5) + COLOR2 + GET_DATA86.ljust(5)+ COLOR3 + GET_DATA94.ljust(5)+COLOR4 +  GET_DATA98.ljust(5)+ COLOR5 +  GET_AUTH.ljust(5)+ COLOR6 + GET_DEAUTH.ljust(5) + COLOR3 + GET_DEAUTH_AC.ljust(5) + COLOR6 + COLOR7 + GET_ASSOC.ljust(5)+ COLOR1 + GET_DISASSOC.ljust(5) + COLOR2 + GET_REASSOC.ljust(5) + COLOR3 + GET_RTS.ljust(5)+ COLOR4 + GET_CTS.ljust(5)+ COLOR2 + GET_ACK.ljust(5)+ COLOR3 + GET_EAPOL_STD.ljust(5) +COLOR5 + GET_EAPOL_START.ljust(5) + GET_WPS.ljust(5)+ COLOR6 + GET_BEACON.ljust(5)+ COLOR7 + GET_PRQX.ljust(5)+ COLOR1 + GET_PRESP.ljust(5)+ COLOR2 + GET_NULL.ljust(5) + COLOR3 + GET_QOS.ljust(5) + COLOR7 + YOURMAC
                    cCount=str(GET_DATAARP) + "\t" + str(GET_DATA86) + "\t" + str(GET_DATA94) + "\t" + str(GET_DATA98) + "\t" + str(GET_AUTH)  + "\t" + str(GET_DEAUTH) + "\t" + str(GET_DEAUTH_AC) + "\t" + str(GET_ASSOC) + "\t" + str(GET_DISASSOC) + "\t" + str(GET_REASSOC) + "\t" + str(GET_RTS) + "\t" + str(GET_CTS) + "\t" + str(GET_ACK) + "\t" + str(GET_EAPOL_STD) + "\t" + str(GET_EAPOL_START) + "\t" + str(GET_WPS) + "\t" + str(GET_BEACON) + "\t" + str(GET_PRQX) + "\t" + str(GET_PRESP) + "\t" + str(GET_NULL) + "\t" + str(GET_QOS)
                    cCount=str(cCount).replace("-","0")
                    __builtin__.OfInterest_List.append (str(FrMAC) + "\t" + str(ToMAC) + "\t" + str(ToBSSID) + "\t" + str(cCount) + "\t" + str(YOURMAC) + "\t" + str(GET_PROBE))
                    if GET_PROBE!="" and TITLE_PROBE=="":
                        if GET_PROBE=="<<Broadcast>>":
                            GET_PROBE=fcolor.SBlack + GET_PROBE
                        print fcolor.SWhite + " ".ljust(54) + "Probe : " + COLOR4 + GET_PROBE + ""
                else:
                    
                    rtnDisplay=rtnDisplay + fcolor.SWhite + str(SN).ljust(8) + FMColor + FrMAC + " " + TMColor + ToMAC + " " + fcolor.BBlue + ToBSSID + " " + COLOR1 + GET_DATAARP.ljust(5) + COLOR2 + GET_DATA86.ljust(5)+ COLOR3 + GET_DATA94.ljust(5)+COLOR4 +  GET_DATA98.ljust(5)+ COLOR5 +  GET_AUTH.ljust(5)+ COLOR3 + GET_DEAUTH.ljust(5) + COLOR6 + GET_DEAUTH_AC.ljust(5) + COLOR7 + GET_ASSOC.ljust(5)+ COLOR1 + GET_DISASSOC.ljust(5) + COLOR2 + GET_REASSOC.ljust(5) + COLOR3 + GET_RTS.ljust(5)+ COLOR4 + GET_CTS.ljust(5)+ COLOR2 + GET_ACK.ljust(5)+ COLOR3 + GET_EAPOL_STD.ljust(5) + COLOR5 + GET_EAPOL_START.ljust(5) + GET_WPS.ljust(5)+ COLOR6 + GET_BEACON.ljust(5)+ COLOR7 + GET_PRQX.ljust(5)+ COLOR1 + GET_PRESP.ljust(5)+ COLOR2 + GET_NULL.ljust(5) + COLOR3 + GET_QOS.ljust(5) + COLOR7  + str(YOURMAC) + "\n"
                    if GET_PROBE!="":
                        if GET_PROBE=="<<Broadcast>>":
                            GET_PROBE=fcolor.SBlack + GET_PROBE
                        rtnDisplay=rtnDisplay + fcolor.SWhite + " ".ljust(54) + "Probe : " + COLOR4 + GET_PROBE + "\n"
                    cCount=str(GET_DATAARP) + "\t" + str(GET_DATA86) + "\t" + str(GET_DATA94) + "\t" + str(GET_DATA98) + "\t" + str(GET_AUTH)  + "\t" + str(GET_DEAUTH) + "\t" + str(GET_DEAUTH_AC) + "\t" + str(GET_ASSOC) + "\t" + str(GET_DISASSOC) + "\t" + str(GET_REASSOC) + "\t" + str(GET_RTS) + "\t" + str(GET_CTS) + "\t" + str(GET_ACK) + "\t" + str(GET_EAPOL_STD) + "\t" + str(GET_EAPOL_START) + "\t" + str(GET_WPS) + "\t" + str(GET_BEACON) + "\t" + str(GET_PRQX) + "\t" + str(GET_PRESP) + "\t" + str(GET_NULL) + "\t" + str(GET_QOS)
                    cCount=str(cCount).replace("-","0")
                    __builtin__.OfInterest_List.append (str(FrMAC) + "\t" + str(ToMAC) + "\t" + str(ToBSSID) + "\t" + str(cCount) + "\t" + str(YOURMAC) + "\t" + str(GET_PROBE))
               
                y += 1;DisplayCt += 1
            x += 1
            if y==20 and usr_resp!="SHOW LIST3_QUIET":
                print TITLE
                y=0
        if usr_resp!="SHOW LIST3_QUIET":
            LineBreak()
        if DisplayCt!=0:
            if usr_resp!="SHOW LIST3_QUIET":
                print fcolor.BWhite + str(DisplayCt) + " records listed. "  + fcolor.SWhite + "[ Total Record : " + str(SN) + " ]"
                if OfInterestSensitive!="" and usr_resp[:10]!="SHOW LIST3":
                    print fcolor.BWhite + "Sr.No. Of Interest (IDS Sensitivity)\t: " + fcolor.BRed + str(OfInterestSensitive)[:-2].replace(",",fcolor.SWhite + "," + fcolor.BRed) + "\t" + fcolor.BGreen + "Use [SHOW LIST3] to filter of interest result."
                if OfInterest!="" and usr_resp[:10]!="SHOW LIST4":
                    print fcolor.BWhite + "Sr.No. Of Interest (Threshold - " + str(__builtin__.THRESHOLD) + ")\t: " + fcolor.BRed + str(OfInterest)[:-2].replace(",",fcolor.SWhite + "," + fcolor.BRed) + "\t" + fcolor.BGreen + "Use [SHOW LIST4] to filter of interest result."
            else:
                if usr_resp=="SHOW LIST3_QUIET":
                    rtnDisplay=rtnDisplay + "\n" + fcolor.BWhite + str(DisplayCt) + " records listed. "  + fcolor.SWhite + "[ Total Record : " + str(SN) + " ]"
        else:
            if usr_resp!="SHOW LIST3_QUIET":
                print fcolor.BWhite + "No record found. " + fcolor.SWhite + "[ Total Record : " + str(SN) + " ]"
        if usr_resp=="SHOW LIST2":
            RECON_CMD=1;
            if len(__builtin__.ANALYSIS_SEARCH)>0:
                DisplayMsg=""
                yc=0
                while yc < len(__builtin__.ANALYSIS_SEARCH):
                    tmpsearch=str(__builtin__.ANALYSIS_SEARCH[yc]).upper()
                    foundloc=FindMACIndex(tmpsearch,ListInfo_BSSID)
                    if foundloc!=-1:
                        OUITxt=DisplayOUIDetail(tmpsearch,fcolor.BCyan)
                        DisplayMsg = DisplayMsg + str(DisplayESSIDDetail(tmpsearch,fcolor.BCyan))
                        DisplayMsg = DisplayMsg + str(OUITxt) 
                        DisplayMsg = DisplayMsg + str(DisplaySSIDDetail(tmpsearch)) + "\n"
                    yc += 1
                if DisplayMsg!="":
                    print DisplayMsg
                DisplayMsg1=""
                DisplayMsg2=""
                yc=0
                while yc < len(tmpMACList):
                    CurrMAC=tmpMACList[yc]
                    xc=0
                    ToDisplay=1
                    while xc < len(__builtin__.ANALYSIS_SEARCH):
                        tmpsearch=str(__builtin__.ANALYSIS_SEARCH[xc]).upper()
                        if CurrMAC==tmpsearch:
                            ToDisplay=0
                        xc += 1
                    if ToDisplay==1:
                        foundloc=FindMACIndex(CurrMAC,ListInfo_BSSID)
                        if foundloc!=-1:
                            OUITxt=DisplayOUIDetail(CurrMAC,fcolor.BCyan)
                            DisplayMsg1 = DisplayMsg1 + str(DisplayESSIDDetail(CurrMAC,fcolor.BCyan))
                            DisplayMsg1 = DisplayMsg1 + str(OUITxt) 
                            DisplayMsg1 = DisplayMsg1 + str(DisplaySSIDDetail(CurrMAC)) + ""
                        else:
                            foundloc=FindMACIndex(CurrMAC,ListInfo_STATION)
                            if foundloc!=-1:
                                MM=CheckContainMyMAC(CurrMAC)
                                if MM==True:
                                    DisplayMsg2 = DisplayMsg2 + fcolor.SRed + "  MAC Addr [ " + fcolor.BGreen + CurrMAC + fcolor.SRed + " ] is a your interface MAC Address.\n"
                                OUITxt=DisplayOUIDetail(CurrMAC,fcolor.BGreen)
                                if ListInfo_CBSSID[foundloc]!="Not Associated":
                                    DisplayMsg2 = DisplayMsg2 + fcolor.SWhite + "  MAC Addr [ " + fcolor.BGreen + CurrMAC + fcolor.SWhite + " ] is a station associated to [ " + fcolor.BPink + ListInfo_CBSSID[foundloc] + fcolor.SWhite + " ]\n"
                                else:
                                    DisplayMsg2 = DisplayMsg2 + fcolor.SWhite + "  MAC Addr [ " + fcolor.BGreen + CurrMAC + fcolor.SWhite + " ] is a station and is not associated.\n"
                                DisplayMsg2 = DisplayMsg2 + str(OUITxt)  + ""
                                if ListInfo_CBSSID[foundloc]!="Not Associated":
                                    OUITxt=DisplayOUIDetail(ListInfo_CBSSID[foundloc],fcolor.BPink)
                                    DisplayMsg2 = DisplayMsg2 + str(DisplayESSIDDetail(ListInfo_CBSSID[foundloc],fcolor.BPink))
                                    DisplayMsg2 = DisplayMsg2 + str(OUITxt) 
                                    DisplayMsg2 = DisplayMsg2 + str(DisplaySSIDDetail(ListInfo_CBSSID[foundloc])) + "\n"
                                else:
                                    DisplayMsg2 = DisplayMsg2 + "\n"
                    yc += 1
                if usr_resp!="SHOW LIST3_QUIET":
                    if DisplayMsg1!="":
                        print DisplayMsg1
                    if DisplayMsg2!="":
                        print DisplayMsg2
    if usr_resp=="SHOW LIST3_QUIET":
        if __builtin__.SHOW_SUSPICIOUS_LISTING=="Yes" and rtnDisplay!="":
            CenterText(fcolor.BGIRed + fcolor.BWhite,"< < <<  SUSPICIOUS ACTIVITY LISTING  >> > >      ")
            print ""
            rtnDisplay=TITLE + "\n" + rtnDisplay
            rtnDisplay=rtnDisplay + "\n" + "Reported : " + str(Now()) 
            print rtnDisplay
            WriteSuspiciousLog(rtnDisplay) 
            __builtin__.MSG_SuspiciousListing=__builtin__.MSG_SuspiciousListing + rtnDisplay + "\n"
            __builtin__.MSG_CombinationLogs=__builtin__.MSG_CombinationLogs + rtnDisplay + "\n"
            BeepSound()
        else:
            if __builtin__.SHOW_SUSPICIOUS_LISTING=="Yes":
                DisplayText=fcolor.SGreen + str(Now()) + "\t- No suspicious activty listing."
                print str(DisplayText)
                WriteSuspiciousLog(DisplayText)
    return rtnDisplay

def SearchFiles(sDir,sExtList,sNameFilter):
    __builtin__.FoundFiles = [fn for fn in os.listdir(sDir) if any([fn.endswith(ext) for ext in sExtList])];
    __builtin__.FoundFiles.sort()
    __builtin__.FoundFiles_Filtered=[]
    if sNameFilter!="":
        F1Filter=sNameFilter[:1]
        F2Filter=sNameFilter[-1:]
        FFilter=str(sNameFilter).replace("*","").upper()
        FFilterLen=len(FFilter)
        x=0
        while x<len(__builtin__.FoundFiles):
            uFoundFile=str(__builtin__.FoundFiles[x]).upper()
            SplitFileDetail(uFoundFile)
            UFoundNameOnly=str(__builtin__.FileNameOnly).upper()
            if F1Filter=="*" and F2Filter=="*" and str(uFoundFile).find(FFilter)!=-1:
                __builtin__.FoundFiles_Filtered.append (__builtin__.FoundFiles[x])
            if F1Filter!="*" and F2Filter=="*" and len(uFoundFile)>FFilterLen and uFoundFile[:FFilterLen]==FFilter:
                __builtin__.FoundFiles_Filtered.append (__builtin__.FoundFiles[x])
            if F1Filter=="*" and F2Filter!="*" and len(uFoundFile)>FFilterLen and uFoundFile[-FFilterLen:]==UFoundNameOnly:
                __builtin__.FoundFiles_Filtered.append (__builtin__.FoundFiles[x])
            x += 1
        __builtin__.FoundFiles=__builtin__.FoundFiles_Filtered

def IsHex(sStr):
    import string
    sStr=str(sStr).replace(":","").replace("*","")
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in sStr)

def DisplayAnalysisMACFilter(WithTAB):
    FILTERSTR=""
    yc=0
    while yc<len(__builtin__.ANALYSIS_MAC):
        FILTERSTR=FILTERSTR + fcolor.BYellow + __builtin__.ANALYSIS_MAC[yc] + StdColor + " / "
        yc += 1
    if FILTERSTR!="":
        FILTERSTR=str(FILTERSTR)[:-3]
    TABSPC=""
    NL=""
    if WithTAB=="1":
        TABSPC=tabspacefull
        NL="\n"
    if WithTAB=="2":
        TABSPC=tabspacefull
    if FILTERSTR!="":
        print TABSPC + fcolor.SGreen + "SEARCH MAC ADDRESS : " + fcolor.BYellow + str(FILTERSTR) + str(NL)

def DisplayAnalysisSearchFilter(WithTAB):
    FILTERSTR=""
    yc=0
    while yc<len(__builtin__.ANALYSIS_SEARCH):
        FILTERSTR=FILTERSTR + fcolor.BYellow + __builtin__.ANALYSIS_SEARCH[yc] + StdColor + " / "
        yc += 1
    if FILTERSTR!="":
        FILTERSTR=str(FILTERSTR)[:-3]
    TABSPC=""
    NL=""
    if WithTAB=="1":
        TABSPC=tabspacefull
        NL="\n"
    if WithTAB=="2":
        TABSPC=tabspacefull
    if FILTERSTR!="":
        print TABSPC + fcolor.SGreen + "CONTAIN FILTER     : " + fcolor.BYellow + str(FILTERSTR) + str(NL)

def DisplayAnalysisIgnoreFilter(WithTAB):
    FILTERSTR=""
    yc=0
    while yc<len(__builtin__.ANALYSIS_IGNORE):
        FILTERSTR=FILTERSTR + fcolor.BYellow + __builtin__.ANALYSIS_IGNORE[yc] + StdColor + " / "
        yc += 1
    if FILTERSTR!="":
        FILTERSTR=str(FILTERSTR)[:-3]
    TABSPC=""
    NL=""
    if WithTAB=="1":
        TABSPC=tabspacefull
        NL="\n"
    if WithTAB=="2":
        TABSPC=tabspacefull
    if FILTERSTR!="":
        print TABSPC + fcolor.SGreen + "HIDE PACKET TYPE   : " + fcolor.BYellow + str(FILTERSTR) + str(NL)

def PacketAnalysis():
    CenterText(fcolor.BBlack + fcolor.BGIWhite,"Interactive Mode - Packet Analysis    ")
    printc ("+", fcolor.BBlue + "Packet Analysis - Interactive","")
    print tabspacefull + StdColor + "This option allow user to search for information on the captured packets on the intrusion module which user can have an insight view and better analysis of these packets. There are also many other options available. Type [HELP] for detail.";print ""
    if len(__builtin__.ANALYSIS_SEARCH)!=0 or len(__builtin__.ANALYSIS_IGNORE)!=0 or len(__builtin__.ANALYSIS_MAC)!=0:
        print tabspacefull + fcolor.BWhite + "Curent Filter Setting"
        DisplayAnalysisMACFilter("2")
        DisplayAnalysisSearchFilter("2")
        DisplayAnalysisIgnoreFilter("2")
        print ""
    ReadCommand()
    LineBreak()
    return
  
 

def TCPDump_ExtractDetail(DataList,rawline):
    x=0
    __builtin__.MAC_TA=""
    __builtin__.MAC_RA=""
    __builtin__.MAC_SA=""
    __builtin__.MAC_DA=""
    __builtin__.MAC_BSSID=""
    __builtin__.SRC_TYPE=""
    __builtin__.DST_TYPE=""
    __builtin__.SRC_MAC=""
    __builtin__.DST_MAC=""
    __builtin__.SRC_MACLoc=""
    __builtin__.DST_MACLoc=""
    __builtin__.PKT_CMD=""
    __builtin__.PKT_SPEED=""
    __builtin__.PKT_FREQ=""
    __builtin__.PKT_STANDARD=""
    __builtin__.PKT_POWER=""
    __builtin__.PKT_ESSID=""
    __builtin__.PKT_PROBE_REQ=""
    __builtin__.PKT_PROBE_RSP=""
    __builtin__.PKT_MBIT=""
    __builtin__.PKT_CHANNEL=""
    __builtin__.PKT_ESS="No"
    lendata=len(DataList)-1
    __builtin__.PKT_CMD=datastr=DataList[lendata] 
    if __builtin__.PKT_CMD=="BA":
        __builtin__.PKT_CMD="Block-Ack"
    if rawline.find("Data IV")!=-1:
        __builtin__.PKT_CMD="DATA"
    while x<len(DataList):
        w=x-1
        y=x+ 1
        if y>lendata:
            y=lendata
        datastr=DataList[x]
        if datastr=="Mb/s":
            __builtin__.PKT_SPEED=DataList[w] + " Mb/s"
        if datastr=="MHz":
            __builtin__.PKT_FREQ=DataList[w] + " MHz"
            __builtin__.PKT_FREQ=str(__builtin__.PKT_FREQ).replace(" MHz","").lstrip().rstrip()
            if __builtin__.PKT_FREQ.isdigit():
                __builtin__.PKT_FREQ=float(__builtin__.PKT_FREQ) /1000
            if DataList[y][:2]=="11":
                __builtin__.PKT_STANDARD=DataList[y].upper()
        if datastr[:1]=="-" and datastr[-2:]=="dB":
            __builtin__.PKT_POWER=datastr.replace("dB","")
        if datastr=="CH:":
            __builtin__.PKT_CHANNEL=DataList[y].replace(",","")
        if datastr=="ESS" or datastr=="ESS,":
            __builtin__.PKT_ESS="Yes"
        if len(DataList[x])==20 or len(DataList[x])==23:
            if datastr[:3]=="TA:":
                __builtin__.MAC_TA=str(DataList[x][3:]).upper()
                __builtin__.SRC_MAC=__builtin__.MAC_TA
            if datastr[:3]=="RA:":
                __builtin__.MAC_RA=str(DataList[x][3:]).upper()
                __builtin__.DST_MAC=__builtin__.MAC_RA
            if datastr[:3]=="SA:":
                __builtin__.MAC_SA=str(DataList[x][3:]).upper()
                __builtin__.SRC_MAC=__builtin__.MAC_SA
            if datastr[:3]=="DA:":
                __builtin__.MAC_DA=str(DataList[x][3:]).upper()
                __builtin__.DST_MAC=__builtin__.MAC_DA
            if datastr[:6]=="BSSID:":
                __builtin__.MAC_BSSID=str(DataList[x][6:]).upper() 
                if __builtin__.SRC_MAC=="":
                    __builtin__.SRC_MAC=__builtin__.MAC_BSSID
        x += 1
    if __builtin__.SRC_MAC!="":
        foundloc=FindMACIndex(__builtin__.SRC_MAC,ListInfo_BSSID)
        if foundloc!=-1:
            __builtin__.SRC_MACLoc=foundloc
            __builtin__.SRC_TYPE="AP"
        foundloc=FindMACIndex(__builtin__.SRC_MAC,ListInfo_STATION)
        if foundloc!=-1:
            __builtin__.SRC_MACLoc=foundloc
            __builtin__.SRC_TYPE="ST"
    if __builtin__.DST_MAC!="":
        foundloc=FindMACIndex(__builtin__.DST_MAC,ListInfo_BSSID)
        if foundloc!=-1:
            __builtin__.DST_MACLoc=foundloc
            __builtin__.DST_TYPE="AP"
        foundloc=FindMACIndex(__builtin__.DST_MAC,ListInfo_STATION)
        if foundloc!=-1:
            __builtin__.DST_MACLoc=foundloc
            __builtin__.DST_TYPE="ST"
    if __builtin__.SRC_MAC=="FF:FF:FF:FF:FF:FF":
        __builtin__.SRC_TYPE="BCAST"
    if __builtin__.DST_MAC=="FF:FF:FF:FF:FF:FF":
        __builtin__.DST_TYPE="BCAST"
    if __builtin__.MAC_BSSID=="":
        if __builtin__.SRC_TYPE=="ST":
            __builtin__.MAC_BSSID=__builtin__.SRC_MAC
        if __builtin__.DST_TYPE=="ST":
            __builtin__.MAC_BSSID=__builtin__.DST_MAC
     
    if rawline.find("Beacon (")!=-1:
        Pos1=rawline.find("Beacon (")+8
        NewLine=str(rawline)[Pos1:]
        Pos2=str(NewLine).find(") ")
        __builtin__.PKT_ESSID=str(NewLine)[:Pos2]
        __builtin__.PKT_CMD="Beacon"
    if rawline.find("Probe_Request (")!=-1:
        Pos1=rawline.find("Probe_Request (")+15
        NewLine=str(rawline)[Pos1:]
        Pos2=str(NewLine).find(") ")
        __builtin__.PKT_PROBE_REQ=str(NewLine)[:Pos2]
        __builtin__.PKT_CMD="Probe_Request"
    if rawline.find("Probe_Response (")!=-1:
        Pos1=rawline.find("Probe_Response (")+16
        NewLine=str(rawline)[Pos1:]
        Pos2=str(NewLine).find(") ")
        __builtin__.PKT_PROBE_RSP=str(NewLine)[:Pos2]
        __builtin__.PKT_CMD="Probe_Response"
    if rawline.find(" Mbit]")!=-1:
        Pos1=rawline.find(" Mbit]") + 6
        NewLine=str(rawline)[:Pos1]
        Pos2=Pos1-60
        if Pos1<1:
            Pos2=1
        NewLine=str(NewLine)[Pos2:]
        Pos2=str(NewLine).find(" [")
        __builtin__.PKT_MBIT=str(NewLine)[Pos2:]
        __builtin__.PKT_MBIT=str(__builtin__.PKT_MBIT).replace("[","").replace("]","").lstrip().rstrip()
    if PKT_ESS=="Yes":
        if SRC_TYPE=="AP":
            foundloc=FindMACIndex(__builtin__.SRC_MAC,ListInfo_BSSID)
            if foundloc!=-1:
                __builtin__.ListInfo_ESS[foundloc]="Yes"
        if DST_TYPE=="AP":
            foundloc=FindMACIndex(__builtin__.DST_MAC,ListInfo_BSSID)
            if foundloc!=-1:
                __builtin__.ListInfo_ESS[foundloc]="Yes"
    if SRC_TYPE=="AP":
        foundloc=FindMACIndex(__builtin__.SRC_MAC,ListInfo_BSSID)
        if foundloc!=-1:
            if __builtin__.PKT_STANDARD!="":
                __builtin__.PKT_STANDARD=__builtin__.PKT_STANDARD.replace("11","")
                Current=str(__builtin__.ListInfo_APStandard[foundloc]).replace("802.11 ","")
                if Current=="-":
                    __builtin__.ListInfo_APStandard[foundloc]="802.11 " + PKT_STANDARD
                else:
                    if Current.find(PKT_STANDARD)==-1:
                        Current=Current + PKT_STANDARD
                        Current=ArrangeStandard(Current)
                        __builtin__.ListInfo_APStandard[foundloc]="802.11 " + Current
            if __builtin__.PKT_CHANNEL!="":
                __builtin__.ListInfo_Channel[foundloc]=str(__builtin__.PKT_CHANNEL)
            if __builtin__.PKT_FREQ!="":
                __builtin__.ListInfo_Freq[foundloc]=str(__builtin__.PKT_FREQ)
            if __builtin__.PKT_ESSID!="":
                __builtin__.ListInfo_ESSID[foundloc]=str(__builtin__.PKT_ESSID)
    if SRC_TYPE=="ST":
        foundloc=FindMACIndex(__builtin__.SRC_MAC,ListInfo_STATION)
        if foundloc!=-1:
            if __builtin__.PKT_STANDARD!="":
                __builtin__.PKT_STANDARD=__builtin__.PKT_STANDARD.replace("11","")
                Current=str(__builtin__.ListInfo_STNStandard[foundloc]).replace("802.11 ","")
                if Current=="-":
                    __builtin__.ListInfo_STNStandard[foundloc]="802.11 " + PKT_STANDARD
                else:
                    if Current.find(PKT_STANDARD)==-1:
                        Current=Current + PKT_STANDARD
                        Current=ArrangeStandard(Current)
                        __builtin__.ListInfo_STNStandard[foundloc]="802.11 " + Current
#

def GetSignalRange(SignalQ):
    SignalQ=str(SignalQ).replace("dB","")
    CQualityPercent=0
    CQRange=fcolor.SBlack + "Unknown"
    CSignal=SignalQ
    if len(CSignal)>1 and len(CSignal)<4:
        CSignal=CSignal.replace("-","")
        if CSignal.isdigit()==True:
            CSignal="-" + str(CSignal)
            CQualityPercent=int(100 + int(CSignal))
            if CQualityPercent>=99 or CQualityPercent==0:  
                CQRange=fcolor.SBlack + "Unknown"
            if CQualityPercent>=70 and CQualityPercent<=98:
                CQRange=fcolor.SGreen + "V.Good"
            if CQualityPercent>=50 and CQualityPercent<=69:
                CQRange=fcolor.SGreen + "Good"
            if CQualityPercent>=26 and CQualityPercent<=49:
                CQRange=fcolor.SYellow + "Average"
            if CQualityPercent>=1 and CQualityPercent<=25:
               CQRange=fcolor.SRed + "Poor"
    return CQRange

def ArrangeStandard(Standard):
    NewStandard=""
    if Standard.find("A")!=-1:
        NewStandard=NewStandard + "A"
    if Standard.find("B")!=-1:
        NewStandard=NewStandard + "B"
    if Standard.find("G")!=-1:
        NewStandard=NewStandard + "G"
    if Standard.find("N")!=-1:
        NewStandard=NewStandard + "N"
    return NewStandard

def Percent(val, digits):
    val *= 10 ** (digits + 2)
    return '{1:.{0}f} %'.format(digits, floor(val) / 10 ** digits)

def CheckContainMyMAC(StrVal):
    if str(StrVal).find(__builtin__.SELECTED_MON_MAC)!=-1:
        return True
    if str(StrVal).find(__builtin__.SELECTED_MANIFACE_MAC)!=-1:
        return True
    if str(StrVal).find(__builtin__.SELECTED_IFACE_MAC)!=-1:
        return True
    return False

def ClearTSharkData():
    __builtin__.List_ANALYZER=[]
    __builtin__.List_FrMAC=[]
    __builtin__.List_ToMAC=[]
    __builtin__.List_BSSID=[]
    __builtin__.List_Auth=[]
    __builtin__.List_Deauth=[]
    __builtin__.List_Deauth_AC=[]
    __builtin__.List_Assoc=[]
    __builtin__.List_Reassoc=[]
    __builtin__.List_Disassoc=[]
    __builtin__.List_RTS=[]
    __builtin__.List_CTS=[]
    __builtin__.List_ACK=[]
    __builtin__.List_EAPOL_STD=[]
    __builtin__.List_EAPOL_START=[]
    __builtin__.List_WPS=[]
    __builtin__.List_Beacon=[]
    __builtin__.List_SSID=[]
    __builtin__.List_SSIDCT=[]
    __builtin__.List_IsAP=[]
    __builtin__.List_PResp=[]
    __builtin__.List_PReq=[]
    __builtin__.List_ProbeName=[]
    __builtin__.List_NULL=[]
    __builtin__.List_QOS=[]
    __builtin__.List_Data86=[]
    __builtin__.List_DataARP=[]
    __builtin__.List_Data98=[]
    __builtin__.List_Data94=[]

def AddTSharkData(DataList):
    DT_FrMAC="";DT_ToMAC="";DT_Type="";DT_LEN="";DT_CMD="";DT_FLAGS="";DT_SSID="";DT_SN="";DT_FN="";DT_BI="";DT_BSSID="";
    DT_FrMAC=str(DataList[13]).upper()		# SA
    DT_ToMAC=str(DataList[14]).upper()		# DA
    DT_BSSID=str(DataList[17]).upper()		# BSSID
    DT_SA=str(DataList[13]).upper()
    DT_DA=str(DataList[14]).upper()
    DT_RA=str(DataList[15]).upper()
    DT_TA=str(DataList[16]).upper()
    DT_Type=DataList[25]   # 802.11
    DT_LEN=DataList[18]
    DT_NTYPE=str(DataList[25]).upper()
    DT_CMD=str(DataList[26]).upper()
    DT_FLAGS=str(DataList[27]).upper()
    DT_SSID=str(DataList[24])
    if DT_SSID[-11:]=="<Malformed>":
        DT_SSID=""
    if str(DT_SSID).find("[Malformed")!=-1:
        DT_SSID=""
    if DT_FrMAC=="XX:XX:XX:XX:XX:XX" or DT_ToMAC=="XX:XX:XX:XX:XX:XX":
        return
    if DT_NTYPE!="802.11" and DT_NTYPE!="EAP_REQ" and DT_NTYPE!="EAP_RSP" and DT_NTYPE!="EAPOL" and DT_NTYPE!="EAP":
        return
    x=0
    tmpANALYZER=[]
    Skip=0
    while x<len(__builtin__.List_ANALYZER):
        tmpANALYZER=__builtin__.List_ANALYZER[x].split("\t")
        if tmpANALYZER[0]==DT_FrMAC and tmpANALYZER[1]==DT_ToMAC  and tmpANALYZER[2]==DT_BSSID and tmpANALYZER[3]==DT_NTYPE and tmpANALYZER[4]==DT_CMD and tmpANALYZER[5]==DT_LEN and tmpANALYZER[6]==DT_FLAGS:
            DTA_CT=tmpANALYZER[7]
            DTA_CT=int(DTA_CT)+1
            ALZ_DATA=str(DT_FrMAC) + "\t" + str(DT_ToMAC) + "\t" + str(DT_BSSID) + "\t" + str(DT_NTYPE) + "\t" + str(DT_CMD) + "\t" + str(DT_LEN) + "\t" + str(DT_FLAGS) + "\t" + str(DTA_CT)
            __builtin__.List_ANALYZER[x]=ALZ_DATA
            Skip=1
        x += 1
    if Skip==0:
        ALZ_DATA=str(DT_FrMAC) + "\t" + str(DT_ToMAC) + "\t" + str(DT_BSSID) + "\t" + str(DT_NTYPE) + "\t" + str(DT_CMD) + "\t" + str(DT_LEN) + "\t" + str(DT_FLAGS) + "\t" + "1"
        __builtin__.List_ANALYZER.append (ALZ_DATA)
       
    x=0
    ExistList=-1
    FirstHit=-1
    while x<len(__builtin__.List_FrMAC):
        if __builtin__.List_FrMAC[x]==DT_FrMAC and str(__builtin__.List_ToMAC[x])[:3]=="FF:" and str(__builtin__.List_ToMAC[x])!="FF:FF:FF:FF:FF:FF"  and DT_ToMAC[:3]=="FF:"  and DT_ToMAC!="FF:FF:FF:FF:FF:FF" and __builtin__.List_BSSID[x]==DT_BSSID:
            FirstHit=x
        if __builtin__.List_FrMAC[x]==DT_FrMAC and __builtin__.List_ToMAC[x]==DT_ToMAC  and __builtin__.List_BSSID[x]==DT_BSSID:
            ExistList=x
            x=len(__builtin__.List_FrMAC)
        x += 1
    if ExistList==-1 and FirstHit!=-1:
        ExistList=FirstHit
    GET_DATAARP="0"
    GET_AUTH="0"
    GET_DEAUTH="0"
    GET_DEAUTH_AC="0"
    GET_DISASSOC="0"
    GET_REASSOC="0"
    GET_ASSOC="0"
    GET_RTS="0"
    GET_CTS="0"
    GET_ACK="0"
    GET_EAPOL_STD="0"
    GET_EAPOL_START="0"
    GET_WPS="0"
    GET_BEACON="0"
    GET_PRESP="0"
    GET_PRQX="0"
    GET_NULL="0"
    GET_QOS="0"
    GET_DATA86="0"
    GET_DATA98="0"
    GET_DATA94="0"
    PROBE_SSID=DT_SSID
    AESSID=DT_SSID
    if DT_CMD=="DATA":
        if DT_ToMAC=="FF:FF:FF:FF:FF:FF" and DT_FrMAC!=DT_BSSID:
            GET_DATAARP="1"
    if DT_CMD=="DATA":                
        if DT_LEN=="71" or DT_LEN=="73":
            if DT_ToMAC[:9]=="01:00:5E:":
                GET_DATAARP="1"
    if DT_CMD=="DATA":                 
        if DT_LEN=="98" and DT_FLAGS==".P....F.C":
            GET_DATA98="1"
    if DT_CMD=="DATA" and DT_LEN.isdigit()==True:
        if int(DT_LEN)<90 and DT_FLAGS==".P....F.C" and DT_ToMAC[:3]=="FF:":
            GET_DATA98="1"
    if DT_CMD=="DATA":                  
        if DT_LEN=="94" and DT_FLAGS==".P...M.TC":
            GET_DATA94="1"
    if DT_CMD=="DATA" and DT_FLAGS==".P.....TC":                 
        if DT_FrMAC[9:]==":00:00:00":
            GET_DATA86="1"
    if DT_CMD=="DATA":                
        if DT_ToMAC[:9]=="FF:F3:18:":
            GET_DATAARP="1"
    if DT_CMD=="QOS_DATA" and DT_FrMAC[:6]==DT_ToMAC[:6] and DT_FrMAC[9:-2:]=="DE:AD:" and DT_ToMAC[:9]!="FF:FF:FF:" and DT_FLAGS==".P....F.C":
         GET_QOS="1"
    if DT_CMD[:14]=="AUTHENTICATION":
        GET_AUTH="1"
    if DT_CMD[:16]=="DEAUTHENTICATION":
        if DT_FLAGS=="........C":
            GET_DEAUTH_AC="1"
        else:
            GET_DEAUTH="1"
    if DT_CMD[:12]=="DISASSOCIATE":
        GET_DISASSOC="1"
    if DT_CMD[:11]=="ASSOCIATION":
        GET_ASSOC="1"
    if DT_CMD[:13]=="REASSOCIATION":
        GET_REASSOC="1"
    if DT_CMD=="REQUEST-TO-SEND":
        GET_RTS="1"
    if DT_CMD=="CLEAR-TO-SEND":
        GET_CTS="1"
    if DT_CMD=="ACKNOWLEDGEMENT":
        GET_ACK="1"
    if DT_CMD=="BEACON":
        GET_BEACON="1"
    if DT_NTYPE=="EAPOL" and DT_CMD!="START":
        GET_EAPOL_STD="1"
    if DT_NTYPE=="EAPOL" and DT_CMD=="START":
        GET_EAPOL_START="1"
    if DT_NTYPE=="EAP_REQ" or DT_NTYPE=="EAP_RSP":
        GET_WPS="1"
    if DT_CMD=="PROBE_RESPONSE":
        GET_PRESP="1"
    if DT_CMD=="PROBE_REQUEST":
        GET_PRQX="1"
    if DT_CMD=="NULL_FUNCTION":
        GET_NULL="1"
    if ExistList==-1:
        __builtin__.List_FrMAC.append (DT_FrMAC)
        __builtin__.List_ToMAC.append (DT_ToMAC)
        __builtin__.List_BSSID.append (DT_BSSID)
        __builtin__.List_DataARP.append(str(GET_DATAARP))
        __builtin__.List_Data86.append(str(GET_DATA86))
        __builtin__.List_Data98.append(str(GET_DATA98))
        __builtin__.List_Data94.append(str(GET_DATA94))
        __builtin__.List_Auth.append(str(GET_AUTH))
        __builtin__.List_Deauth.append(str(GET_DEAUTH))
        __builtin__.List_Deauth_AC.append(str(GET_DEAUTH_AC))
        __builtin__.List_Assoc.append(str(GET_ASSOC))
        __builtin__.List_Reassoc.append(str(GET_REASSOC))
        __builtin__.List_Disassoc.append(str(GET_DISASSOC))
        __builtin__.List_RTS.append(str(GET_RTS))
        __builtin__.List_CTS.append(str(GET_CTS))
        __builtin__.List_ACK.append(str(GET_ACK))
        __builtin__.List_EAPOL_STD.append(str(GET_EAPOL_STD))
        __builtin__.List_EAPOL_START.append(str(GET_EAPOL_START))
        __builtin__.List_WPS.append(str(GET_WPS))
        __builtin__.List_NULL.append(str(GET_NULL))
        __builtin__.List_QOS.append(str(GET_QOS))
        __builtin__.List_Beacon.append(str(GET_BEACON))
        __builtin__.List_PResp.append(str(GET_PRESP))
        __builtin__.List_PReq.append(str(GET_PRQX))
        __builtin__.List_SSID.append(str(DT_SSID) + ", ")
        __builtin__.List_ProbeName.append(str(PROBE_SSID) + " / ")
        if AESSID!="":
            __builtin__.List_IsAP.append("Yes")
        else:
            __builtin__.List_IsAP.append("No")
    else:
        __builtin__.ANALYSE_DATA="TSHARK"
        GET_DATAARP=__builtin__.List_DataARP[ExistList]
        GET_DATA86=__builtin__.List_Data86[ExistList]
        GET_DATA98=__builtin__.List_Data98[ExistList]
        GET_DATA94=__builtin__.List_Data94[ExistList]
        GET_AUTH=__builtin__.List_Auth[ExistList]
        GET_DEAUTH=__builtin__.List_Deauth[ExistList]
        GET_DEAUTH_AC=__builtin__.List_Deauth_AC[ExistList]
        GET_ASSOC=__builtin__.List_Assoc[ExistList]
        GET_REASSOC=__builtin__.List_Reassoc[ExistList]
        GET_DISASSOC=__builtin__.List_Disassoc[ExistList]
        GET_RTS=__builtin__.List_RTS[ExistList]
        GET_CTS=__builtin__.List_CTS[ExistList]
        GET_ACK=__builtin__.List_ACK[ExistList]
        GET_EAPOL_STD=__builtin__.List_EAPOL_STD[ExistList]
        GET_EAPOL_START=__builtin__.List_EAPOL_START[ExistList]
        GET_WPS=__builtin__.List_WPS[ExistList]
        GET_BEACON=__builtin__.List_Beacon[ExistList]
        GET_PRESP=__builtin__.List_PResp[ExistList]
        GET_PRQX=__builtin__.List_PReq[ExistList]
        GET_NULL=__builtin__.List_NULL[ExistList]
        GET_QOS=__builtin__.List_QOS[ExistList]
        SSID_List=[]
        if __builtin__.List_SSID[ExistList]!="":
            List_SSIDS=str(__builtin__.List_SSID[ExistList])
            SSID_List=List_SSIDS.split(", ")
        ProbeName_List=[]
        if __builtin__.List_ProbeName[ExistList]!="":
            List_ProbeNameS=str(__builtin__.List_ProbeName[ExistList])
            ProbeName_List=List_ProbeNameS.split(" / ")
        if DT_SSID!="":
            __builtin__.List_IsAP[ExistList]="Yes"
        
        lSSID=len(SSID_List)
        lsid=0
        FoundSSID="0"
        if lSSID!=0 and DT_SSID!="":
            while lsid<lSSID:
                if SSID_List[lsid]!="" and SSID_List[lsid]==str(DT_SSID):
                    FoundSSID="1"
                    lsid=lSSID
                lsid=lsid+1
            if FoundSSID=="0":
                if __builtin__.List_SSID[ExistList]==", ":
                    __builtin__.List_SSID[ExistList]=""
                if DT_SSID!="Broadcast":
                    __builtin__.List_SSID[ExistList]=__builtin__.List_SSID[ExistList] + str(DT_SSID) + ", "
        lSSID=len(ProbeName_List)
        lsid=0
        FoundProbeName="0"
        if lSSID!=0 and PROBE_SSID!="":
            while lsid<lSSID:
                if ProbeName_List[lsid]!="" and ProbeName_List[lsid]==str(PROBE_SSID):
                    FoundProbeName="1"
                    lsid=lSSID
                lsid=lsid+1
            if FoundProbeName=="0":
                if __builtin__.List_ProbeName[ExistList]==" / ":
                    __builtin__.List_ProbeName[ExistList]=""
                __builtin__.List_ProbeName[ExistList]=__builtin__.List_ProbeName[ExistList] + str(PROBE_SSID) + " / "
        if DT_CMD=="DATA" and DT_LEN=="98" and DT_FLAGS==".P....F.C":               # chopchop ??
            GET_DATA98=str(int(GET_DATA98) + 1)
        if DT_CMD=="DATA" and DT_LEN.isdigit()==True and int(DT_LEN)<90 and DT_FLAGS==".P.....TC":
            if DT_ToMAC[:3]=="FF:":
                GET_DATA98=str(int(GET_DATA98) + 1)
        if DT_CMD=="DATA" and DT_LEN=="94" and DT_FLAGS==".P...M.TC":               # fragment PRGA
            GET_DATA94=str(int(GET_DATA94) + 1)
 
        if DT_CMD=="DATA":
            if DT_LEN=="71" or DT_LEN=="73":
                if DT_ToMAC[:9]=="01:00:5E:":
                    GET_DATAARP=str(int(GET_DATAARP) + 1)
        if DT_CMD=="DATA"                                              :# ARP Broadcast
            if DT_DA[:9]=="FF:FF:FF:" and DT_FrMAC!=DT_BSSID:
                GET_DATAARP=str(int(GET_DATAARP) + 1)
        if DT_CMD=="DATA" and DT_FLAGS==".P.....TC":               # MDK mICHAEL SHUTDOWN EXPLOIT (TKIP)
             if DT_FrMAC[9:]=="00:00:00":
               GET_DATA86=str(int(GET_DATA86) + 1)
        if DT_CMD[:14]=="AUTHENTICATION":
            GET_AUTH=str(int( GET_AUTH) + 1)
        if DT_CMD[:16]=="DEAUTHENTICATION":
            if DT_FLAGS=="........C":
                GET_DEAUTH_AC=str(int(GET_DEAUTH_AC) + 1)
            else:
                GET_DEAUTH=str(int(GET_DEAUTH) + 1)
        if DT_CMD[:12]=="DISASSOCIATE":
            GET_DISASSOC=str(int(GET_DISASSOC) + 1)
        if DT_CMD[:11]=="ASSOCIATION":
            GET_ASSOC=str(int(GET_ASSOC) + 1)
        if DT_CMD[:13]=="REASSOCIATION":
            GET_REASSOC=str(int(GET_REASSOC) + 1)
        if DT_CMD=="REQUEST-TO-SEND":
            GET_RTS=str(int(GET_RTS) + 1)
        if DT_CMD=="CLEAR-TO-SEND":
            GET_CTS=str(int(GET_CTS) + 1)
        if DT_CMD=="ACKNOWLEDGEMENT":
            GET_ACK=str(int(GET_ACK) + 1)
        if DT_NTYPE=="EAPOL" and DT_CMD!="START":
            GET_EAPOL_STD=str(int(GET_EAPOL_STD) + 1)
        if DT_NTYPE=="EAPOL" and DT_CMD=="START":
            GET_EAPOL_START=str(int(GET_EAPOL_START) + 1)
        if DT_NTYPE=="EAP_REQ" or DT_NTYPE=="EAP_RSP":
            GET_WPS=str(int(GET_WPS) + 1)
        if DT_CMD=="BEACON":
            GET_BEACON=str(int(GET_BEACON) + 1)
        if DT_CMD=="PROBE_RESPONSE":
            GET_PRESP=str(int(GET_PRESP) + 1)
        if DT_CMD=="PROBE_REQUEST":
            GET_PRQX=str(int(GET_PRQX) + 1)
        if DT_CMD=="NULL_FUNCTION":
            GET_NULL=str(int(GET_NULL) + 1)
        if DT_CMD=="QOS_DATA" and DT_FrMAC[:6]==DT_ToMAC[:6] and DT_FrMAC[9:-2:]=="DE:AD:" and DT_ToMAC[:9]!="FF:FF:FF:" and DT_FLAGS==".P....F.C":
            GET_QOS=str(int(GET_QOS) + 1)
        __builtin__.List_DataARP[ExistList]=GET_DATAARP
        __builtin__.List_Data86[ExistList]=GET_DATA86
        __builtin__.List_Data98[ExistList]=GET_DATA98
        __builtin__.List_Data94[ExistList]=GET_DATA94
        __builtin__.List_Auth[ExistList]=GET_AUTH
        __builtin__.List_Deauth[ExistList]=GET_DEAUTH
        __builtin__.List_Deauth_AC[ExistList]=GET_DEAUTH_AC
        __builtin__.List_Assoc[ExistList]=GET_ASSOC
        __builtin__.List_Reassoc[ExistList]=GET_REASSOC
        __builtin__.List_Disassoc[ExistList]=GET_DISASSOC
        __builtin__.List_RTS[ExistList]=GET_RTS
        __builtin__.List_CTS[ExistList]=GET_CTS
        __builtin__.List_ACK[ExistList]=GET_ACK
        __builtin__.List_EAPOL_STD[ExistList]=GET_EAPOL_STD
        __builtin__.List_EAPOL_START[ExistList]=GET_EAPOL_START
        __builtin__.List_WPS[ExistList]=GET_WPS
        __builtin__.List_Beacon[ExistList]=GET_BEACON
        __builtin__.List_PResp[ExistList]=GET_PRESP
        __builtin__.List_PReq[ExistList]=GET_PRQX
        __builtin__.List_NULL[ExistList]=GET_NULL
        __builtin__.List_QOS[ExistList]=GET_QOS
        if DT_SSID!="" and __builtin__.List_SSID[ExistList]=="":
            __builtin__.List_SSID[ExistList]=DT_SSID + " / "
            __builtin__.List_IsAP[ExistList]="Yes"
        if PROBE_SSID!="" and __builtin__.List_ProbeName[ExistList]=="":
            __builtin__.List_ProbeName[ExistList]=PROBE_SSID + " / "
        if AESSID!="":
            __builtin__.List_IsAP[ExistList]="Yes"
    ExistList=-1

def AnalyseTShark(DisplayTitle):
    spacing="" #tabspacefull
    RecCt=0;linecount=0;lineblock=0
    ClearTSharkData()
    if IsFileDirExist(__builtin__.TSharkFileBak2)=="F":
        ColorChange=0
        if DisplayTitle=="1":
            CenterText(fcolor.BGICyan + fcolor.BBlack,"< < <<  CONVERTED TSHARK FRAMES DATA   >> > >      ");print ""
            DisplayAnalysisFilters();print ""
        if __builtin__.SHOWRESULT==3:
            Result=GetFileLine(__builtin__.TSharkFileBak2,"1")
            printl (spacing + fcolor.SGreen + "Analysing Packets...TShark","0","")
        with open(TSharkFileBak2,"r") as f:
            for line in f:
                if __builtin__.SHOWRESULT==3 and lineblock==100:
                    completed=Percent(linecount / float(__builtin__.TotalLine),2)
                    printl (spacing + fcolor.SGreen + "Analysing Packets...TShark - " + str(completed),"0","")
                    lineblock=0
                tmplist=[]
                line=line.replace("\n","").replace("\r","").replace("signal antenna ","")
                line=line.replace("             -> ","xx:xx:xx:xx:xx:xx -> ").replace("->              ","-> xx:xx:xx:xx:xx:xx ").replace(" -> "," ").replace(", "," ").replace("  "," ").replace("  "," ")
                line=line.replace("Beacon frame","Beacon").replace("QoS Null function (No data)","QoS_Null").replace("QoS Data","QoS_Data").replace("Probe Request","Probe_Request").replace("Probe Response","Probe_Response").replace(" (RA)","").replace(" (TA)","").replace("802.11 Block Ack","Block-Ack").replace("Fragmented IEEE 802.11 frame","Fragmented_Frame").replace("Unrecognized (Reserved frame)","Unrecognized").replace("","").replace(" (No data)","").replace(" (Control-frame)","").replace("Association Response","Association_Response").replace("Association Request","Association_Request").replace("Null function","Null_Function").replace(" (Reserved frame)","").replace("Measurement Pilot","Measurement_Pilot").replace(" (BSSID)","").replace("Action No Ack","ActionNoAck").replace("QOS_DATA + CF-ACKNOWLEDGEMENT","QoS_Data+CF-Ack").replace("QoS_Data + CF-Poll","QoS_Data+CF-Poll").replace("Reassociation Request","Reassociation_Request").replace("Block-Ack Req","Block-Ack-Req").replace("","").replace("","").replace("","").replace("  "," ").replace("  "," ").replace("","").replace("","").replace("","").replace("","").replace("","").replace("  "," ").replace("  "," ")
                line=line + "\t.\t.\t.\t.\t."
                line=str(line).lstrip().rstrip()
                tmplist=line.split("\t")
                AddTSharkData(tmplist)
                
                DT_FN=str(tmplist[0]).upper()
                DT_FrMAC=str(tmplist[13]).upper()
                DT_ToMAC=str(tmplist[14]).upper()
                DT_BSSID=str(tmplist[17]).upper()
                DT_Type=tmplist[24]   # 802.11
                DT_DURATION=tmplist[3]
                DT_FLEN=tmplist[18]
                DT_CMD=str(tmplist[26])  #.upper()
                DT_NTYPE=str(tmplist[25])  #.upper()
                DT_FLAGS=str(tmplist[27])
                DT_SSID=str(tmplist[24])
                DT_DATARATE=str(tmplist[8])
                DT_SIGNAL=str(tmplist[9]).replace("dB","")
#
                if len(tmplist)>10 and len(DT_FrMAC)==17:
                    linecount += 1;lineblock += 1
                    ToDisplay=1
                    tmplistu=str(tmplist).upper()
                    PKTCMD=str(tmplist[26]).upper()
                    ToDisplay=1
                    FoundMatch=0
                    if len(__builtin__.ANALYSIS_SEARCH)>0:
                        yc=0
                        FoundMatch=0
                        while yc < len(__builtin__.ANALYSIS_SEARCH):
                            tmpsearch=str(__builtin__.ANALYSIS_SEARCH[yc]).upper()
                            if str(tmplistu).find(tmpsearch)!=-1:
                                FoundMatch += 1
                            yc += 1
                        if FoundMatch>0:
                            ToDisplay=1
                        else:
                            ToDisplay=0
                    if len(__builtin__.ANALYSIS_MAC)>0 and ToDisplay==1:
                        yc=0
                        FoundMatch=0
                        while yc < len(__builtin__.ANALYSIS_MAC):
                            tmpsearch=str(__builtin__.ANALYSIS_MAC[yc]).upper()
                            if str(tmplistu).find(tmpsearch)!=-1:
                                FoundMatch += 1
                            yc += 1
                        if FoundMatch>0:
                            ToDisplay=1
                        else:
                            ToDisplay=0
                    if len(__builtin__.ANALYSIS_IGNORE)>0 and ToDisplay==1:
                        yc=0
                        while yc < len(__builtin__.ANALYSIS_IGNORE):
                            tmpsearch=str(__builtin__.ANALYSIS_IGNORE[yc]).upper()
                            if str(PKTCMD)==tmpsearch:
                                ToDisplay=0
                            yc += 1
                    DT_SSID=str(tmplist[24])
                        
                    
                    
                    if ToDisplay==1:
                        RecCt += 1
                        ColorChange += 1
                        if ColorChange==1:
                            ColorC=fcolor.SWhite
                        if ColorChange==2:
                            ColorC=fcolor.SGreen
                            ColorChange=0
                        YOURMAC=""
                        if CheckContainMyMAC(line)==True:
                            ColorC=fcolor.SPink
                            YOURMAC=fcolor.BPink + " [YOUR MAC]"
                            
       
                        UDT_CMD=str(DT_CMD).upper()
                        if UDT_CMD.find("ASSOC")!=-1 or UDT_CMD.find("AUTH")!=-1:
                            ColorC=fcolor.SRed
                        NLine=str(DT_FN).ljust(9) + str(DT_DATARATE).ljust(10) + str(DT_SIGNAL).ljust(5) + str(DT_FrMAC).ljust(20) + str(DT_ToMAC).ljust(20) + str(DT_BSSID).ljust(20) + DT_DURATION.ljust(8) + DT_FLEN.ljust(8) + DT_NTYPE.ljust(10) + DT_CMD.ljust(25) + DT_FLAGS.ljust(12) + str(DT_SSID) + str(YOURMAC)
                        if __builtin__.SHOWRESULT==1:
                            if RecCt==1:
                                print fcolor.BBlue + "Sr.No.".ljust(9) + "Rate".ljust(10) + "Pwr".ljust(5) + "Source MAC".ljust(20) + "Destination MAC".ljust(20) + "BSSID".ljust(20) + "DUR".ljust(8) + "LEN".ljust(8) + "Protocol".ljust(10) + "Frame Type".ljust(25) + "Flags".ljust(12) + "ESSID"
                            print ColorC + str(NLine)
                        if __builtin__.SHOWRESULT==2:
                            print fcolor.BGreen + "" + ColorC + str(tmplist)
                        if __builtin__.SHOWRESULT==3 or __builtin__.SHOWRESULT==4:
                            open(__builtin__.SavedTSharkFile,"a+b").write(line + "\n")
        if __builtin__.SHOWRESULT!=3 and __builtin__.SHOWRESULT!=4:
            print ""
            if RecCt!=0:
                print fcolor.BWhite + str(RecCt) + " records listed / " + str(int(linecount)-int(RecCt)) + " records ignored."
                DisplayAnalysisFilters()
            else:
                print fcolor.BWhite + "No record found. " + str(linecount) + " data read."
                DisplayAnalysisFilters()
        else:
            if __builtin__.SHOWRESULT!=4:
                printl (spacing + fcolor.SGreen + "Analysing Packets...TShark - Completed.","0","")
    else:
        printl (fcolor.BRed + "Packet file - " + fcolor.BYellow + __builtin__.TCPDumpFileBak + fcolor.BRed + " not found !","0","")

def AnalyseTCPDump(DisplayTitle):
    spacing="" # tabspacefull
    RecCt=0;linecount=0;lineblock=0;
    if IsFileDirExist(__builtin__.TCPDumpFileBak)=="F":
        ColorChange=0
        if DisplayTitle=="1":
            CenterText(fcolor.BGICyan + fcolor.BBlack,"< < <<  CONVERTED TCPDUMP FRAMES DATA   >> > >      ");print ""
            DisplayAnalysisFilters();print ""
        if __builtin__.SHOWRESULT==3:
            Result=GetFileLine(__builtin__.TCPDumpFileBak,"1")
            printl (spacing + fcolor.SGreen + "Analysing Packets...TCPDump","0","")
        with open(TCPDumpFileBak,"r") as f:
            for line in f:
                linecount += 1;lineblock += 1
                if __builtin__.SHOWRESULT==3 and lineblock==100:
                    completed=Percent(linecount / float(__builtin__.TotalLine),2)
                    printl (spacing + fcolor.SGreen + "Analysing Packets...TCPDump - " + str(completed),"0","")
                    lineblock=0
                tmplist=[]
                line=line.replace("\n","").replace("\r","").replace("signal antenna ","Signal_Antenna:")
                line=line.replace("Beacon frame","Beacon").replace("QoS Null function (No data)","QoS_Null").replace("QoS Data","QoS_Data").replace("Probe Request","Probe_Request").replace("Probe Response","Probe_Response").replace(" (RA)","").replace(" (TA)","").replace("802.11 Block Ack","Block-Ack").replace("Fragmented IEEE 802.11 frame","Fragmented_Frame").replace("Unrecognized (Reserved frame)","Unrecognized").replace("","").replace(" (No data)","").replace(" (Control-frame)","").replace("Association Response","Association_Response").replace("Association Request","Association_Request").replace("Null function","Null_Function").replace(" (Reserved frame)","").replace("Measurement Pilot","Measurement_Pilot").replace(" (BSSID)","").replace("Action No Ack","ActionNoAck").replace("Acknowledgment","Acknowledgement").replace(" Mb/s ","Mb/s ").replace(" MHz ","MHz ").replace("WEP Encrypted","WEP_Encrypted").replace("Data IV:","DataIV:").replace("GI More Data Retry Strictly Ordered","GI_More_Data_Retry_Strictly_Ordered").replace("CF +QoS","CF+QoS").replace(" Pad "," Pad:").replace(" KeyID "," KeyID:").replace(" Strictly Ordered ","_Strictly_Ordered_").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("","").replace("  "," ").replace("  "," ")
                tmplist=line.split(" ")
                lineu=str(line).upper()
                tmplistu=str(tmplist).upper()
                TCPDump_ExtractDetail(tmplist,line)
                ToDisplay=1
                if len(__builtin__.ANALYSIS_SEARCH)>0:
                    yc=0
                    FoundMatch=0
                    while yc < len(__builtin__.ANALYSIS_SEARCH):
                        tmpsearch=str(__builtin__.ANALYSIS_SEARCH[yc]).upper()
                        if str(tmplistu).find(tmpsearch)!=-1:
                            FoundMatch += 1
                        yc += 1
                    if FoundMatch>0:
                        ToDisplay=1
                    else:
                        ToDisplay=0
                if len(__builtin__.ANALYSIS_MAC)>0 and ToDisplay==1:
                    yc=0
                    FoundMatch=0
                    while yc < len(__builtin__.ANALYSIS_MAC):
                        tmpsearch=str(__builtin__.ANALYSIS_MAC[yc]).upper()
                        if str(tmplistu).find(tmpsearch)!=-1:
                            FoundMatch += 1
                        yc += 1
                    if FoundMatch>0:
                        ToDisplay=1
                    else:
                        ToDisplay=0
                if len(__builtin__.ANALYSIS_IGNORE)>0 and ToDisplay==1:
                    yc=0
                    while yc < len(__builtin__.ANALYSIS_IGNORE):
                        tmpsearch=str(__builtin__.ANALYSIS_IGNORE[yc]).upper()
                        if __builtin__.SHOWRESULT==1 or __builtin__.SHOWRESULT==2 or __builtin__.SHOWRESULT==3: 
                            if str(lineu).find(tmpsearch)!=-1:
                                ToDisplay=0
                        yc += 1
                if ToDisplay==1:
                    RecCt += 1
                    if __builtin__.SHOWRESULT==1:
                        ColorChange += 1
                        if ColorChange==1:
                            ColorC=fcolor.SWhite
                        if ColorChange==2:
                            ColorC=fcolor.SGreen
                            ColorChange=0
                        YOURMAC=""
                        if CheckContainMyMAC(line)==True:
                            YOURMAC=fcolor.BPink + " [YOUR MAC]"
                            ColorC=fcolor.SPink
                        if tmplistu.find("ASSOC")!=-1 or tmplistu.find("AUTH")!=-1:
                            ColorC = fcolor.SRed
                        print ColorC + line + str(YOURMAC)
                    if __builtin__.SHOWRESULT==2:
                        if CheckContainMyMAC(line)==True:
                            print fcolor.BRed + "Found Your MAC Address"
                        print fcolor.SGreen + str(tmplist)
                        print fcolor.SWhite + "SRC MAC   : " + fcolor.BGreen + str(__builtin__.SRC_MAC) + fcolor.SWhite + "  [" + fcolor.BGreen + str(__builtin__.SRC_MACLoc) + fcolor.SWhite + "]\t\tType : " + fcolor.BGreen + str(__builtin__.SRC_TYPE)
                        print fcolor.SWhite + "DST MAC   : " + fcolor.BGreen + str(__builtin__.DST_MAC) + fcolor.SWhite + "  [" + str(__builtin__.DST_MACLoc) + fcolor.SWhite + "]\t\tType : " + fcolor.BGreen + str(__builtin__.DST_TYPE)
                        print fcolor.SWhite + "COMMAND   : " + fcolor.BGreen + str(__builtin__.PKT_CMD)
                        print fcolor.SWhite + "SPEED     : " + fcolor.BGreen + str(__builtin__.PKT_SPEED) + "\t" + fcolor.SWhite + "FREQ  = " + fcolor.BGreen + str(__builtin__.PKT_FREQ)+ "\t" + fcolor.SWhite + "STANDARD = " + fcolor.BGreen + str(__builtin__.PKT_STANDARD) + "\t" + fcolor.SWhite + "POWER = " + fcolor.BGreen + str(__builtin__.PKT_POWER)
                        print fcolor.SWhite + "BSSID     : " + fcolor.BGreen + str(__builtin__.MAC_BSSID) + fcolor.SWhite + "\tESS = " + fcolor.BGreen + str(PKT_ESS) + "\t" + fcolor.SWhite + "CHANNEL = " + fcolor.BGreen + str(__builtin__.PKT_CHANNEL) + fcolor.SWhite + "\t\tESSID = " + fcolor.BPink + str(__builtin__.PKT_ESSID) + "\t" + fcolor.SWhite 
                        print fcolor.SWhite + "PROBE REQ : " + fcolor.BBlue + str(__builtin__.PKT_PROBE_REQ) + "\t\t\t" + fcolor.SWhite + "RESPONSE : " + fcolor.BGreen + str(__builtin__.PKT_PROBE_RSP)
                        print fcolor.SWhite + "MBIT      : " + fcolor.BGreen + str(__builtin__.PKT_MBIT)
                        print ""
                    if __builtin__.SHOWRESULT==3:
                        open(__builtin__.SavedTCPDumpFile,"a+b").write(line + "\n")
        if __builtin__.SHOWRESULT!=3:
            print ""
            if RecCt!=0:
                print fcolor.BWhite + str(RecCt) + " records listed / " + str(int(linecount)-int(RecCt)) + " records ignored."
                DisplayAnalysisFilters()
            else:
                print fcolor.BWhite + "No record found. " + str(linecount) + " data read."
                DisplayAnalysisFilters()
        if __builtin__.SHOWRESULT==3: 
            printl (spacing + fcolor.SGreen + "Analysing Packets...TCPDump - Completed.","0","")
    else:
        print fcolor.BRed + "Packet file - " + fcolor.BYellow + __builtin__.TCPDumpFileBak + fcolor.BRed + " not found !"
                

def signal_handler(signal,frame):
    printc (" ", fcolor.BRed + "\nInterrupted !!","")
    Result=AskQuestion(fcolor.SRed + "Are you sure you want to exit"+ fcolor.BGreen,"y/N","U","N","1")
    if Result=="Y":
        exit_gracefully(0)

def RunWash():
    DelFile (tmpdir + "WPS*",1)
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MON) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    cmdLine="ps -eo pid | grep '" + str(__builtin__.WashProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    ps.wait();ps.stdout.close()
    __builtin__.WashProc=str(__builtin__.WashProc)
    if str(readout)==str(__builtin__.WashProc):
        os.killpg(int(__builtin__.WashProc), signal.SIGTERM)
    Search="WAIDPS - Monitoring WPS"
    KillProc(Search)
    cmdLine="xterm -geometry 100x3-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Monitoring WPS' -e 'wash -o " + __builtin__.WPS_DUMP + " -C -i " + __builtin__.SELECTED_MON + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)		
    __builtin__.WashProc=ps.pid

def RunIWList():
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MANIFACE) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    cmdLine="ps -eo pid | grep '" + str(__builtin__.IWListProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    __builtin__.IWListProc=str(__builtin__.IWListProc)
    ps.wait();ps.stdout.close()
    if str(readout)==str(__builtin__.IWListProc):
        os.killpg(int(__builtin__.IWListProc), signal.SIGTERM)
    Search="WAIDPS - Scanning For Access Points"
    KillProc(Search)
    if __builtin__.SELECTED_MANIFACE!="":
        cmdLine="xterm -geometry 100x3-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Scanning For Access Points' -e 'iwlist " + __builtin__.SELECTED_MANIFACE + " scanning > " + str(__builtin__.TMP_IWList_DUMP) + "'"
        ps=subprocess.Popen(cmdLine ,shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)	
        __builtin__.IWListProc=ps.pid

def RunAirodump():
    DelFile (tmpdir + "Collect-Dump-*",1)
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_MON) + " up > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    cmdLine="ps -eo pid | grep '" + str(__builtin__.DumpProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    __builtin__.DumpProc=str(__builtin__.DumpProc)
    ps.wait();ps.stdout.close()
    if str(readout)==str(__builtin__.DumpProc):
        os.killpg(int(__builtin__.DumpProc), signal.SIGTERM)
    Search="WAIDPS - Monitoring SSID/Clients"
    KillProc(Search)
    if __builtin__.FIXCHANNEL!=0:
        ps=subprocess.Popen("iwconfig " + str(__builtin__.SELECTED_MON) + " channel " + str(__builtin__.FIXCHANNEL) + " > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        cmdLine="xterm -geometry 100x20-0-0 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Monitoring SSID/Clients' -hold -e 'airodump-ng --berlin " + str(TIMEOUT) + " --channel " + str(__builtin__.FIXCHANNEL) + " -w " + appdir + "/tmp/Collect-Dump " + __builtin__.SELECTED_MON + "'"
    else:
        cmdLine="xterm -geometry 100x20-0-0 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Monitoring SSID/Clients' -hold -e 'airodump-ng --berlin " + str(TIMEOUT) + " -w " + appdir + "/tmp/Collect-Dump " + __builtin__.SELECTED_MON + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)	
    __builtin__.DumpProc=ps.pid

def RunPacketCapture():
    if SHOW_IDS=="Yes" or SHOW_SUSPICIOUS_LISTING=="Yes":
        DelFile (tmpdir + "MON_*",1)
        if __builtin__.FIXCHANNEL==0:
            cmdLine="xterm -geometry 100x10-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Capturing Packets' -e '" + "tshark -i " + str(__builtin__.SELECTED_MON) + " -w " + str(__builtin__.PacketDumpFile) + "'"
        else:
            cmdLine="xterm -geometry 100x10-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Capturing Packets' -e '" + "tshark -i " + str(__builtin__.SELECTED_MON) + " -w " + str(__builtin__.PacketDumpFile) + "'"
        ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)	
        __builtin__.PCapProc=ps.pid

def KillProc(ProcName):
    pstr="kill $(ps aux | grep '" + str(ProcName) + "' | awk '{print $2}')"
    ps=subprocess.Popen(pstr, shell=True, stdout=subprocess.PIPE)	
    ps.wait();ps.stdout.close()

def KillAllMonitor():
    Search="WAIDPS - Monitoring SSID/Clients"
    KillProc(Search)
    Search="WAIDPS - Monitoring WPS"
    KillProc(Search)
    Search="WAIDPS - Scanning For Access Points"
    KillProc(Search)
    Search="WAIDPS - Capturing Packets"
    KillProc(Search)
    Search="WAIDPS - Intrusion Prevention"
    KillProc(Search)

def GetMyMAC(IFACE):
    MACADDR=""
    ps=subprocess.Popen("ifconfig " + str(IFACE) + " | grep 'HWaddr' | tr -s ' ' | cut -d ' ' -f5" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))
    MACADDR=ps.stdout.read().replace("\n","").upper().replace("-",":")
    ps.wait();ps.stdout.close()
    MACADDR=MACADDR[:17]
    return MACADDR
    

def RandomMAC():
    H1="00"
    H2=ChangeHex(random.randrange(255))
    H3=ChangeHex(random.randrange(255))
    H4=ChangeHex(random.randrange(255))
    H5=ChangeHex(random.randrange(255))
    H6=ChangeHex(random.randrange(255))
    ASSIGNED_MAC=str(H1) + ":" + str(H2) + ":" + str(H3) + ":" + str(H4) + ":" + str(H5) + ":" + str(H6) 
    return ASSIGNED_MAC;

def CreateMonitor(CMD):
    if __builtin__.SELECTED_IFACE!="":
        if CMD=="1":
            printc (".",fcolor.SGreen + "Enabling monitoring for [ " + fcolor.BRed + __builtin__.SELECTED_IFACE + fcolor.SGreen + " ]...","")
        ASSIGNED_MAC=RandomMAC()
        ps=subprocess.Popen("iw " + __builtin__.SELECTED_IFACE + " interface add wlmon0 type monitor > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        ps=subprocess.Popen("ip link set dev wlmon0 address " + str(ASSIGNED_MAC) + " > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        ps=subprocess.Popen("ifconfig wlmon0 up  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        __builtin__.SELECTED_MON="wlmon0"
        ASSIGNED_MAC=RandomMAC()
        ps=subprocess.Popen("iw " + __builtin__.SELECTED_IFACE + " interface add probe0 type managed  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        ps=subprocess.Popen("ip link set dev probe0 address " + str(ASSIGNED_MAC) + " > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        ps=subprocess.Popen("ifconfig probe0 up    > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        cmdLine="ifconfig probe0 | grep -i 'up broadcast'"
        ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
        readout=str(ps.stdout.read())
        ps.wait();ps.stdout.close()
        if readout=="":
            __builtin__.SELECTED_MANIFACE=__builtin__.SELECTED_IFACE
        else:
            __builtin__.SELECTED_MANIFACE="probe0"
        __builtin__.SELECTED_MON="wlmon0"
        if CMD=="1":
            print ""
            printc (" ", fcolor.SWhite + "Selected Interface ==> " + fcolor.BRed + str(__builtin__.SELECTED_IFACE),"")
        ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE) + " up  > /dev/null 2>&1" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
        ps.wait();ps.stdout.close()
        if CMD=="1":
            printc (" ", fcolor.SWhite + "Selected Monitoring Interface ==> " + fcolor.BRed + str(__builtin__.SELECTED_MON),"")
            printc (" ", fcolor.SWhite + "Selected Managing Interface   ==> " + fcolor.BRed + str(__builtin__.SELECTED_MANIFACE),"")
            print ""
    else:
        if CMD=="1":
            printc ("!!!","Failed to enable monitor as no interface selected !","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)

def HarvestingProcess(CMD):
    if CMD=="1":
        RewriteCSV()
        ExtractDump()
        EnrichDump()
        EnrichSSID()
        ExtractWPS()
        SortBSSIDList()
        ExtractClient()
        SortStationList()
        return
    if CMD=="2":
        DisplayInfrastructure()
        DisplayClientList()
        CheckMonitoringMAC()
        CheckDiffBSSIDConnection()
        return
    if CMD=="3":
        WriteDBFile()
        return

def IDSProcess(CMD):
    if SHOW_IDS=="Yes" or SHOW_SUSPICIOUS_LISTING=="Yes":
        if CMD=="1":
            AnalysePacketCapture()
            printl ("","0","")
            return
        if CMD=="2":
            ShowAnalysedListing("SHOW LIST3_QUIET")
            LineBreak()
            ShowIDSDetection("")
            return

def EnterUserPassword(cmd):
    ContinueWrite=""
    if cmd=="1":
        if IsFileDirExist(EncDBFile)=="F":
            printc ("!!!","A encrypted database already exist !!","")
            printc (" ",fcolor.BRed + "By continuing, existing encrypted will be over-written.","")
            usr_resp=AskQuestion(fcolor.BRed + "Are you sure ?" + fcolor.BGreen,"y/N","U","N","1")
            if usr_resp=="Y":
                ContinueWrite="1"
            else:
                return
        else:
            printc ("!!!","At present, there is no password for your encrypted data.","")
            printc ("!!!","If you forgot your password, all encrypted data will be gone..","")
    os.system("stty -echo")
    password=raw_input(tabspacefull + fcolor.BGreen + "Enter your password : ")
    print ""
    password2=raw_input(tabspacefull + fcolor.BGreen + "Confirm password    : ")
    print ""
    os.system("stty echo")
    print ""
    if password!=password2:
        printc ("!!!","Password entered are not the same !!","")
        EnterUserPassword("")
        return;
    secret=Hashing(password)
    __builtin__.ENCRYPTED_PASS=secret
    EncStr=secret + "\n" + "Encrypted Content\n"
    cipher = AES.new(secret)
    encoded = EncodeAES(cipher, EncStr)
    open (EncDBFile,"w").write(encoded)
    __builtin__.USERPASS=1
    SaveConfig("")

def ReadCommandHistory():
    if IsFileDirExist(__builtin__.CommandHistory)=="F":
        rwf=tmpdir + "tmp.tmp"
        open(rwf,"w").write("")
        with open(__builtin__.CommandHistory,"r") as f:
            for line in f:
                if len(line)>2:
                    open(rwf,"a+b").write(line)
        DelFile (__builtin__.CommandHistory,"")
        os.rename(rwf,__builtin__.CommandHistory)
        readline.read_history_file(__builtin__.CommandHistory)

def Main():
    KillAllMonitor()
    ps=subprocess.Popen("iw probe0 del  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    ps=subprocess.Popen("iw wlmon0 del  > /dev/null 2>&1", shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    MonCt = GetInterfaceList("MON")
    __builtin__.MONList=__builtin__.IFaceList
    Ct=GetInterfaceList("MAN")
    __builtin__.SELECTED_MANIFACE=""
    __builtin__.SELECTED_IFACE_PROBE=""
    if Ct!=0:
        __builtin__.SELECTED_MANIFACE=__builtin__.IFaceList[0]
    GetAppName()
    CheckLinux()
    CheckPyVersion("2.6")
    os.system('clear')
    DisplayAppDetail()
    DisplayDescription()
    CheckAdmin()
    CheckAppLocation()
    if IMPORT_ERRMSG!="":
        print fcolor.BBlue + "Following Libaries required by WAIDS is missing"
        printc ("!!!","Script will not proceed..","")
        print fcolor.SRed + IMPORT_ERRMSG
        printc ("x","","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    CheckRequiredFiles()
    GetHardwareID()
    CreateDatabaseFiles()
    DropFiles()
    GetParameter("1")
    DelFile (tmpdir + "Collect-Dump-*",1)
    DelFile (tmpdir + "WPS*",1)
    DelFile (tmpdir + "Dumps*",1)
    LoadConfig()
    LoadPktConfig()
    if __builtin__.HWID!=__builtin__.HWID_Saved:
        if __builtin__.HWID_Saved=="":
            __builtin__.HWID_Saved=__builtin__.HWID
        else:
            printc ("!!!","Hardware ID is different, decryption of encrypted data would not be possible.","")
            printc ("!!!","If you choose to update with new hardware ID, all existing encrypted will be deleted..","")
            usr_resp=AskQuestion(fcolor.BRed + "Continue and update new Hardware ID ?" + fcolor.BGreen,"y/N","U","N","1")
            if usr_resp=="Y":
                SaveConfig("")
                RestartApplication()
            else:
                exit_gracefully(1)
    usr=os.getlogin()
    if __builtin__.USERNAME=="":
        __builtin__.USERNAME=usr
        __builtin__.USERHASH=MD5(__builtin__.USERNAME,"h")
        SaveConfig("")
    if __builtin__.USERPASS=="":
        EnterUserPassword("1")
        print ""
        
    RETRY=0
    __builtin__.PrintToFile=__builtin__.PRINTTOFILE
    if __builtin__.ReadPacketOnly=="1":
        if IsFileDirExist(captured_pcap)=="F" and IsFileDirExist(captured_csv)=="F":
            print "     Reading captured packet only..."
            ConvertPackets("1")
            AnalyseCaptured()
        else:
            printc ("!!!","[-ro] Function is use to read existing captured packet only...","")
            printc (" ","Make sure all neccessary captured files is present in order to use this function...","")
        exit()
    ps=subprocess.Popen("ps -A | grep 'airodump-ng'" , shell=True, stdout=subprocess.PIPE)	
    Process=ps.stdout.read()
    ps.wait();ps.stdout.close()
    if Process!="":
        ps=subprocess.Popen("killall 'airodump-ng'" , shell=True, stdout=subprocess.PIPE)	
        Process=ps.stdout.read()
        ps.wait();ps.stdout.close()
    ps=subprocess.Popen("ps -A | grep 'aireplay-ng'" , shell=True, stdout=subprocess.PIPE)	
    Process=ps.stdout.read()
    ps.wait();ps.stdout.close()
    if Process!="":
        ps=subprocess.Popen("killall 'aireplay-ng'" , shell=True, stdout=subprocess.PIPE)	
        Process=ps.stdout.read()
        ps.wait();ps.stdout.close()
    printc ("i","Monitor Selection","")
    MonCt = GetInterfaceList("MON")
    WLANCt = GetInterfaceList("WLAN")
    if MonCt==0 and WLANCt==0:
        printc (".",fcolor.SRed + "No wireless interface detected !","")
        __builtin__.ERRORFOUND=1
        exit_gracefully(1)
    if WLANCt!=0:
        if __builtin__.SELECTED_IFACE=="":
            __builtin__.SELECTED_IFACE=SelectInterfaceToUse()
            CreateMonitor("1")
        else:
            if __builtin__.SELECTED_IFACE=="":
                __builtin__.SELECTED_IFACE=__builtin__.IFaceList[0]
            CreateMonitor("1")
            Rund="iwconfig " + __builtin__.SELECTED_IFACE + " > /dev/null 2>&1"
            result=os.system(Rund)
            if result==0:
                printc(">",fcolor.BIGray + "Interface Selection Bypassed....","")
            else:
                printc ("!!!", fcolor.BRed + "The interface specified [ " + fcolor.BWhite + __builtin__.SELECTED_IFACE + fcolor.BRed + " ] is not available." ,"")
                print ""
                __builtin__.SELECTED_IFACE=SelectInterfaceToUse()
    RunAirodump()
    if __builtin__.LOAD_WPS=="Yes" and __builtin__.FIXCHANNEL==0:
        RunWash()
    if __builtin__.LOAD_PKTCAPTURE=="Yes":
        RunPacketCapture()
    ps=subprocess.Popen("ifconfig " + str(__builtin__.SELECTED_IFACE_PROBE) + " up" , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'))
    ps.wait();ps.stdout.close()
    cmdLine="ps -eo pid,args | grep 'WAIDPS - Monitoring SSID/Clients' | grep 'xterm' | cut -c 1-6"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    __builtin__.DumpProcPID=ps.stdout.read()
    ps.wait();ps.stdout.close()
    cmdLine="ps -eo pid,args | grep 'WAIDPS - Monitoring WPS' | grep 'xterm' | cut -c 1-6"    
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    __builtin__.WashProcPID=ps.stdout.read()
    ps.wait();ps.stdout.close()
    __builtin__.SELECTED_MON_MAC=GetMyMAC(__builtin__.SELECTED_MON)
    __builtin__.SELECTED_MANIFACE_MAC=GetMyMAC(__builtin__.SELECTED_MANIFACE)
    __builtin__.SELECTED_IFACE_MAC=GetMyMAC(__builtin__.SELECTED_IFACE)
    GetMonitoringMAC()
    GetWhitelist()
    DisplayPanel()
    ReadCommandHistory()
    CurLoop=0;RestartIFaceCt=0
    while CurLoop<int(__builtin__.LoopCount):
        captured_pcap=tmpdir + "captured"
        retkey=WaitingCommands(__builtin__.TIMEOUT,1)
        DisplayPanel()
        HarvestingProcess("1")
        IDSProcess("1")
        HarvestingProcess("2")
        IDSProcess("2")
        HarvestingProcess("3")
        RestartIFaceCt += 1
        __builtin__.MSG_CombinationLogs=RemoveAdditionalLF(__builtin__.MSG_CombinationLogs)
        if retkey==None or retkey=="":
            if RestartIFaceCt>100:
                printc ("i","Application had run for quite some time, restarting interface..","")
                ResetInterface("");RestartIFaceCt=0
            CurLoop += 1
            if int(__builtin__.LoopCount)-CurLoop<3 and int(__builtin__.LoopCount)!=CurLoop:
                printc (" ", "Remaining loop count : " + str(int(__builtin__.LoopCount)-CurLoop),"")
        else:
            print ""
            CurLoop=__builtin__.LoopCount + 1
    printc ("i", fcolor.BWhite + "Completed !! ","")
    exit_gracefully(0)

def DebugPrint(sVal):
    ToDisplay=0
    if ToDisplay==1:
        print fcolor.SWhite + str(sVal)

def WriteDBFile():
    WriteAccessPointDB()
    __builtin__.UPDATE_STN_COUNT=int(__builtin__.UPDATE_STN_COUNT)+1
    if int(__builtin__.UPDATE_STN_COUNT)>=int(__builtin__.TIMES_BEFORE_UPDATE_STN_DB):
        __builtin__.UPDATE_STN_COUNT=0
        WriteAllStationDB()

def WriteAccessPointDB():
    SkipWrite=0
    x=0
    AddData=0
    while x<len(ListInfo_BSSID):
        WriteFile=0
        if int(__builtin__.ListInfo_BSSIDTimes[x])>=int(__builtin__.TIMES_BEFORE_UPDATE_AP_DB):
            WriteFile=1
        if __builtin__.ListInfo_Enriched[x]=="Yes":
            WriteFile=1
        if WriteFile==1 and len(ListInfo_BSSID[x])==17 and __builtin__.SELECTED_MANIFACE_MAC!=ListInfo_BSSID[x] and __builtin__.SELECTED_MON_MAC!=ListInfo_BSSID[x] and __builtin__.SELECTED_IFACE_MAC!=ListInfo_BSSID[x]:
            SkipWrite=0
            with open(DBFile2,"r") as f:
                for line in f:
                    line=line.replace("\n","").replace("\r","")
                    sl=len(line)
                    if SkipWrite==0 and sl>34:
                        tmplist=[]
                        tmplist=str(line).split(";")
                        if len(tmplist)>10:
                            if tmplist[0]==str(ListInfo_BSSID[x]) and tmplist[5]==str(ListInfo_Channel[x]) and tmplist[6]==str(ListInfo_Privacy[x]) and tmplist[7]==str(ListInfo_Cipher[x]) and tmplist[8]==str(ListInfo_Auth[x]) and tmplist[10]==str(ListInfo_BitRate[x]) and tmplist[15]==str(ListInfo_WPS[x]) and tmplist[16]==str(ListInfo_WPSVer[x]) and tmplist[18]==str(ListInfo_ESSID[x]):
                                SkipWrite=1
                                break
                if SkipWrite==0 and RemoveUnwantMAC(ListInfo_BSSID[x])!="" and ListInfo_BSSID[x]!=__builtin__.SELECTED_MON_MAC and ListInfo_BSSID[x]!=__builtin__.SELECTED_MANIFACE_MAC  and ListInfo_BSSID[x]!=__builtin__.SELECTED_IFACE_MAC:
                    AddData=AddData+1
                    WriteData=str(ListInfo_BSSID[x]) + str(col)
                    WriteData=WriteData + str(ListInfo_Enriched[x]) + str(col)  
                    WriteData=WriteData + str(ListInfo_Mode[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_FirstSeen[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_LastSeen[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Channel[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Privacy[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Cipher[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_Auth[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_MaxRate[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_BitRate[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_BestQuality[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestLat[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestLon[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_GPSBestAlt[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_WPS[x]) + str(col) 
                    WriteData=WriteData + str(ListInfo_WPSVer[x]) + str(col) 
                    WriteData=WriteData + str(Now()) + str(col)
                    WriteData=WriteData + str(ListInfo_ESSID[x]) + str(col) + "\n"
                    open(DBFile2,"a+b").write(WriteData)
        x += 1

def WriteAllStationDB():
    AddData=0
    AddData3=0
    AddData4=0
    x=0
    SkipWrite=0
    while x<len(ListInfo_STATION):
        ESSID=FindESSID(ListInfo_CBSSID[x])
        SkipWrite=0
        if len(ListInfo_STATION[x])==17 and __builtin__.SELECTED_MANIFACE_MAC!=ListInfo_STATION[x] and __builtin__.SELECTED_MON_MAC!=ListInfo_STATION[x] and __builtin__.SELECTED_IFACE_MAC!=ListInfo_STATION[x]:
##            print "MON  MAC : " + str(__builtin__.SELECTED_MON_MAC)
            if ListInfo_CBSSID[x].find("Not Associated")==-1:
                with open(DBFile5,"r") as f:
                    next(f)
                    for line in f:
                        line=line.replace("\n","").replace("\r","")
                        sl=len(line)
                        if SkipWrite==0 and sl>34:
                            tmplist=[]
                            tmplist=str(line).split(";")
                            if len(tmplist)>2:
                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ListInfo_CBSSID[x]):
                                    if IsAscii(tmplist[2])==True and IsAscii(ListInfo_CESSID[x])==False:
                                        SkipWrite=1
                                    if tmplist[2]==str(ListInfo_CESSID[x]):
                                        SkipWrite=1
                                        break
                    if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="" and ListInfo_STATION[x]!=__builtin__.SELECTED_MON_MAC and ListInfo_STATION[x]!=__builtin__.SELECTED_MANIFACE_MAC and ListInfo_STATION[x]!=__builtin__.SELECTED_IFACE_MAC:
                        AddData=AddData+1
                        WriteData=str(ListInfo_STATION[x]) + str(col)
                        WriteData=WriteData + str(ListInfo_CBSSID[x]) + str(col) 
                        WriteData=WriteData + str(ESSID) + str(col) + "\n"
                        open(DBFile5,"a+b").write(WriteData)
                f.close()
            if ListInfo_STATION[x]!="":
                SkipWrite=0
                with open(DBFile3,"r") as f:
                    next(f)
                    for line in f:
                        line=line.replace("\n","").replace("\r","")
                        sl=len(line)
                        if SkipWrite==0 and sl>34:
                            tmplist=[]
                            tmplist=str(line).split(";")
                            if len(tmplist)>2:
                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ListInfo_CBSSID[x]) :
                                    if tmplist[6]==str(ListInfo_CESSID[x]):
                                        SkipWrite=1
                                        break
                    if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="":
                        AddData3=AddData3+1
                        WriteData=str(ListInfo_STATION[x]) + str(col)
                        WriteData=WriteData + str(ListInfo_CBSSID[x]) + str(col)  
                        WriteData=WriteData + str(ListInfo_CFirstSeen[x]) + str(col) 
                        WriteData=WriteData + str(ListInfo_CLastSeen[x]) + str(col) 
                        WriteData=WriteData + str(ListInfo_CBestQuality[x]) + str(col) 
                        WriteData=WriteData + str(Now()) + str(col)
                        WriteData=WriteData + str(ESSID) + str(col) + "\n"
                        open(DBFile3,"a+b").write(WriteData)
                f.close()
            if ListInfo_PROBE[x]!="":
                tmpProbeList=[]
                tmpProbeList=str(ListInfo_PROBE[x]).split(" / ")
                y=0
                while y<len(tmpProbeList):
                    ProbeName=str(tmpProbeList[y])
                    if ProbeName!="":
                        SkipWrite=0
                        with open(DBFile4,"r") as f:
                            next(f)
                            for line in f:
                                line=line.replace("\n","").replace("\r","")
                                sl=len(line)
                                if SkipWrite==0 and sl>17:
                                    tmplist=[]
                                    tmplist=str(line).split(";")
                                    if len(tmplist)>2:
                                        if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[2]==str(ProbeName) :
                                            SkipWrite=1
                                            break
                            if SkipWrite==0 and RemoveUnwantMAC(ListInfo_STATION[x])!="":
                                AddData4=AddData4+1
                                WriteData=str(ListInfo_STATION[x]) + str(col)
                                WriteData=WriteData + str(Now()) + str(col)
                                WriteData=WriteData + str(ProbeName) + str(col) + "\n"
                                open(DBFile4,"a+b").write(WriteData)
                        f.close()
                    y += 1
        x += 1
    return

def Check_OUI(MACAddr,CMD):
    Result=""
    OUI=""
    if len(MACAddr)==17:
        MACAddr=MACAddr.replace(":","")
        MACAddr9=MACAddr[:9]
        MACAddr6=MACAddr[:6]
        MACAddr12=MACAddr[:12]
        if IsFileDirExist(__builtin__.MACOUI)=="F":
            if CMD=="":
                cmdLine="grep -w " + str(MACAddr6) + " " + str(__builtin__.MACOUI)
                ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                readout=str(ps.stdout.read().replace("\n","").replace(MACAddr6,"").lstrip().rstrip())
                ps.wait();ps.stdout.close()
                if readout!="":
                    OUI=str(readout)
                    return OUI
                else:
                    return "Unknown"
            else:
                cmdLine="grep -w " + str(MACAddr12) + " " + str(__builtin__.MACOUI)
                ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                readout=str(ps.stdout.read().replace("\n","")) #.replace(MACAddr12,"").lstrip().rstrip())
                if readout!="":
                    OUI=str(readout)[13:]
                    return OUI
                else:
                    cmdLine="grep -w " + str(MACAddr9) + " " + str(__builtin__.MACOUI)
                    ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                    readout=str(ps.stdout.read().replace("\n","")) #.replace(MACAddr9,"").lstrip().rstrip())
                    if readout!="":
                        OUI=str(readout)[10:]
                        return OUI
                    else:
                        cmdLine="grep -w " + str(MACAddr6) + " " + str(__builtin__.MACOUI)
                        ps=Popen(str(cmdLine), shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)
                        readout=str(ps.stdout.read().replace("\n","")) #.replace(MACAddr6,"").lstrip().rstrip())
                        if readout!="":
                            OUI=str(readout)[7:]
                            return OUI
                        else:
                            return "Unknown"
                return "Unknown"

def GetScreenWidth():
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    TWidth=TWidth
    return TWidth

def CheckMaxCount(StrVal,MaxRec):
    if int(StrVal)>int(MaxRec):
        MaxRec=int(StrVal)
    return MaxRec

def DisplayNetworkChart():
    x=0;CH_MaxCt=0;EN_MaxCt=0;CL_MaxCt=0;SN_MaxCt=0
    CH0=0;DCH0=0;CH1=0;DCH1=0;CH2=0;DCH2=0;CH3=0;DCH3=0;CH4=0;DCH4=0;CH5=0;DCH5=0;CH6=0;DCH6=0;CH7=0;DCH7=0;CH8=0;DCH8=0;CH9=0;DCH9=0;CH10=0;DCH10=0;CH11=0;DCH11=0;CH12=0;DCH12=0;CH13=0;DCH13=0;CH14=0;DCH14=0;CH100=0;DCH100=0;WPA2=0;DWPA2=0;WPA=0;DWPA=0;WEP=0;DWEP=0;OPN=0;DOPN=0;UNK=0;DUNK=0
    WPA2_WPS=0;WPA_WPS=0;WEP_WPS=0;OPN_WPS=0;UNK_WPS=0
    SN_VG=0;DSN_VG=SN_VG;SN_GD=0;DSN_GD=SN_GD;SN_AV=0;DSN_AV=SN_AV;SN_PR=0;DSN_PR=SN_PR;SN_UK=0;DSN_UK=SN_UK
    WPA2_CLN=0;DWPA2_CLN=0;WPA_CLN=0;DWPA_CLN=0;WEP_CLN=0;DWEP_CLN=0;OPN_CLN=0;DOPN_CLN=0;UNK_CLN=0;DUNK_CLN=0
    WPA2_CLNCT=0;DWPA2_CLNCT=0;WPA_CLNCT=0;DWPA_CLNCT=0;WEP_CLNCT=0;DWEP_CLNCT=0;OPN_CLNCT=0;DOPN_CLNCT=0;UNK_CLNCT=0;DUNK_CLNCT=0
    while x < len(ListInfo_BSSID):
        CH=__builtin__.ListInfo_Channel[x]
        ENC=__builtin__.ListInfo_Privacy[x]
        WPS=__builtin__.ListInfo_WPS[x]
        CLN=int(__builtin__.ListInfo_ConnectedClient[x])
        SNL=RemoveColor(str(__builtin__.ListInfo_QualityRange[x]))
        if ENC=="WPA2":
          WPA2 += 1;EN_MaxCt=CheckMaxCount(WPA2,EN_MaxCt);DWPA2=WPA2
          if WPS=="Yes":
              WPA2_WPS += 1
          if CLN!=0:
              WPA2_CLN += 1;DWPA2_CLN=WPA2_CLN
              WPA2_CLNCT = WPA2_CLNCT + int(CLN);DWPA2_CLNCT=WPA2_CLNCT
              CL_MaxCt=CheckMaxCount(WPA2_CLN,CL_MaxCt)
        if ENC=="WPA":
          WPA += 1;EN_MaxCt=CheckMaxCount(WPA,EN_MaxCt);DWPA=WPA
          if WPS=="Yes":
              WPA_WPS += 1
          if CLN!=0:
              WPA_CLN += 1;DWPA_CLN=WPA_CLN
              WPA_CLNCT = WPA_CLNCT + int(CLN);DWPA_CLNCT=WPA_CLNCT
              CL_MaxCt=CheckMaxCount(WPA_CLN,CL_MaxCt)
        if ENC=="WEP":
          WEP += 1;EN_MaxCt=CheckMaxCount(WEP,EN_MaxCt);DWEP=WEP
          if WPS=="Yes":
              WEP_WPS += 1
          if CLN!=0:
              WEP_CLN += 1;DWEP_CLN=WEP_CLN
              WEP_CLNCT = WEP_CLNCT + int(CLN);DWEP_CLNCT=WEP_CLNCT
              CL_MaxCt=CheckMaxCount(WEP_CLN,CL_MaxCt)
        if ENC=="OPN":
          OPN += 1;EN_MaxCt=CheckMaxCount(OPN,EN_MaxCt);DOPN=OPN
          if WPS=="Yes":
              OPN_WPS += 1
          if CLN!=0:
              OPN_CLN += 1;DOPN_CLN=OPN_CLN
              OPN_CLNCT = OPN_CLNCT + int(CLN);DOPN_CLNCT=OPN_CLNCT
              CL_MaxCt=CheckMaxCount(OPN_CLN,CL_MaxCt)
        if ENC!="WPA2" and ENC!="WPA" and ENC!="WEP" and ENC!="OPN":
          UNK += 1;EN_MaxCt=CheckMaxCount(UNK,EN_MaxCt);DUNK=UNK
          if WPS=="Yes":
              UNK_WPS += 1
          if CLN!=0:
              UNK_CLN += 1;UNK_CLN=UNK_CLN
              UNK_CLNCT = UNK_CLNCT + int(CLN);DUNK_CLNCT=UNK_CLNCT
              CL_MaxCt=CheckMaxCount(UNK_CLN,CL_MaxCt)
        if CH=="1":
          CH1 += 1;CH_MaxCt=CheckMaxCount(CH1,CH_MaxCt);DCH1=CH1
        if CH=="2":
          CH2 += 1;CH_MaxCt=CheckMaxCount(CH2,CH_MaxCt);DCH2=CH2
        if CH=="3":
          CH3 += 1;CH_MaxCt=CheckMaxCount(CH3,CH_MaxCt);DCH3=CH3
        if CH=="4":
          CH4 += 1;CH_MaxCt=CheckMaxCount(CH4,CH_MaxCt);DCH4=CH4
        if CH=="5":
          CH5 += 1;CH_MaxCt=CheckMaxCount(CH5,CH_MaxCt);DCH5=CH5
        if CH=="6":
          CH6 += 1;CH_MaxCt=CheckMaxCount(CH6,CH_MaxCt);DCH6=CH6
        if CH=="7":
          CH7 += 1;CH_MaxCt=CheckMaxCount(CH7,CH_MaxCt);DCH7=CH7
        if CH=="8":
          CH8 += 1;CH_MaxCt=CheckMaxCount(CH8,CH_MaxCt);DCH8=CH8
        if CH=="9":
          CH9 += 1;CH_MaxCt=CheckMaxCount(CH9,CH_MaxCt);DCH9=CH9
        if CH=="10":
          CH10 += 1;CH_MaxCt=CheckMaxCount(CH10,CH_MaxCt);DCH10=CH10
        if CH=="11":
          CH11 += 1;CH_MaxCt=CheckMaxCount(CH11,CH_MaxCt);DCH11=CH11
        if CH=="12":
          CH12 += 1;CH_MaxCt=CheckMaxCount(CH12,CH_MaxCt);DCH12=CH12
        if CH=="13":
          CH13 += 1;CH_MaxCt=CheckMaxCount(CH13,CH_MaxCt);DCH13=CH13
        if CH=="14":
          CH14 += 1;CH_MaxCt=CheckMaxCount(CH14,CH_MaxCt);DCH14=CH14
        if int(CH)>14:
          CH100 += 1;CH_MaxCt=CheckMaxCount(CH100,CH_MaxCt);DCH100=CH100
        if int(CH)<1:
          CH0 += 1;CH_MaxCt=CheckMaxCount(CH0,CH_MaxCt);DCH0=CH0
        if SNL=="V.Good" or SNL=="V.Good":
            SN_VG += 1;DSN_VG=SN_VG;SN_MaxCt=CheckMaxCount(SN_VG,SN_MaxCt)
        if SNL=="Good" or SNL=="Good":
            SN_GD += 1;DSN_GD=SN_GD;SN_MaxCt=CheckMaxCount(SN_GD,SN_MaxCt)
        if SNL=="Average":
            SN_AV += 1;DSN_AV=SN_AV;SN_MaxCt=CheckMaxCount(SN_AV,SN_MaxCt)
        if SNL=="Poor":
            SN_PR += 1;DSN_PR=SN_PR;SN_MaxCt=CheckMaxCount(SN_PR,SN_MaxCt)
        if SNL=="Unknown":
            SN_UK += 1;DSN_UK=SN_UK;SN_MaxCt=CheckMaxCount(SN_UK,SN_MaxCt)
        x += 1
    os.system('clear')
    CenterText(fcolor.BWhite + fcolor.BGBlue, "Access Point Information Barchart View")
    print ""
    MaxWidth=GetScreenWidth()
    HalfWidth=MaxWidth/2
    CH_TIMES="";EN_TIMES=""; CL_TIMES=""; SN_TIMES=""
    CalCH=int(CH_MaxCt * 2) + 25
    if int(CalCH)<int(HalfWidth):
       CH_TIMES="x2"
    else:
        CalCH=int(CH_MaxCt) + 25
        if int(CalCH)<int(HalfWidth):
           CH_TIMES="x1"
        else:
            CalCH=int(CH_MaxCt / 2) + 25
            if int(CalCH)<int(HalfWidth):
               CH_TIMES="/2"
            else:
                CalCH=int(CH_MaxCt / 3) + 25
                if int(CalCH)<int(HalfWidth):
                   CH_TIMES="/3"
                else:
                    CalCH=int(CH_MaxCt / 4) + 25
                    if int(CalCH)<int(HalfWidth):
                       CH_TIMES="/4"
    CalEN=int(EN_MaxCt * 2) + 20
    if int(CalEN)<int(HalfWidth):
       EN_TIMES="x2"
    else:
        CalEN=int(EN_MaxCt) + 20
        if int(CalEN)<int(HalfWidth):
           EN_TIMES="x1"
        else:
            CalEN=int(EN_MaxCt / 2) + 20
            if int(CalEN)<int(HalfWidth):
               EN_TIMES="/2"
            else:
                CalEN=int(EN_MaxCt / 3) + 20
                if int(CalEN)<int(HalfWidth):
                   EN_TIMES="/3"
                else:
                    CalEN=int(EN_MaxCt / 4) + 20
                    if int(CalEN)<int(HalfWidth):
                       EN_TIMES="/4"
    CalCL=int(CL_MaxCt * 4) + 20
    if int(CalCL)<int(HalfWidth):
        CL_TIMES="x4"
    else:
        CalCL=int(CL_MaxCt * 3) + 20
        if int(CalCL)<int(HalfWidth):
            CL_TIMES="x3"
        else:
            CalCL=int(CL_MaxCt * 2) + 20
            if int(CalCL)<int(HalfWidth):
                CL_TIMES="x2"
            else:
                CalCL=int(CL_MaxCt) + 20
                if int(CalCL)<int(HalfWidth):
                    CL_TIMES="x1"
                else:
                    CalCL=int(CL_MaxCt / 2) + 20
                    if int(CalCL)<int(HalfWidth):
                        CL_TIMES="/2"
                    else:
                        CalCL=int(CL_MaxCt / 3) + 20
                        if int(CalCL)<int(HalfWidth):
                            CL_TIMES="/3"
                        else:
                            CalCL=int(CL_MaxCt / 4) + 20
                            if int(CalCL)<int(HalfWidth):
                                CL_TIMES="/4"
    CalSN=int(SN_MaxCt * 4) + 15
    if int(CalSN)<int(HalfWidth):
        SN_TIMES="x4"
    else:
        CalSN=int(SN_MaxCt * 3) + 15
        if int(CalSN)<int(HalfWidth):
            SN_TIMES="x3"
        else:
            CalSN=int(SN_MaxCt * 2) + 15
            if int(CalSN)<int(HalfWidth):
                SN_TIMES="x2"
            else:
                CalSN=int(SN_MaxCt) + 15
                if int(CalSN)<int(HalfWidth):
                    SN_TIMES="x1"
                else:
                    CalSN=int(SN_MaxCt / 2) + 15
                    if int(CalSN)<int(HalfWidth):
                        SN_TIMES="/2"
                    else:
                        CalSN=int(SN_MaxCt / 3) + 15
                        if int(CalSN)<int(HalfWidth):
                            SN_TIMES="/3"
                        else:
                            CalSN=int(SN_MaxCt / 4) + 15
                            if int(CalSN)<int(HalfWidth):
                                SN_TIMES="/4"
    CH_CHG=0
    if CH_TIMES=="x2":
        CH0=int(CH0) * 2;CH1=int(CH1) * 2; CH2=int(CH2) * 2; CH3=int(CH3) * 2; CH4=int(CH4) * 2;CH5=int(CH5) * 2; CH6=int(CH6) * 2; CH7=int(CH7) * 2;CH8=int(CH8) * 2;CH9=int(CH9) * 2;CH10=int(CH10) * 2;CH11=int(CH11) * 2;CH12=int(CH12) * 2;CH13=int(CH13) * 2;CH14=int(CH14) * 2;CH100=int(CH100) * 2
    if CH_TIMES=="/2" or CH_TIMES=="/3" or CH_TIMES=="/4":
        CH_CHG=1
        DivVal=int(CH_TIMES[-1:])
        CH0=int(CH0/DivVal);CH1=int(CH1/DivVal);CH2=int(CH2/DivVal);CH3=int(CH3/DivVal);CH4=int(CH4/DivVal);CH5=int(CH5/DivVal);CH6=int(CH6/DivVal);CH7=int(CH7/DivVal);CH8=int(CH8/DivVal);CH9=int(CH9/DivVal);CH10=int(CH10/DivVal);CH11=int(CH11/DivVal);CH12=int(CH12/DivVal);CH13=int(CH13/DivVal);CH14=int(CH14/DivVal);CH100=int(CH100/DivVal)
    if CH_CHG==1:
        if CH0==0 and DCH0!=0:
            CH0=1
        if CH1==1 and DCH1!=0:
            CH1=1
        if CH2==0 and DCH2!=0:
            CH2=1
        if CH3==0 and DCH3!=0:
            CH3=1
        if CH4==0 and DCH4!=0:
            CH4=1
        if CH5==0 and DCH5!=0:
            CH5=1
        if CH6==0 and DCH6!=0:
            CH6=1
        if CH7==0 and DCH7!=0:
            CH7=1
        if CH8==0 and DCH8!=0:
            CH8=1
        if CH9==0 and DCH9!=0:
            CH9=1
        if CH10==0 and DCH10!=0:
            CH10=1
        if CH11==0 and DCH11!=0:
            CH11=1
        if CH12==0 and DCH12!=0:
            CH12=1
        if CH13==0 and DCH13!=0:
            CH13=1
        if CH14==0 and DCH14!=0:
            CH14=1
        if CH100==0 and DCH100!=0:
            CH100=1
    EN_CHG=0
    if EN_TIMES=="x2":
        WPA2=int(WPA2*2);WPA=int(WPA*2);WEP=int(WEP*2);OPN=int(OPN*2);UNK=int(UNK*2)
    if EN_TIMES=="/2" or EN_TIMES=="/3" or EN_TIMES=="/4":
        EN_CHG=1
        DivVal=int(EN_TIMES[-1:]);WPA2=int(WPA2/DivVal);WPA=int(WPA/DivVal);WEP=int(WEP/DivVal);OPN=int(OPN/DivVal);UNK=int(UNK/DivVal)
    if EN_CHG==1:
        if WPA2==0 and DWPA2!=0:
            WPA2=1
        if WPA==0 and DWPA!=0:
            WPA=1
        if WEP==0 and DWEP!=0:
            WEP=1
        if OPN==0 and DOPN!=0:
            OPN=1
        if UNK==0 and DUNK!=0:
            UNK=1
    CL_CHG=0
    if CL_TIMES=="x2" or CL_TIMES=="x3" or CL_TIMES=="x4":
        DivVal=int(CL_TIMES[-1:])
        WPA2_CLN=int(WPA2_CLN*DivVal);WPA_CLN=int(WPA_CLN*DivVal);WEP_CLN=int(WEP_CLN*DivVal);OPN_CLN=int(OPN_CLN*DivVal);UNK_CLN=int(UNK_CLN*DivVal)
    if CL_TIMES=="/2" or CL_TIMES=="/3" or CL_TIMES=="/4":
        CL_CHG=1
        DivVal=int(CL_TIMES[-1:]);WPA2_CLN=int(WPA2_CLN/DivVal);WPA_CLN=int(WPA_CLN/DivVal);WEP_CLN=int(WEP_CLN/DivVal);OPN_CLN=int(OPN_CLN/DivVal);UNK_CLN=int(UNK_CLN/DivVal)
    if CL_CHG==1:
        if WPA2_CLN==0 and DWPA2_CLN!=0:
            WPA2_CLN=1
        if WPA_CLN==0 and DWPA_CLN!=0:
            WPA_CLN=1
        if WEP_CLN==0 and DWEP_CLN!=0:
            WEP_CLN=1
        if OPN_CLN==0 and DOPN_CLN!=0:
            OPN_CLN=1
        if UNK_CLN==0 and DUNK_CLN!=0:
            UNK_CLN=1
    SN_CHG=0
    if SN_TIMES=="x2" or SN_TIMES=="x3" or SN_TIMES=="x4":
        DivVal=int(SN_TIMES[-1:])
        SN_VG=int(SN_VG*DivVal);SN_GD=int(SN_GD*DivVal);SN_AV=int(SN_AV*DivVal);SN_PR=int(SN_PR*DivVal);SN_UK=int(SN_UK*DivVal)
    if SN_TIMES=="/2" or SN_TIMES=="/3" or SN_TIMES=="/4":
        SN_CHG=1
        DivVal=int(SN_TIMES[-1:]);SN_VG=int(SN_VG/DivVal);SN_GD=int(SN_GD/DivVal);SN_AV=int(SN_AV/DivVal);SN_PR=int(SN_PR/DivVal);SN_UK=int(SN_UK/DivVal)
    if SN_CHG==1:
        if SN_VG==0 and DSN_VG!=0:
            SN_VG=1
        if SN_GD==0 and DSN_GD!=0:
            SN_GD=1
        if SN_AV==0 and DSN_AV!=0:
            SN_AV=1
        if SN_PR==0 and DSN_PR!=0:
            SN_PR=1
        if SN_UK==0 and DSN_UK!=0:
            SN_UK=1
    Title1 = "Channel [ " + str(x) + " ] Access Points"; Title1 = Title1.ljust(80)
    Title2 = "Encryption (Access Point / Total WPS)";Title2 = Title2.ljust(50)
    MainTitle = fcolor.BGreen + str(Title1) + str(Title2)
    print MainTitle
    print ""
    DText=DisplayBar("Channel 01  : ", " ", CH1, DCH1, 80, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    DText2=DisplayBar("WPA2    : ", " ", WPA2, str(DWPA2) + " / " + str(WPA2_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 02  : ", " ", CH2, DCH2, 80, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    DText2=DisplayBar("WPA     : ", " ", WPA, str(DWPA) + " / " + str(WPA_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGPink, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 03  : ", " ", CH3, DCH3, 80, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    DText2=DisplayBar("WEP     : ", " ", WEP, str(DWEP) + " / " + str(WEP_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 04  : ", " ", CH4, DCH4, 80, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    DText2=DisplayBar("OPN     : ", " ", OPN, str(DOPN) + " / " + str(OPN_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 05  : ", " ", CH5, DCH5, 80, fcolor.BWhite, fcolor.BGPink, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", UNK, str(DUNK) + " / " + str(UNK_WPS) + " WPS", 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2;print ""
    DText=DisplayBar("Channel 06  : ", " ", CH6, DCH6, 80, fcolor.BWhite, fcolor.BGCyan, fcolor.SWhite)
    print DText + fcolor.BGreen + "Connected Client (Access Point / Total Clients)";print ""
    DText=DisplayBar("Channel 07  : ", " ", CH7, DCH7, 80, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    DText2=DisplayBar("WPA2    : ", " ", WPA2_CLN, str(DWPA2_CLN) + " / " + str(WPA2_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 08  : ", " ", CH8, DCH8, 80, fcolor.BWhite, fcolor.BGIRed, fcolor.SWhite)
    DText2=DisplayBar("WPA     : ", " ", WPA_CLN, str(DWPA_CLN) + " / " + str(WPA_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 09  : ", " ", CH9, DCH9, 80, fcolor.BWhite, fcolor.BGIGreen, fcolor.SWhite)
    DText2=DisplayBar("WEP     : ", " ", WEP_CLN, str(DWEP_CLN) + " / " + str(WEP_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 10  : ", " ", CH10, DCH10, 80, fcolor.BWhite, fcolor.BGIYellow, fcolor.SWhite)
    DText2=DisplayBar("OPN     : ", " ", OPN_CLN, str(DOPN_CLN) + " / " + str(OPN_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGBlue, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 11  : ", " ", CH11, DCH11, 80, fcolor.BWhite, fcolor.BGIBlue, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", UNK_CLN, str(DUNK_CLN) + " / " + str(UNK_CLNCT) + " Clients", 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 12  : ", " ", CH12, DCH12, 80, fcolor.BWhite, fcolor.BGIPink, fcolor.SWhite)
    print DText + fcolor.BGreen + "Signal Range";print ""
    DText=DisplayBar("Channel 13  : ", " ", CH13, DCH13, 80, fcolor.BWhite, fcolor.BGICyan, fcolor.SWhite)
    DText2=DisplayBar("Good    : ", " ", SN_GD, str(DSN_GD) , 50, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel 14  : ", " ", CH14, DCH14, 80, fcolor.BWhite, fcolor.BGGreen, fcolor.SWhite)
    DText2=DisplayBar("Average : ", " ", SN_AV, str(DSN_AV) , 50, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Channel >14 : ", " ", CH100, DCH100, 80, fcolor.BWhite, fcolor.BGYellow, fcolor.SWhite)
    DText2=DisplayBar("Poor    : ", " ", SN_PR, str(DSN_PR) , 50, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    print DText + DText2 ;print ""
    DText=DisplayBar("Error Chn   : ", " ", CH0, DCH0, 80, fcolor.BWhite, fcolor.BGRed, fcolor.SWhite)
    DText2=DisplayBar("Unknown : ", " ", SN_UK, str(DSN_UK) , 50, fcolor.BWhite, fcolor.BGWhite, fcolor.SWhite)
    print DText + DText2 ;print ""

def DisplayBar(Label, Fill, BarTimes, BarCount, Justify, LblColor, BarColor, CountColor):
    DText="C1" + str(Label) + "C2" + Fill * int(BarTimes) + "C3" + " " + str(BarCount)
    DText=DText.ljust(Justify + 6)
    DText=DText.replace("C1",LblColor).replace("C2",BarColor).replace("C3", fcolor.CReset + CountColor)
    return DText

def ExtractWPS():
    LineList = []
    __builtin__.ListInfo_WPSExist = 0
    __builtin__.ListInfo_WPSAdd = 0
    __builtin__.ListInfo_WPSCount = 0
    if IsFileDirExist(__builtin__.WPS_DUMP)=="F":
        with open(__builtin__.WPS_DUMP,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if line.find("BSSID                  Channel       RSSI       WPS Version       WPS Locked")==-1 and line.find("--------------------")==-1 and len(line)>82:
                    st = list(line)
                    st[18]=";"
                    st[30]=";"
                    st[45]=";"
                    st[60]=";"
                    st[80]=";"
                    lp="".join(st)
                    LineList=lp.split(";")
                    BSSID=LineList[0].lstrip().rstrip()
                    if len(BSSID)==17:
                        __builtin__.ListInfo_WPSCount += 1
                        WPSVer=LineList[3].lstrip().rstrip()
                        WPSLock=LineList[4].lstrip().rstrip()
                    x=0
                    foundloc=0
                    Skip=""
                    while x < len(ListInfo_BSSID):
                        if BSSID==ListInfo_BSSID[x]:
                            Skip="1"
                            foundloc=x
                            x = len(ListInfo_BSSID)
                            if ListInfo_WPS[foundloc]!="Yes":
                                __builtin__.ListInfo_WPSAdd += 1
                            else:
                                __builtin__.ListInfo_WPSExist += 1
                        x=x+1
                    if Skip=="1":
                        ListInfo_WPS[foundloc] = "Yes"
                        ListInfo_WPSVer[foundloc] = WPSVer
                        ListInfo_WPSLock[foundloc] = WPSLock

def DisplayESSIDDetail(MACAddr,MACColor):
    Result=""
    ESSID=FindESSID(MACAddr)
    if ESSID=="":
        ESSID=fcolor.BIGray + "<<NO NAME>>"
    Result=ColorStd2 + "  BSSID    [ " + MACColor + str(MACAddr) + ColorStd2 + " ]'s Name is [ " + fcolor.BYellow + str(ESSID) + ColorStd2 + " ].\n"
    return Result

def DisplaySSIDDetail(MACAddr):
    i=0
    Result=""
    while i < len(ListInfo_BSSID):
        if str(ListInfo_BSSID[i])==str(MACAddr):
            PrivacyDetail=str(ListInfo_Privacy[i]) + " / " + str(ListInfo_Cipher[i]) + " / " + str(ListInfo_Auth[i])
            Result= ColorStd2  + "  Details  : " + fcolor.BGreen + str(PrivacyDetail).ljust(36) + ColorStd2 + "Channel : " + fcolor.BGreen + str(ListInfo_Channel[i]).ljust(9) + ColorStd2 + "Client : " + fcolor.BGreen + str(ListInfo_ConnectedClient[i]).ljust(9)  + ColorStd2 + "WPS : " + fcolor.BGreen + str(ListInfo_WPS[i]).ljust(5)  + "\n"
            return str(Result);
        i += 1
    return Result;

def GetSignal(MACAddr):
    Signal=""
    foundloc=FindMACIndex(MACAddr,ListInfo_BSSID)
    if foundloc==-1:
        foundloc=FindMACIndex(MACAddr,ListInfo_STATION)
        if foundloc!=-1:
            Signal=ListInfo_CBestQuality[foundloc]
    else:
        Signal=ListInfo_BestQuality[foundloc]
    return Signal

def GetSignalData(MACAddr):
    Signal=""
    foundloc=FindMACIndex(MACAddr,ListInfo_BSSID)
    if foundloc==-1:
        foundloc=FindMACIndex(MACAddr,ListInfo_STATION)
        if foundloc!=-1:
            Signal=ListInfo_CBestQuality[foundloc]
            Signal=Signal + " / " + ListInfo_CQualityRange[foundloc]
    else:
        Signal=ListInfo_BestQuality[foundloc]
        Signal=Signal + " / " + ListInfo_QualityRange[foundloc]
    return Signal

def ReplaceSlash(sStr,sColor,slColor):
    if sStr[-3:]==" / ":
        sStr=sStr[:-3]
    sStr=sStr.replace(" / ",slColor + " / " + sColor)
    return sColor + sStr

def RemoveDoubleLF(strValue):
    ax=0
    while ax<3:
        strValue=str(strValue).replace("\n\n","\n")
        ax += 1
    return strValue

def RemoveAdditionalLF(strValue):
    ax=0
    while ax<3:
        strValue=str(strValue).replace("\n\n\n","\n\n")
        ax += 1
    return strValue

def DisplayOUIDetail(MACAddr,MACColor):
    Result=""
    OUI=Check_OUI(MACAddr,"")
    Result=ColorStd2 + "  MAC Addr [ " + MACColor + str(MACAddr) + ColorStd2 + " ]'s MAC OUI belongs to [ " + fcolor.SCyan + str(OUI) + ColorStd2 + " ].\n"
    return Result

def ListDuplicate(clist):
    seen = set()
    seen_add = seen.add
    seen_twice = set(x for x in clist if x in seen or seen_add(x))
    return list(seen_twice)

def ConvertNoToAlpha(num):
    chrlist=['-','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    return chrlist[int(num)]

def CheckWhitelist(sVal):
    if str(__builtin__.WhiteMACList).find("'" + sVal + "'")!=-1 or str(__builtin__.WhiteNameList).find("'" + sVal + "'")!=-1:
        return sVal
    return ""

def CheckDiffBSSIDConnection():
    x=0
    __builtin__.MSG_DiffBSSIDConnection=""
    __builtin__.MSG_NoAssocConnection=""
    __builtin__.MSG_APnClient=""
    __builtin__.MSG_EvilTwins=""
    tmpAll_ESSID=[]
    ColorSeen=fcolor.SBlue
    CautiousCount=0
    x=0
    while x < len(ListInfo_ESSID):
        tmpAll_ESSID.append (ListInfo_ESSID[x])
        x += 1
    Similar_ESSID=ListDuplicate(tmpAll_ESSID)
    Similar_ESSID=filter(None,Similar_ESSID)
    if len(Similar_ESSID)>0:
        x=0
        while x<len(Similar_ESSID) and CheckWhitelist(Similar_ESSID[x])=="":
            print "CheckWhitelist : " + str(CheckWhitelist(Similar_ESSID[x]))
            if len(str(x))==1:
                spacer="  "
            if len(str(x))==2:
                spacer=" "
            y=0
            bssidct=0
            CautiousCount += 1
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + fcolor.SWhite + "[" + fcolor.BRed + str(CautiousCount) + fcolor.SWhite + "]" + spacer + fcolor.BGreen + "SSID Name   [ " + fcolor.BPink + str(Similar_ESSID[x]) + fcolor.BGreen + " ]\n"
            while y<len(ListInfo_ESSID):
                if ListInfo_ESSID[y]==Similar_ESSID[x]:
                    BSSID=ListInfo_BSSID[y]
                    BSSIDOUI=Check_OUI(BSSID,"")
                    BSSIDSIGNAL=__builtin__.ListInfo_BestQuality[y] + " dBm / " + RemoveColor(__builtin__.ListInfo_QualityRange[y])
                    CONNECTED_CLIENT=""
                    CONNECTED_CLIENT_CT=0
                    p=0
                    while p<len(__builtin__.ListInfo_CBSSID):
                        if __builtin__.ListInfo_CBSSID[p]==BSSID:
                            CONNECTED_CLIENT=CONNECTED_CLIENT + __builtin__.ListInfo_STATION[p] + " / "
                            CONNECTED_CLIENT_CT += 1
                        p += 1
                    bssidct +=1
                    if CONNECTED_CLIENT!="":
                        CONNECTED_CLIENT=ReplaceSlash(CONNECTED_CLIENT,fcolor.SBlue,fcolor.SWhite)
                    BSSIDText=fcolor.BWhite + str(ConvertNoToAlpha(bssidct)) + ". " + fcolor.BBlue + "BSSID    " + fcolor.SWhite + "[ " + fcolor.BYellow + str(BSSID) + fcolor.SWhite + " ] - Signal : " + fcolor.BGreen + BSSIDSIGNAL.ljust(24) + "" + fcolor.SCyan + str(BSSIDOUI) + "\n"
                    BSSIDText=BSSIDText.replace(" / Good",fcolor.SWhite + " / " + fcolor.SGreen + "Good").replace(" / Average",fcolor.SWhite + " / " + fcolor.SYellow + "Average").replace(" / Poor",fcolor.SWhite + " / " + fcolor.SRed + "Poor").replace(" / Unknown",fcolor.SBlack + " / " + fcolor.SGreen + "Unknown").replace(" / V.Good",fcolor.BGreen + " / " + fcolor.SGreen + "V.Good")
                    __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "   " + spacer + BSSIDText
                    __builtin__.MSG_EvilTwins = __builtin__.MSG_EvilTwins + "      " + str(DisplaySSIDDetail(BSSID))
                    if CONNECTED_CLIENT_CT==0:
                        __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "    " + spacer + fcolor.SWhite + "  Client   [ " + fcolor.SRed + "No Client Found" + fcolor.SWhite + " ]\n"                    
                    else:
                        __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "    " + spacer + fcolor.SWhite + "  Client   [ " + fcolor.BRed + str(CONNECTED_CLIENT_CT) + fcolor.SWhite + " ] - " + fcolor.SBlue + str(CONNECTED_CLIENT) + "\n"
                y += 1
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "\n"
            x += 1
        if __builtin__.MSG_EvilTwins!="":
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "\n" + fcolor.BCyan + "     Note  : " + fcolor.SWhite + "Shown above are Access Points with Similar Name, Evil-Twin in normal cases are usually open network or encrypted if passphase is known."
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "\n" + fcolor.BCyan + "             " + fcolor.SWhite + "Senario where similar names are commonly found in organization, airport, mall, hotel, campus, etc where the area is big."
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + "\n" + fcolor.BCyan + "             " + fcolor.SWhite + "Multiple " + fcolor.SRed + "[Deauthentication]" + fcolor.SWhite + " found on said Access Point detect may indicate high possibility of " + fcolor.SRed + "Evil-Twin\n"
            __builtin__.MSG_EvilTwins=__builtin__.MSG_EvilTwins + ReportNow() + "\n"
            __builtin__.MSG_EvilTwins=fcolor.BRed + str(CautiousCount) + " Similar SSID Names Detected !!!\n" + __builtin__.MSG_EvilTwins
    while x < len(ListInfo_STATION):
        y=0
	if str(ListInfo_BSSID).find(str(ListInfo_STATION[x]))!=-1 and CheckWhitelist(ListInfo_STATION[x])=="":
            y=int(str(ListInfo_BSSID).find(ListInfo_STATION[x]))-2
            y=y/21
            while y < len(ListInfo_BSSID):
                if ListInfo_STATION[x]==ListInfo_BSSID[y]:
                    ConnectedBSSID=""
                    if int(ListInfo_SSIDTimeGap[y])<int(__builtin__.HIDE_AFTER_MIN) and int(ListInfo_CTimeGap[x])<int(__builtin__.HIDE_AFTER_MIN):
                        CautiousCount += 1
                        OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd + "Device MAC [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] is found to be both an " + fcolor.BRed + "Access Point " + ColorStd + "&" + fcolor.BRed + " Wireless Client\n" 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_STATION[x],ColorDev))
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(OUITxt) 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_STATION[x])) 
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Ac. Pt.  : First Seen on [ " + ColorSeen + str(ListInfo_FirstSeen[y]) + ColorStd2 + " ] and Last Seen on [ " + ColorSeen + str(ListInfo_LastSeen[y]) + ColorStd2 + " ] (Last seen " + str(ListInfo_SSIDTimeGap[y]) + " mins ago)\n"
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Station  : First Seen on [ " + ColorSeen + str(ListInfo_CFirstSeen[x]) + ColorStd2 + " ] and Last Seen on [ " + ColorSeen + str(ListInfo_CLastSeen[x]) + ColorStd2 + " ] (Last seen " + str(ListInfo_CTimeGap[x]) + " mins ago)\n" 
                        if str(ListInfo_CBSSIDPrev[x]).find("Not Associated")==-1:
                            OUITxt2=DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetSignalData(str(ListInfo_STATION[x]))) + ColorStd2 + " ==>  [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd2 + " ] = " + Color1st  + str(GetSignalData(str(ListInfo_CBSSIDPrev[x]))) + "\n"
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ArrangeSignalLocation(ColorDev,str(ListInfo_STATION[x]),str(GetSignal(str(ListInfo_STATION[x]))),Color1st,ListInfo_CBSSIDPrev[x],str(GetSignal(ListInfo_CBSSIDPrev[x])),"  ",ColorStd2,"")
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st))
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + OUITxt2
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_CBSSIDPrev[x]))
                            ConnectedBSSID=ListInfo_CBSSIDPrev[x]
                        if str(ListInfo_CBSSID[x]).find("Not Associated")==-1 and ListInfo_CBSSIDPrev[x]!=ListInfo_CBSSID[x]:
                            OUITxt2=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ColorStd2 + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd2 + " ] = " + ColorDev + str(GetSignalData(str(ListInfo_STATION[x]))) + ColorStd2 + " ==>  [ " + Color1st + str(ListInfo_CBSSID[x]) + ColorStd2 + " ] = " + Color2nd  + str(GetSignalData(str(ListInfo_CBSSID[x]))) + "\n"
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + ArrangeSignalLocation(ColorDev,str(ListInfo_STATION[x]),str(GetSignal(str(ListInfo_STATION[x]))),Color1st,ListInfo_CBSSID[x],str(GetSignal(ListInfo_CBSSID[x])),"  ",ColorStd2,"")
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd))
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + OUITxt2
                            __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
                            ConnectedBSSID=ListInfo_CBSSID[x]
                            
                        __builtin__.MSG_APnClient = __builtin__.MSG_APnClient + str(ReportNow()) + "\n"
                        SkipWrite=0
                        if IsFileDirExist(DBFile1)=="F":
                            with open(DBFile1,"r") as f:
                                for line in f:
                                    line=line.replace("\n","")
                                    line=line.replace("\r","")
                                    if SkipWrite==0:
                                        sl=len(line.replace("\n",""))
                                        if sl>34:
                                            tmplist=[]
                                            tmplist=str(line).split(";")
                                            if len(tmplist)>4:
                                                if tmplist[0]==str(ListInfo_STATION[x]) and tmplist[1]==str(ConnectedBSSID) and tmplist[5]==str(ListInfo_ESSID[y]):
                                                    SkipWrite=1
                                                    break
                        if SkipWrite==0:
                            col=";"
                            WriteData=str(ListInfo_STATION[x]) + str(col) + str(ConnectedBSSID) + str(col) + str(ListInfo_FirstSeen[y]) + str(col) + str(ListInfo_CFirstSeen[x]) + str(col) + str(Now())  + str(col) + str(ListInfo_ESSID[y]) + str(col) + "\n"
                            open(DBFile1,"a+b").write(WriteData)
                    y=len(ListInfo_BSSID)
                y += 1
        if ListInfo_CBSSIDPrev[x]!=ListInfo_CBSSID[x] and CheckWhitelist(ListInfo_STATION[x])=="":
            if ListInfo_CBSSIDPrev[x].find("Not Associated")==-1:
               OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
               OUITxt2=DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)
               ESSIDTxt2=DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st)
               OUITxt3=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
               ESSIDTxt3=DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd)
               CautiousCount += 1
               if len(str(x))==1:
                   spacer="  "
               if len(str(x))==2:
                   spacer=" "
               if ListInfo_CBSSID[x]=="Not Associated":
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd + " Device    [ "  + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] initially associated with [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] is now not associated with any access point.\n"
               else:
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd + " Device    [ "  + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] initially associated with [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] is now associated to [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ].\n" 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_STATION[x],ColorDev)) 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd2 + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetSignalData(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color1st + str(ListInfo_CBSSIDPrev[x]) + ColorStd + " ] = " + Color1st  + str(GetSignalData(str(ListInfo_CBSSIDPrev[x]))) + "\n"
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ArrangeSignalLocation(ColorDev,str(ListInfo_STATION[x]),str(GetSignal(str(ListInfo_STATION[x]))),Color1st,ListInfo_CBSSIDPrev[x],str(GetSignal(ListInfo_CBSSIDPrev[x])),"  ",ColorStd2,"")
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ColorStd2 + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetSignalData(str(ListInfo_STATION[x]))) + ColorStd + " ==>  [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ] = " + Color2nd + str(GetSignalData(str(ListInfo_CBSSID[x]))) + "\n"
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + ArrangeSignalLocation(ColorDev,str(ListInfo_STATION[x]),str(GetSignal(str(ListInfo_STATION[x]))),Color1st,ListInfo_CBSSID[x],str(GetSignal(ListInfo_CBSSID[x])),"  ",ColorStd2,"")
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayESSIDDetail(ListInfo_CBSSIDPrev[x],Color1st))  
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_CBSSIDPrev[x],Color1st)) 
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplaySSIDDetail(ListInfo_CBSSIDPrev[x]))
               if str(ListInfo_CBSSID[x]).find("Not Associated")==-1:
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd))
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd))
                   __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
               __builtin__.MSG_DiffBSSIDConnection = __builtin__.MSG_DiffBSSIDConnection + str(ReportNow()) + "\n"
               WriteSwitchedAP(ListInfo_STATION[x],ListInfo_CBSSIDPrev[x],ListInfo_CBSSID[x],FindESSID(ListInfo_CBSSIDPrev[x]), FindESSID(ListInfo_CBSSID[x]))
            else:
               CautiousCount += 1
               if len(str(x))==1:
                   spacer="  "
               if len(str(x))==2:
                   spacer=" "
               OUITxt=DisplayOUIDetail(ListInfo_STATION[x],ColorDev)
               OUITxt3=DisplayOUIDetail(ListInfo_CBSSID[x],Color2nd)
               ESSIDTxt3=DisplayESSIDDetail(ListInfo_CBSSID[x],Color2nd)
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + ColorStd +  " Device    [ "  + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] initially not associated is now associated with [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ].\n" 
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + ColorStd2 + "  Signal   [ " + ColorDev + str(ListInfo_STATION[x]) + ColorStd + " ] = " + ColorDev + str(GetSignalData(str(ListInfo_STATION[x]))) + ColorStd + " ==> [ " + Color2nd + str(ListInfo_CBSSID[x]) + ColorStd + " ] = " + Color2nd  + str(GetSignalData(str(ListInfo_CBSSID[x]))) + "\n"
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + ArrangeSignalLocation(ColorDev,str(ListInfo_STATION[x]),str(GetSignal(str(ListInfo_STATION[x]))),Color1st,ListInfo_CBSSID[x],str(GetSignal(ListInfo_CBSSID[x])),"  ",ColorStd2,"")
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(OUITxt) + str(ESSIDTxt3) + str(OUITxt3) 
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(DisplaySSIDDetail(ListInfo_CBSSID[x]))
               __builtin__.MSG_NoAssocConnection = __builtin__.MSG_NoAssocConnection + str(ReportNow())+ "\n"
            ListInfo_CBSSIDPrev[x]=ListInfo_CBSSID[x]
            if str(ListInfo_CBSSIDPrevList[x]).find(str(ListInfo_CBSSID[x]))==-1:
                ListInfo_CBSSIDPrevList[x]=ListInfo_CBSSIDPrevList[x] + str(ListInfo_CBSSID[x]) + " | " 
        x += 1
    if __builtin__.MSG_DiffBSSIDConnection!="" or __builtin__.MSG_NoAssocConnection!="" or __builtin__.MSG_APnClient!="" or __builtin__.MSG_EvilTwins!="":
        if __builtin__.SHOW_CONNECTION_ALERT=="Yes":
            CenterText(fcolor.BGIYellow + fcolor.BRed,"=====  ASSOCIATION/CONNECTION  ALERT  [ " + str(CautiousCount) + " ] ===== ")
            print ""
            BeepSound()
            if __builtin__.MSG_EvilTwins!="":
                __builtin__.MSG_EvilTwins=str(__builtin__.MSG_EvilTwins).replace("\n\n\n","\n\n")
                print str(__builtin__.MSG_EvilTwins)
                WriteCautiousLog(__builtin__.MSG_EvilTwins)
                if str(__builtin__.MSG_HistoryConnection).find(__builtin__.MSG_EvilTwins)==-1:
                    __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_EvilTwins + "\n"
                    __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)
                    __builtin__.MSG_CombinationLogs=__builtin__.MSG_CombinationLogs + __builtin__.MSG_EvilTwins + ""
            if __builtin__.MSG_APnClient!="":
                __builtin__.MSG_APnClient=fcolor.BRed + "Dual Device Type Detected !!!\n" + __builtin__.MSG_APnClient
                __builtin__.MSG_APnClient=str(__builtin__.MSG_APnClient).replace("\n\n\n","\n\n")
                print str(__builtin__.MSG_APnClient)
                WriteCautiousLog(__builtin__.MSG_APnClient)
                if str(__builtin__.MSG_HistoryConnection).find(__builtin__.MSG_APnClient)==-1:
                    __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_APnClient + "\n"
                    __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)
                    __builtin__.MSG_CombinationLogs=__builtin__.MSG_CombinationLogs + __builtin__.MSG_APnClient + ""
            if __builtin__.MSG_NoAssocConnection!="":
                __builtin__.MSG_NoAssocConnection=fcolor.BRed + "New Association Detected !!!\n" + __builtin__.MSG_NoAssocConnection
                __builtin__.MSG_NoAssocConnection=str(__builtin__.MSG_NoAssocConnection).replace("\n\n\n","\n\n")
                print str(__builtin__.MSG_NoAssocConnection)
                WriteCautiousLog(__builtin__.MSG_NoAssocConnection)
                __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_NoAssocConnection + "\n"
                __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)
                __builtin__.MSG_CombinationLogs=__builtin__.MSG_CombinationLogs + __builtin__.MSG_NoAssocConnection + ""
            if __builtin__.MSG_DiffBSSIDConnection!="":
                __builtin__.MSG_DiffBSSIDConnection=fcolor.BRed + "Station Switching Connection\n" + __builtin__.MSG_DiffBSSIDConnection
                __builtin__.MSG_DiffBSSIDConnection=str(__builtin__.MSG_DiffBSSIDConnection).replace("\n\n\n","\n\n")
                WriteCautiousLog(__builtin__.MSG_DiffBSSIDConnection)
                print str(__builtin__.MSG_DiffBSSIDConnection)
                __builtin__.MSG_HistoryConnection=__builtin__.MSG_HistoryConnection + __builtin__.MSG_DiffBSSIDConnection + ""
                __builtin__.MSG_HistoryConnection=RemoveAdditionalLF(__builtin__.MSG_HistoryConnection)
                __builtin__.MSG_CombinationLogs=__builtin__.MSG_CombinationLogs + __builtin__.MSG_DiffBSSIDConnection + ""
            LineBreak()

def WriteSwitchedAP(StnMAC,PrevBSSID,NewBSSID,PrevESSID,NewESSID):
    SkipWrite=0
    with open(DBFile6,"r") as f:
        next(f)
        for line in f:
            line=line.replace("\n","").replace("\r","")
            sl=len(line)
            if SkipWrite==0 and sl>17:
                tmplist=[]
                tmplist=str(line).split(";")
                if len(tmplist)>=6:
                    if tmplist[0]==str(StnMAC) and tmplist[1]==str(PrevBSSID) and tmplist[2]==str(NewBSSID) and tmplist[4]==str(PrevESSID)  and tmplist[5]==str(NewESSID):
                        SkipWrite=1
        if SkipWrite==0 and RemoveUnwantMAC(StnMAC)!="":
            WriteData=str(StnMAC) + str(col)
            WriteData=WriteData + str(PrevBSSID) + str(col)  
            WriteData=WriteData + str(NewBSSID) + str(col) 
            WriteData=WriteData + str(Now()) + str(col)
            WriteData=WriteData + str(PrevESSID) + str(col) 
            WriteData=WriteData + str(NewESSID) + str(col) + "\n"
            open(DBFile6,"a+b").write(WriteData)

def WriteCautiousLog(StrVal):
    StrVal=RemoveColor(StrVal)
    if IsFileDirExist(CautiousLog)!="F":
        open(CautiousLog,"w").write("")
    if IsFileDirExist(CautiousLog)=="F":
        open(CautiousLog,"a+b").write(StrVal)

def WriteAttackLog(StrVal):
    StrVal=RemoveColor(StrVal)
    if IsFileDirExist(AttackLog)!="F":
        open(AttackLog,"w").write("")
    if IsFileDirExist(AttackLog)=="F":
        open(AttackLog,"a+b").write(StrVal)

def WriteSuspiciousLog(StrVal):
    StrVal=RemoveColor(StrVal) + "\n"
    StrVal=str(StrVal).replace("\n\n","\n")
    if StrVal.find("Total Record")!=-1:
        StrVal=StrVal+"\n"
    if IsFileDirExist(SuspiciousLog)!="F":
        open(SuspiciousLog,"w").write("")
    if IsFileDirExist(SuspiciousLog)=="F":
        open(SuspiciousLog,"a+b").write(StrVal)

def ExtractClient():
    LineList = []
    if IsFileDirExist(__builtin__.Client_CSV)=="F":
        with open(__builtin__.Client_CSV,"r") as f:
            __builtin__.ListInfo_CExist = 0
            __builtin__.ListInfo_CAdd = 0
            __builtin__.ListInfo_CRemoved = 0
            __builtin__.ListInfo_BRemoved = 0
            __builtin__.ListInfo_UnassociatedCount = 0
            __builtin__.ListInfo_AssociatedCount = 0
            __builtin__.ListInfo_ProbeCount = 0
            for line in f:
                line=line.replace("\n","").replace("\00","").replace("\r","")
                if len(line)>=94:
                    line=line + ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
                    st = list(line)
                    st[18]=";"
                    st[39]=";"
                    st[60]=";"
                    st[65]=";"
                    st[75]=";"
                    st[94]=";"
                    lp="".join(st)
                    lp=lp.replace(",;","; ")
                    LineList=lp.split(";")
                    STATION=LineList[0]
                    if len(STATION)==17:
                        foundloc=FindMACIndex(STATION,ListInfo_BSSID)
                        cBSSID=LineList[5]
                        if foundloc!=-1:
                            if CheckRepeat(STATION)!="-" and cBSSID!="(not associated)":
                                STATION=""
                    if len(STATION)==17:
                        x=0
                        foundloc=0
                        Skip=""
                        if str(ListInfo_STATION).find(STATION)!=-1:
                            foundloc=FindMACIndex(STATION,ListInfo_STATION)
                            Skip="1"
                            if __builtin__.ListInfo_STATION[foundloc]!=STATION:
                                print "STATION : " + str(STATION)
                                print "ListInfo_STATION[foundloc] : " + str(ListInfo_STATION[foundloc])
                                printc ("x","","")
                        CQualityPercent=0
                        CQRange=fcolor.SBlack + "Unknown"
                        CSignal=str(LineList[3]).lstrip().rstrip()
                        if len(CSignal)>1 and len(CSignal)<4:
                            CSignal=CSignal.replace("-","")
                            if CSignal.isdigit()==True:
                                CSignal="-" + str(CSignal)
                                CQualityPercent=int(100 + int(CSignal))
                                if CQualityPercent>=99 or CQualityPercent==0:  
                                    CQRange=fcolor.SBlack + "Unknown"
                                if CQualityPercent>=70 and CQualityPercent<=98:
                                    CQRange=fcolor.SGreen + "V.Good"
                                if CQualityPercent>=50 and CQualityPercent<=69:
                                    CQRange=fcolor.SGreen + "Good"
                                if CQualityPercent>=26 and CQualityPercent<=49:
                                    CQRange=fcolor.SYellow + "Average"
                                if CQualityPercent>=1 and CQualityPercent<=25:
                                    CQRange=fcolor.SRed + "Poor"
                        ProbesData=LineList[6]
                        ProbesData=ProbesData.replace(","," / ").lstrip().rstrip()
                        Assoc=LineList[5]
                        if ProbesData!="":
                            __builtin__.ListInfo_ProbeCount += 1
                        if Assoc!="":
                            Assoc=str(Assoc).lstrip().rstrip()
                            Assoc=str(Assoc).replace("(not associated)","Not Associated")
                        if Assoc.find("Not Associated")==-1:
                            __builtin__.ListInfo_AssociatedCount += 1
                        else:
                            Assoc="Not Associated"
                            __builtin__.ListInfo_UnassociatedCount += 1
                        if Assoc!="Not Associated":
                            ESSID=FindESSID(Assoc)
                        else:
                            ESSID=""
                        CLIENT_OUI=Check_OUI(STATION,"")
                        StartTime=LineList[1].lstrip().rstrip()
                        EndTime=LineList[2].lstrip().rstrip()
                        Elapse=CalculateTime (StartTime,EndTime)
                        DontAdd=0
                        if int(__builtin__.TimeGap)>= int(__builtin__.TOTALLY_REMOVE_MIN):
                            DontAdd=1
                            Skip=="1"
                        if Skip=="":
                            __builtin__.ListInfo_CAdd += 1
                            __builtin__.ListInfo_STATION.append (str(STATION).lstrip().rstrip())
                            __builtin__.ListInfo_CFirstSeen.append ((LineList[1]).lstrip().rstrip())
                            __builtin__.ListInfo_CLastSeen.append ((LineList[2]).lstrip().rstrip())
                            __builtin__.ListInfo_CBestQuality.append (str(LineList[3]).lstrip().rstrip())
                            __builtin__.ListInfo_CQualityRange.append (CQRange)
                            __builtin__.ListInfo_CQualityPercent.append (CQualityPercent)
                            __builtin__.ListInfo_CPackets.append (str(LineList[4]).lstrip().rstrip())
                            __builtin__.ListInfo_STNStandard.append ("-")
                            __builtin__.ListInfo_CBSSID.append (str(Assoc).lstrip().rstrip())
                            __builtin__.ListInfo_CBSSIDPrev.append (str(Assoc).lstrip().rstrip())
                            __builtin__.ListInfo_CBSSIDPrevList.append (str(Assoc).lstrip().rstrip() + " | ")
                            __builtin__.ListInfo_PROBE.append (str(ProbesData).lstrip().rstrip())
                            __builtin__.ListInfo_CESSID.append (str(ESSID).lstrip().rstrip())
                            __builtin__.ListInfo_COUI.append (str(CLIENT_OUI).lstrip().rstrip())
                            StartTime=LineList[1].lstrip().rstrip()
                            EndTime=LineList[2].lstrip().rstrip()
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_CElapse.append (Elapse)
                            __builtin__.ListInfo_CTimeGap.append (__builtin__.TimeGap)
                            __builtin__.ListInfo_CTimeGapFull.append (__builtin__.TimeGapFull)
                        elif DontAdd==0:
                            __builtin__.ListInfo_CExist += 1
                            __builtin__.ListInfo_STATION[foundloc] = str(STATION).lstrip().rstrip()
                            __builtin__.ListInfo_CFirstSeen[foundloc] = str(LineList[1]).lstrip().rstrip()
                            __builtin__.ListInfo_CLastSeen[foundloc] = str(LineList[2]).lstrip().rstrip()
                            __builtin__.ListInfo_CBestQuality[foundloc] = str(LineList[3]).lstrip().rstrip()
                            __builtin__.ListInfo_CQualityRange[foundloc] = str(CQRange)
                            __builtin__.ListInfo_CQualityPercent[foundloc] = str(CQualityPercent)
                            __builtin__.ListInfo_CPackets[foundloc] = str(LineList[4]).lstrip().rstrip()
                            __builtin__.ListInfo_CBSSID[foundloc] = str(Assoc).lstrip().rstrip()
                            __builtin__.ListInfo_CESSID[foundloc] = str(ESSID).lstrip().rstrip()
                            __builtin__.ListInfo_PROBE[foundloc] = str(ProbesData).lstrip().rstrip()
                            __builtin__.ListInfo_COUI[foundloc] = str(CLIENT_OUI).lstrip().rstrip()
    RemoveInactive()

def RemoveInactive():
   try:
    x=0
    x=len(__builtin__.ListInfo_BSSID)-1
    while x >-1:
        if int(__builtin__.ListInfo_SSIDTimeGap[x]) >= int(__builtin__.TOTALLY_REMOVE_MIN):
            ListInfo_ESSID.pop(x)
            ListInfo_HiddenSSID.pop(x)
            ListInfo_BSSIDTimes.pop(x)
            ListInfo_BSSID.pop(x)
            ListInfo_Channel.pop(x)
            ListInfo_APStandard.pop(x)
            ListInfo_ESS.pop(x)
            ListInfo_Cloaked.pop(x)
            ListInfo_Privacy.pop(x)
            ListInfo_Cipher.pop(x)
            ListInfo_Auth.pop(x)
            ListInfo_MaxRate.pop(x)
            ListInfo_Beacon.pop(x)
            ListInfo_Data.pop(x)
            ListInfo_Total.pop(x)
            ListInfo_FirstSeen.pop(x)
            ListInfo_LastSeen.pop(x)
            ListInfo_BestQuality.pop(x)
            ListInfo_BestSignal.pop(x)
            ListInfo_BestNoise.pop(x)
            ListInfo_GPSBestLat.pop(x)
            ListInfo_GPSBestLon.pop(x)
            ListInfo_GPSBestAlt.pop(x)
            ListInfo_QualityRange.pop(x)
            ListInfo_QualityPercent.pop(x)
            ListInfo_BSSID_OUI.pop(x)
            ListInfo_WPS.pop(x)
            ListInfo_WPSVer.pop(x)
            ListInfo_WPSLock.pop(x)
            ListInfo_ConnectedClient.pop(x)
            ListInfo_Freq.pop(x)
            ListInfo_Signal.pop(x)
            ListInfo_Enriched.pop(x)
            ListInfo_Quality.pop(x)
            ListInfo_BitRate.pop(x)
            ListInfo_WPAVer.pop(x)
            ListInfo_PairwiseCipher.pop(x)
            ListInfo_GroupCipher.pop(x)
            ListInfo_AuthSuite.pop(x)
            ListInfo_LastBeacon.pop(x)
            ListInfo_Mode.pop(x)
            ListInfo_EncKey.pop(x)
            ListInfo_SSIDElapse.pop(x)
            ListInfo_SSIDTimeGap.pop(x)
            ListInfo_SSIDTimeGapFull.pop(x)
            __builtin__.ListInfo_BRemoved += 1
        else:
            y=0
            y=len(__builtin__.ListInfo_STATION)-1
            while y >-1:
                if int(__builtin__.ListInfo_CTimeGap[y]) >= int(__builtin__.TOTALLY_REMOVE_MIN):
                    ListInfo_STATION.pop(y)
                    ListInfo_STNStandard.pop(y)
                    ListInfo_CFirstSeen.pop(y)
                    ListInfo_CLastSeen.pop(y)
                    ListInfo_CBestQuality.pop(y)
                    ListInfo_CQualityRange.pop(y)
                    ListInfo_CQualityPercent.pop(y)
                    ListInfo_CPackets.pop(y)
                    ListInfo_CBSSID.pop(y)
                    ListInfo_CBSSIDPrev.pop(y)
                    ListInfo_CBSSIDPrevList.pop(y)
                    ListInfo_PROBE.pop(y)
                    ListInfo_CESSID.pop(y)
                    ListInfo_COUI.pop(y)
                    ListInfo_CElapse.pop(y)
                    ListInfo_CTimeGap.pop(y)
                    ListInfo_CTimeGapFull.pop(y)
                    __builtin__.ListInfo_CRemoved += 1
                y=y-1
        x -= 1
    RecalculateClient()
   except:
    RecalculateClient()
    return

def RecalculateClient():
    x=0
    while x<len(ListInfo_BSSID):
        ListInfo_ConnectedClient[x]="0"
        StartTime=__builtin__.ListInfo_FirstSeen[x]
        EndTime=__builtin__.ListInfo_LastSeen[x]
        Elapse=CalculateTime (StartTime,EndTime)
        __builtin__.ListInfo_SSIDElapse[x]= str(Elapse)
        __builtin__.ListInfo_SSIDTimeGap[x]= str(__builtin__.TimeGap)
        __builtin__.ListInfo_SSIDTimeGapFull[x]= str(__builtin__.TimeGapFull)
        x += 1
    x=0
    while x<len(ListInfo_STATION):
        StartTime=__builtin__.ListInfo_CFirstSeen[x]
        EndTime=__builtin__.ListInfo_CLastSeen[x]
        Elapse=CalculateTime (StartTime,EndTime)
        __builtin__.ListInfo_CElapse[x]= str(Elapse)
        __builtin__.ListInfo_CTimeGap[x]= str(__builtin__.TimeGap)
        __builtin__.ListInfo_CTimeGapFull[x]= str(__builtin__.TimeGapFull)
        if ListInfo_CBSSID[x]!="Not Associated":
            foundloc=FindMACIndex(ListInfo_CBSSID[x],ListInfo_BSSID)
            if foundloc!=-1:
                CLN=ListInfo_ConnectedClient[foundloc]
                CLN=int(CLN)+1
                ListInfo_ConnectedClient[foundloc]=int(CLN)
        x=x+1

def FindESSID(MACAddr):
    BSSIDLoc=str(ListInfo_BSSID).find(str(MACAddr))
    if BSSIDLoc!=-1:
        ax=int(BSSIDLoc) -2
        ax=ax/21
        if ListInfo_BSSID[ax]==MACAddr:
            Result=ListInfo_ESSID[ax]
            return Result
        else:
            print "ax = " + str(ax)
            print "MACAddr = " + str(MACAddr)
            print "ListInfo_BSSID[ax] = " + str(ListInfo_BSSID[ax])
            printc ("x","","")
    return ""

def EnrichDump():
    if IsFileDirExist(__builtin__.SSID_CSV)=="F":
        with open(__builtin__.SSID_CSV,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line)>20:
                    line=line + ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"
                    line=line.replace(",",";")
                    LineList=line.split(";")
                    BSSID=LineList[0]
                    FIRSTSEEN=LineList[1]
                    LASTSEEN=LineList[2]
                    CHANNEL=LineList[3]
                    FREQ=LineList[4]
                    ENCRYPTION=LineList[5].lstrip().rstrip()
                    CIPHER=LineList[6].lstrip().rstrip()
                    AUTH=LineList[7].lstrip().rstrip()
                    SIGNAL=LineList[8].lstrip().rstrip()
                    if CIPHER=="CCMP TKIP":
                        CIPHER="CCMP/TKIP"
                    x=0
                    while x < len(ListInfo_BSSID):
                        if BSSID==ListInfo_BSSID[x]:
                            if CIPHER!="":
                                ListInfo_Cipher[x] = CIPHER
                            if AUTH!="":
                                ListInfo_Auth[x] = AUTH
                            x=len(ListInfo_BSSID)
                        x=x+1

def ExtractDump():
    if __builtin__.DumpProc!="":
        KillSubProc(str(__builtin__.DumpProc))
    RunAirodump()
    cmdLine="ps -eo pid | grep '" + str(__builtin__.DumpProc) + "'"
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    ps.wait();ps.stdout.close()
    __builtin__.DumpProc=str(__builtin__.DumpProc)
    if str(readout)!=str(__builtin__.DumpProc):
        printc ("!", "[Network Monitor stopped - Restarting]","")
        RunAirodump()
        time.sleep(1)
    cmdLine="ps -eo pid | grep '" + str(__builtin__.WashProc) + "'"
    __builtin__.WashProc=str(__builtin__.WashProc)
    ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE)	
    readout=str(ps.stdout.read().replace("\n",""))
    readout=str(readout).lstrip().rstrip()
    ps.wait();ps.stdout.close()
    if str(readout)=="" or readout!=str(__builtin__.WashProc):
        if __builtin__.LOAD_WPS=="Yes" and __builtin__.FIXCHANNEL==0:
            printc ("!", "[WPS Monitor stopped - Restarting]","")
            RunWash()
            time.sleep(1)
    LineList = []
    Encryption = []
    __builtin__.ListInfo_Exist = 0
    __builtin__.ListInfo_Add = 0
    if IsFileDirExist(__builtin__.NewCaptured_Kismet)=="F":
        with open(__builtin__.NewCaptured_Kismet,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if line.find("Network;NetType;ESSID;BSSID;Info;Channel")==-1 and len(line)>10:
                    line=line + "0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;"
                    LineList=line.split(";")
                    BSSID=LineList[3]
                    if len(BSSID)==17:
                        ESSID=LineList[2]
                        if len(ESSID)==0:
                            ESSID=""
                        if len(ESSID)>=32:
                            ESSID=ESSID[:-32]
                        x=0
                        foundloc=0
                        Skip=""
                        mi=FindMACIndex(BSSID,ListInfo_BSSID)
                        if mi!=-1:
                            foundloc=mi
                            Skip="1"
                            if IsAscii(ESSID)==True and ESSID.find("\\x")==-1:
                                if ListInfo_BSSID[foundloc]==BSSID:
                                    if ListInfo_ESSID[foundloc]!="" and IsAscii(ESSID)==True and ESSID.find("\\x")==-1:
                                        ESSID=ListInfo_ESSID[foundloc]
                        QualityPercent=0
                        QRange=fcolor.SBlack + "Unknown"
                        if len(LineList[21])>1 and len(LineList[21])<4:
                            if str(LineList[21])=="No" or str(LineList[21])=="Yes":
                                LineList[21]=-1
                            QualityPercent=int(100 + int(LineList[21]))
                            if QualityPercent>=99 or QualityPercent==0:  
                                QRange=fcolor.SBlack + "Unknown"
                            if QualityPercent>=70 and QualityPercent<=98:
                                QRange=fcolor.SGreen + "V.Good"
                            if QualityPercent>=50 and QualityPercent<=69:
                                QRange=fcolor.SGreen + "Good"
                            if QualityPercent>=26 and QualityPercent<=49:
                                QRange=fcolor.SYellow + "Average"
                            if QualityPercent>=1 and QualityPercent<=25:
                                QRange=fcolor.SRed + "Poor"
                        Encryption=LineList[7].split(",")
                        Encryption.append ("-");Encryption.append ("-");Encryption.append ("-")
                        Privacy="";Ciper="";Auth=""
                        Privacy=Encryption[0];Ciper=Encryption[1];Auth=Encryption[2];
                        HiddenSSID="No"
                        if len(LineList[2])==0:
                            HiddenSSID="Yes"
                        BSSID_OUI=Check_OUI(BSSID,"")
                        StartTime=LineList[19].lstrip().rstrip()
                        StartTime2=str(LineList[19]).lstrip().rstrip()
                        EndTime=LineList[20].lstrip().rstrip()
                        StartTime=ConvertDateFormat(StartTime,"%c")
                        EndTime=ConvertDateFormat(EndTime,"%c")
                        if Skip=="":
                            __builtin__.ListInfo_Add += 1
                            ListInfo_ESSID.append (ESSID)
                            ListInfo_HiddenSSID.append (HiddenSSID)
                            ListInfo_BSSIDTimes.append ("1")
                            ListInfo_BSSID.append (LineList[3])
                            ListInfo_Channel.append (LineList[5])
                            ListInfo_APStandard.append ("-")
                            ListInfo_ESS.append ("-")
                            ListInfo_Cloaked.append (LineList[6])
                            ListInfo_Privacy.append (Privacy)
                            ListInfo_Cipher.append (Ciper)
                            ListInfo_Auth.append (Auth)
                            ListInfo_MaxRate.append (LineList[9])
                            ListInfo_Beacon.append (LineList[11])
                            ListInfo_Data.append (LineList[13])
                            ListInfo_Total.append (LineList[16])
                            ListInfo_FirstSeen.append (StartTime)
                            ListInfo_LastSeen.append (EndTime)
                            ListInfo_BestQuality.append (LineList[21])
                            ListInfo_BestSignal.append (LineList[22])
                            ListInfo_BestNoise.append (LineList[23])
                            ListInfo_GPSBestLat.append (LineList[32])
                            ListInfo_GPSBestLon.append (LineList[33])
                            ListInfo_GPSBestAlt.append (LineList[34])
                            ListInfo_QualityRange.append(QRange)
                            ListInfo_QualityPercent.append (str(QualityPercent))
                            ListInfo_BSSID_OUI.append(BSSID_OUI)
                            ListInfo_WPS.append (str("-"))
                            ListInfo_WPSVer.append (str("-"))
                            ListInfo_WPSLock.append (str("-"))
                            ListInfo_ConnectedClient.append ("0")
                            __builtin__.ListInfo_Freq.append (str(GetFrequency(LineList[5])))
                            __builtin__.ListInfo_Signal.append (str("-"))
                            __builtin__.ListInfo_Enriched.append (str(""))
                            __builtin__.ListInfo_Quality.append (str("-"))
                            __builtin__.ListInfo_BitRate.append (str("-"))
                            __builtin__.ListInfo_WPAVer.append (str("-"))
                            __builtin__.ListInfo_PairwiseCipher.append (str("-"))
                            __builtin__.ListInfo_GroupCipher.append (str("-"))
                            __builtin__.ListInfo_AuthSuite.append (str("-"))
                            __builtin__.ListInfo_LastBeacon.append (str("-"))
                            __builtin__.ListInfo_Mode.append (str("-"))
                            __builtin__.ListInfo_EncKey.append (str("-"))
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_SSIDElapse.append (Elapse)
                            __builtin__.ListInfo_SSIDTimeGap.append (__builtin__.TimeGap)
                            __builtin__.ListInfo_SSIDTimeGapFull.append (__builtin__.TimeGapFull)
                        else:
                            __builtin__.ListInfo_Exist += 1
                            Times=ListInfo_BSSIDTimes[foundloc]
                            Times=int(Times)+1
                            ListInfo_BSSIDTimes[foundloc]=Times
                            ListInfo_HiddenSSID[foundloc]= HiddenSSID
                            ListInfo_BSSID[foundloc] = LineList[3]
                            if LineList[5]>0:
                                ListInfo_Channel[foundloc] =  LineList[5]
                            ListInfo_Cloaked[foundloc] = LineList[6]
                            if __builtin__.ListInfo_Enriched[foundloc]!="Yes":
                                ListInfo_Privacy[foundloc] = Privacy
                                ListInfo_Cipher[foundloc] = Ciper
                                ListInfo_Auth[foundloc] = Auth
                            if ESSID!="":
                                if str(ESSID).find("...")==-1 and str(ESSID).find("\\x")==-1:
                                    ListInfo_ESSID[foundloc] = ESSID
                                else:
                                    if str(ListInfo_ESSID[foundloc])== "":
                                        ListInfo_ESSID[foundloc] = ESSID
                            ListInfo_MaxRate[foundloc] = LineList[9]
                            ListInfo_Beacon[foundloc] = LineList[11]
                            ListInfo_Data[foundloc] = LineList[13]
                            ListInfo_Total[foundloc] = LineList[16]
                            ListInfo_FirstSeen[foundloc] = StartTime
                            ListInfo_LastSeen[foundloc] = EndTime
                            ListInfo_BestQuality[foundloc] = LineList[21]
                            ListInfo_BestSignal[foundloc] = LineList[22]
                            ListInfo_BestNoise[foundloc] = LineList[23]
                            ListInfo_GPSBestLat[foundloc] = LineList[32]
                            ListInfo_GPSBestLon[foundloc] = LineList[33]
                            ListInfo_GPSBestAlt[foundloc] = LineList[34]
                            ListInfo_QualityRange[foundloc] = QRange
                            ListInfo_QualityPercent[foundloc] = str(QualityPercent)
                            ListInfo_BSSID_OUI[foundloc] = str(BSSID_OUI)
                            ListInfo_ConnectedClient[foundloc]="0"
                            Elapse=CalculateTime (StartTime,EndTime)
                            __builtin__.ListInfo_SSIDElapse[foundloc]= str(Elapse)
                            __builtin__.ListInfo_SSIDTimeGap[foundloc]= __builtin__.TimeGap
                            __builtin__.ListInfo_SSIDTimeGapFull[foundloc]= __builtin__.TimeGapFull

def HighlightMonitoringMAC(MACAddr):
    x=0
    while x<len(__builtin__.MonitoringMACList):
        if MACAddr==__builtin__.MonitoringMACList[x]:
            MACAddr=fcolor.BRed + MACAddr
            return MACAddr
        x += 1
    return MACAddr

def GetWhitelist():
    WhitelistStr=""
    __builtin__.WhiteMACList=[]
    __builtin__.WhiteNameList=[]
    if IsFileDirExist(WhitelistFile)=="F":
        with open(WhitelistFile,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line) > 10:
                    if line[:8]=="MACID : ":
                        line=line[8:]
                        if len(line)==17:
                            __builtin__.WhiteMACList.append(line)
                    if line[:8]=="ESSID : ":
                        line=line[8:]
                        __builtin__.WhiteNameList.append(line)
    else:
        open(WhitelistFile,"a+b").write("")

def SaveWhitelist():
    if len(__builtin__.WhiteMACList)>0 or len(__builtin__.WhiteNameList)>0:
        open(WhitelistFile,"w").write("")
        x=0
        while x < len(__builtin__.WhiteMACList):
            open(WhitelistFile,"a+b").write("MACID : " + str(__builtin__.WhiteMACList[x]) + "\n")
            x=x+1
        x=0
        while x < len(__builtin__.WhiteNameList):
            open(WhitelistFile,"a+b").write("ESSID : " + str(__builtin__.WhiteNameList[x]) + "\n")
            x=x+1

def GetMonitoringMAC():
    MonitoringMACStr=""
    __builtin__.MonitoringMACList=[]
    __builtin__.MonitoringNameList=[]
    if IsFileDirExist(MonitorMACfile)=="F":
        with open(MonitorMACfile,"r") as f:
            for line in f:
                line=line.replace("\n","")
                line=line.replace("\00","")
                if len(line) > 10:
                    if line[:8]=="MACID : ":
                        line=line[8:]
                        if len(line)==17:
                            __builtin__.MonitoringMACList.append(line)
                    if line[:8]=="ESSID : ":
                        line=line[8:]
                        __builtin__.MonitoringNameList.append(line)
    else:
        open(MonitorMACfile,"a+b").write("")

def DisplayMonitoringMAC():
    if len(__builtin__.MonitoringMACList)==0 and len(__builtin__.MonitoringNameList)==0:
        printc ("i","No items was specified in current setting..","")
    else:
        printc (".", fcolor.BPink + "List of Monitoring Items","")
        x=0
        while x < len(__builtin__.MonitoringMACList):
            printc (" ",fcolor.SWhite + "MAC  : " + fcolor.BGreen + str(__builtin__.MonitoringMACList[x]),"")
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            printc (" ",fcolor.SWhite + "Name : " + fcolor.BGreen + str(__builtin__.MonitoringNameList[x]),"")
            x=x+1
        LineBreak()

def SaveMonitoringMAC():
    if len(__builtin__.MonitoringMACList)>0 or len(__builtin__.MonitoringNameList)>0:
        open(MonitorMACfile,"w").write("")
        x=0
        while x < len(__builtin__.MonitoringMACList):
            open(MonitorMACfile,"a+b").write("MACID : " + str(__builtin__.MonitoringMACList[x]) + "\n")
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            open(MonitorMACfile,"a+b").write("ESSID : " + str(__builtin__.MonitoringNameList[x]) + "\n")
            x=x+1

def CheckMonitoringMAC():
    List_MonitoringMAC=[]
    if len(__builtin__.MonitoringMACList)>0 or len(__builtin__.MonitoringNameList)>0:
        FoundCount=0
        InactiveCount=0
        InActiveMAC=""
        __builtin__.FoundMonitoringMAC=""
        x=0
        while x < len(__builtin__.MonitoringMACList):
            y=0
            while y < len(ListInfo_BSSID):
                if __builtin__.MonitoringMACList[x].upper()==ListInfo_BSSID[y].upper():
                    if int(__builtin__.ListInfo_SSIDTimeGap[y]) < int(__builtin__.HIDE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC = __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_LastSeen[y]).ljust(24) +   fcolor.SGreen + "BSSID   : " + fcolor.BYellow + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.BWhite + str(ListInfo_ESSID[y]) + "\n"
                        AddMACToList(__builtin__.MonitoringMACList[x].upper(),List_MonitoringMAC)
                    else:
                        InactiveCount += 1
                        InActiveMAC= InActiveMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite +  str(ListInfo_LastSeen[y]).ljust(24) + fcolor.SGreen + "BSSID   : " + fcolor.SYellow + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.SWhite + str(ListInfo_ESSID[y]) + "\n"
                y=y+1
            y=0
            while y < len(ListInfo_STATION):
                if __builtin__.MonitoringMACList[x].upper()==ListInfo_STATION[y].upper():
                    if int(__builtin__.ListInfo_CTimeGap[y]) < int(__builtin__.HIDE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_CLastSeen[y]).ljust(24)  + fcolor.SGreen + "Station : " + fcolor.BYellow + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        AddMACToList(str(__builtin__.MonitoringMACList[x]).upper(),List_MonitoringMAC)
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BWhite + str(ListInfo_CBSSID[y]) + fcolor.SGreen + "  [ " + fcolor.BWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BIGray + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            if ListInfo_CBSSID[y]!="":
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "      Probe   : " + fcolor.BBlue  + str(ListInfo_PROBE[y]) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC = InActiveMAC  + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite + str(ListInfo_CLastSeen[y]).ljust(24) + fcolor.SGreen + "Station : " + fcolor.SYellow + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SWhite + str(ListInfo_CBSSID[y]) + fcolor.SWhite + "  [ " + fcolor.SWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SBlack + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            InActiveMAC = InActiveMAC + fcolor.SGreen + "      Probe   : " + fcolor.SBlue + str(ListInfo_PROBE[y]) + "\n"
                y=y+1
            x=x+1
        x=0
        while x < len(__builtin__.MonitoringNameList):
            y=0
            while y < len(ListInfo_BSSID):
                if __builtin__.MonitoringNameList[x].upper()==ListInfo_ESSID[y].upper():
                    if int(__builtin__.ListInfo_SSIDTimeGap[y]) < int(__builtin__.HIDE_AFTER_MIN):
                        FoundCount += 1
                        __builtin__.FoundMonitoringMAC = __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_LastSeen[y]).ljust(24) +   fcolor.SGreen + "BSSID   : " + fcolor.BWhite + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.BYellow + str(ListInfo_ESSID[y]) + "\n"
                        AddMACToList(ListInfo_BSSID[y],List_MonitoringMAC)
                    else:
                        InactiveCount += 1
                        InActiveMAC= InActiveMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite +  str(ListInfo_LastSeen[y]).ljust(24) + fcolor.SGreen + "BSSID   : " + fcolor.SWhite + str(ListInfo_BSSID[y]) + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_BestQuality[y]).ljust(8) + fcolor.SGreen + "ESSID : " + fcolor.SYellow + str(ListInfo_ESSID[y]) + "\n"
                y=y+1
            y=0
            while y < len(ListInfo_STATION):
                if ListInfo_PROBE[y].upper().find(__builtin__.MonitoringNameList[x].upper())!=-1:
                    ProbeName=ListInfo_PROBE[y]
                    if int(__builtin__.ListInfo_CTimeGap[y]) < int(__builtin__.HIDE_AFTER_MIN):
                        FoundCount += 1
                        AddMACToList(ListInfo_STATION[y],List_MonitoringMAC)
                        __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SWhite + "[" + fcolor.BGreen + str(FoundCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.BWhite + str(ListInfo_CLastSeen[y]).ljust(24)  + fcolor.SGreen + "Station : " + fcolor.BWhite + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.BWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BWhite + str(ListInfo_CBSSID[y]) + fcolor.SGreen + "  [ " + fcolor.BWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "BSSID : " + fcolor.BIGray + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            ProbeName=ProbeName.replace(__builtin__.MonitoringNameList[x],fcolor.BYellow + __builtin__.MonitoringNameList[x] + fcolor.BBlue)
                            __builtin__.FoundMonitoringMAC= __builtin__.FoundMonitoringMAC + fcolor.SGreen + "      Probe   : " + fcolor.BBlue  + str(ProbeName) + "\n"
                    else:
                        InactiveCount += 1
                        InActiveMAC = InActiveMAC  + fcolor.SWhite + "[" + fcolor.BGreen + str(InactiveCount) + fcolor.SWhite + "]".ljust(4) + fcolor.SGreen + "L.Seen  : " + fcolor.SWhite + str(ListInfo_CLastSeen[y]).ljust(24) + fcolor.SGreen + "Station : " + fcolor.SWhite + ListInfo_STATION[y] + "\t" + fcolor.SGreen + "Power : " + fcolor.SWhite + str(ListInfo_CBestQuality[y]).ljust(8) + fcolor.SGreen 
                        if ListInfo_CBSSID[y]!="":
                            ESSID=FindESSID(ListInfo_CBSSID[y])
                            if ListInfo_CBSSID[y].find("Not Associated")==-1:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SWhite + str(ListInfo_CBSSID[y]) + fcolor.SWhite + "  [ " + fcolor.SWhite + str(ESSID) + fcolor.SGreen + " ]\n"
                            else:
                                InActiveMAC = InActiveMAC + fcolor.SGreen + "BSSID : " + fcolor.SBlack + "Not Associated\n"
                        if ListInfo_PROBE[y]!="":
                            ProbeName=ProbeName.replace(__builtin__.MonitoringNameList[x],fcolor.SYellow + __builtin__.MonitoringNameList[x] + fcolor.SBlue)
                            InActiveMAC = InActiveMAC + fcolor.SGreen + "      Probe   : " + fcolor.SBlue + str(ProbeName) + "\n"
                y=y+1
            x=x+1
        if __builtin__.FoundMonitoringMAC!="" or InActiveMAC!="":
            CenterText(fcolor.BGIRed + fcolor.BWhite,"=====  MONITORING   PANEL  ===== ")
            print ""
            BeepSound()
            if __builtin__.FoundMonitoringMAC!="":
                print fcolor.BRed + "FOUND " + str(FoundCount) + " LIVE MONITORED ITEMS !!!"
                print __builtin__.FoundMonitoringMAC
                if __builtin__.SAVE_MONPKT=="Yes":
                    SaveFilteredMAC(List_MonitoringMAC,"MON*",mondir)
            if InActiveMAC!="":
                print fcolor.BRed + "FOUND " + str(InactiveCount) + " INACTIVE MONITORED ITEMS !!!"
                print InActiveMAC
            LineBreak()

def SaveConfig(CMD):
    open(ConfigFile,"w").write("WAIDPS Configuration"+ "\n")
    open(ConfigFile,"a+b").write("Unique HWIdentifier="+str(__builtin__.HWID) + "\n")
    open(ConfigFile,"a+b").write("USERNAME="+str(__builtin__.USERNAME) + "\n")
    open(ConfigFile,"a+b").write("USERHASH="+str(__builtin__.USERHASH) + "\n")
    open(ConfigFile,"a+b").write("USERPASS="+str(__builtin__.USERPASS) + "\n")
    open(ConfigFile,"a+b").write("DISABLE_BREAK=" + str(DISABLE_BREAK) + "\n")
    open(ConfigFile,"a+b").write("LOAD_WPS=" + str(LOAD_WPS) + "\n")
    open(ConfigFile,"a+b").write("LOAD_IWLIST=" + str(LOAD_IWLIST) + "\n")
    open(ConfigFile,"a+b").write("LOAD_PKTCAPTURE=" + str(LOAD_PKTCAPTURE) + "\n")
    open(ConfigFile,"a+b").write("SAVE_MONPKT=" + str(SAVE_MONPKT) + "\n")
    open(ConfigFile,"a+b").write("SAVE_ATTACKPKT=" + str(SAVE_ATTACKPKT) + "\n")
    open(ConfigFile,"a+b").write("SHOW_CONNECTION_ALERT=" + str(SHOW_CONNECTION_ALERT) + "\n")
    open(ConfigFile,"a+b").write("SHOW_SUSPICIOUS_LISTING=" + str(SHOW_SUSPICIOUS_LISTING) + "\n")
    open(ConfigFile,"a+b").write("SHOW_IDS=" + str(SHOW_IDS) + "\n")
    open(ConfigFile,"a+b").write("HIDE_INACTIVE_SSID=" + str(HIDE_INACTIVE_SSID) + "\n")
    open(ConfigFile,"a+b").write("HIDE_INACTIVE_STN=" + str(HIDE_INACTIVE_STN) + "\n")
    open(ConfigFile,"a+b").write("HIDE_AFTER_MIN=" + str(HIDE_AFTER_MIN)+ "\n")
    open(ConfigFile,"a+b").write("TOTALLY_REMOVE_MIN=" + str(TOTALLY_REMOVE_MIN)+ "\n")
    open(ConfigFile,"a+b").write("NETWORK_VIEW=" + str(NETWORK_VIEW)+ "\n")
    open(ConfigFile,"a+b").write("ALERTSOUND=" + str(ALERTSOUND)+ "\n")
    open(ConfigFile,"a+b").write("TIMEOUT=" + str(TIMEOUT)+ "\n")
    open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_AP_DB=" + str(TIMES_BEFORE_UPDATE_AP_DB) + "\n")
    open(ConfigFile,"a+b").write("TIMES_BEFORE_UPDATE_STN_DB=" + str(TIMES_BEFORE_UPDATE_STN_DB)+ "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DATA86=" + str(__builtin__.THRESHOLD_DATA86) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DATAARP=" + str(__builtin__.THRESHOLD_DATAARP) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DATA94=" + str(__builtin__.THRESHOLD_DATA94) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DATA98=" + str(__builtin__.THRESHOLD_DATA98) + "\n")
    open(ConfigFile,"a+b").write("HRESHOLD_ASSOC=" + str(__builtin__.THRESHOLD_ASSOC) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DISASSOC=" + str(__builtin__.THRESHOLD_DISASSOC) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_REASSOC=" + str(__builtin__.THRESHOLD_REASSOC) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_AUTH=" + str(__builtin__.THRESHOLD_AUTH) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DEAUTH=" + str(__builtin__.THRESHOLD_DEAUTH) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_DEAUTH_AC=" + str(__builtin__.THRESHOLD_DEAUTH_AC) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_EAPOL_STD=" + str(__builtin__.THRESHOLD_EAPOL_STD) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_EAPOL_START=" + str(__builtin__.THRESHOLD_EAPOL_START) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_WPS=" + str(__builtin__.THRESHOLD_WPS) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD_QOS=" + str(__builtin__.THRESHOLD_QOS) + "\n")
    open(ConfigFile,"a+b").write("THRESHOLD=" + str(__builtin__.THRESHOLD) + "\n")
    open(ConfigFile,"a+b").write("SENSITIVITY_LVL=" + str(__builtin__.SENSITIVITY_LVL) + "\n")
    if CMD!="":
        printc ("i",fcolor.BRed + "Application Setting Saved...","")

def LoadConfig():
    tmpList=[]
    if IsFileDirExist(ConfigFile)=="F":
	with open(ConfigFile,"r") as f:
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split("=")
                if len(tmpList)==2:
                    if tmpList[0]=="Unique HWIdentifier" and tmpList[1]!="":
                        __builtin__.HWID_Saved=tmpList[1]
                    if tmpList[0]=="USERNAME" and tmpList[1]!="":
                        __builtin__.USERNAME=tmpList[1]
                    if tmpList[0]=="USERHASH" and tmpList[1]!="":
                        __builtin__.USERHASH=tmpList[1]
                    if tmpList[0]=="USERPASS" and tmpList[1]!="":
                        __builtin__.USERPASS=tmpList[1]
                    if tmpList[0]=="LOAD_WPS" and tmpList[1]!="":
                        __builtin__.LOAD_WPS=tmpList[1]
                    if tmpList[0]=="LOAD_IWLIST" and tmpList[1]!="":
                        __builtin__.LOAD_IWLIST=tmpList[1]
                    if tmpList[0]=="LOAD_PKTCAPTURE" and tmpList[1]!="":
                        __builtin__.LOAD_PKTCAPTURE=tmpList[1]
                    if tmpList[0]=="SAVE_MONPKT" and tmpList[1]!="":
                        __builtin__.SAVE_MONPKT=tmpList[1]
                    if tmpList[0]=="SAVE_ATTACKPKT" and tmpList[1]!="":
                        __builtin__.SAVE_ATTACKPKT=tmpList[1]
                    if tmpList[0]=="SHOW_CONNECTION_ALERT" and tmpList[1]!="":
                        __builtin__.SHOW_CONNECTION_ALERT=tmpList[1]
                    if tmpList[0]=="SHOW_SUSPICIOUS_LISTING" and tmpList[1]!="":
                        __builtin__.SHOW_SUSPICIOUS_LISTING=tmpList[1]
                    if tmpList[0]=="SHOW_IDS" and tmpList[1]!="":
                        __builtin__.SHOW_IDS=tmpList[1]
                    if tmpList[0]=="DISABLE_BREAK" and tmpList[1]!="":
                        __builtin__.DISABLE_BREAK=tmpList[1]
                    if tmpList[0]=="HIDE_INACTIVE_SSID" and tmpList[1]!="":
                        __builtin__.HIDE_INACTIVE_SSID=tmpList[1]
                    if tmpList[0]=="HIDE_AFTER_MIN" and tmpList[1]!="":
                        __builtin__.HIDE_AFTER_MIN=tmpList[1]
                    if tmpList[0]=="TOTALLY_REMOVE_MIN" and tmpList[1]!="":
                        __builtin__.TOTALLY_REMOVE_MIN=tmpList[1]
                    if tmpList[0]=="NETWORK_VIEW" and tmpList[1]!="":
                        __builtin__.NETWORK_VIEW=tmpList[1]
                    if tmpList[0]=="ALERTSOUND" and tmpList[1]!="":
                        __builtin__.ALERTSOUND=tmpList[1]
                    if tmpList[0]=="TIMEOUT" and tmpList[1]!="":
                        __builtin__.TIMEOUT=tmpList[1]
                    if tmpList[0]=="TIMES_BEFORE_UPDATE_AP_DB" and tmpList[1]!="":
                        __builtin__.TIMES_BEFORE_UPDATE_AP_DB=tmpList[1]
                    if tmpList[0]=="TIMES_BEFORE_UPDATE_STN_DB" and tmpList[1]!="":
                        __builtin__.TIMES_BEFORE_UPDATE_STN_DB=tmpList[1]
                    if tmpList[0]=="HIDE_INACTIVE_STN" and tmpList[1]!="":
                        __builtin__.HIDE_INACTIVE_STN=tmpList[1]
                    if tmpList[0]=="THRESHOLD_DATA86" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DATA86=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DATAARP" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DATAARP=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DATA94" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DATA94=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DATA98" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DATA98=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_ASSOC" and tmpList[1]!="":
                        __builtin__.THRESHOLD_ASSOC=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DISASSOC" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DISASSOC=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_REASSOC" and tmpList[1]!="":
                        __builtin__.THRESHOLD_REASSOC=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_AUTH" and tmpList[1]!="":
                        __builtin__.THRESHOLD_AUTH=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DEAUTH" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DEAUTH=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_DEAUTH_AC" and tmpList[1]!="":
                        __builtin__.THRESHOLD_DEAUTH_AC=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_EAPOL_START" and tmpList[1]!="":
                        __builtin__.THRESHOLD_EAPOL_START=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_EAPOL_STD" and tmpList[1]!="":
                        __builtin__.THRESHOLD_EAPOL_STD=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_WPS" and tmpList[1]!="":
                        __builtin__.THRESHOLD_WPS=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD_QOS" and tmpList[1]!="":
                        __builtin__.THRESHOLD_QOS=int(tmpList[1])
                    if tmpList[0]=="THRESHOLD" and tmpList[1]!="":
                        __builtin__.THRESHOLD=int(tmpList[1])
                    if tmpList[0]=="SENSITIVITY_LVL" and tmpList[1]!="":
                        __builtin__.SENSITIVITY_LVL=tmpList[1]
                    
                    __builtin__.SENSITIVITY_LVL4= [__builtin__.THRESHOLD_DATA86,__builtin__.THRESHOLD_DATAARP,__builtin__.THRESHOLD_DATA94,__builtin__.THRESHOLD_DATA98,__builtin__.THRESHOLD_ASSOC,__builtin__.THRESHOLD_DISASSOC,__builtin__.THRESHOLD_REASSOC,__builtin__.THRESHOLD_AUTH,__builtin__.THRESHOLD_DEAUTH,__builtin__.THRESHOLD_DEAUTH_AC,__builtin__.THRESHOLD_EAPOL_STD, __builtin__.THRESHOLD_EAPOL_START,__builtin__.THRESHOLD_WPS,__builtin__.THRESHOLD_QOS,__builtin__.THRESHOLD ]   # CUSTOM
                    if tmpList[0]=="A" and tmpList[1]!="":
                        A=tmpList[1]
    else:
        SaveConfig("")
    if __builtin__.DISABLE_BREAK=="Yes":
        signal.signal(signal.SIGINT,signal.SIG_IGN)

def SetIDS_Sensitivity(CMD):
    tmpSENSITIVE=[]
    if CMD=="":
        printc ("+", fcolor.BBlue + "Intrusion Detection System - Detection Sensitivity","")
        Option1 = tabspacefull + SelBColor + "0" + StdColor + "/" + SelBColor + "D - " + SelColor + "D" + StdColor + "isplay Current Setting\n"
        Option2 = tabspacefull + SelBColor + "1" + StdColor + "/" + SelBColor + "H - " + SelColor + "H" + StdColor + "ighly Sensitive\n"
        Option3 = tabspacefull + SelBColor + "2" + StdColor + "/" + SelBColor + "M - " + SelColor + "M" + StdColor + "edium Sensitive\n"
        Option4 = tabspacefull + SelBColor + "3" + StdColor + "/" + SelBColor + "L - " + SelColor + "L" + StdColor + "ow Sensitive\n\n"
        Option5 = tabspacefull + SelBColor + "4" + StdColor + "/" + SelBColor + "C - " + SelColor + "C" + StdColor + "ustom Setting (Include Refresh Timeout Rate)\n"
        OptionA=Option1 + Option2 + Option3 + Option4 + Option5
        print OptionA
        print tabspacefull + fcolor.BWhite + "Current Setting : " + fcolor.BRed + str(__builtin__.SENSITIVITY_LVL) + ""
        usr_resp=AskQuestion("Enter your option : ",fcolor.SWhite + "<default = return>","U","RETURN","1")
        if usr_resp=="RETURN":
            return
    else:
        usr_resp=CMD
    ToDisplay=0
    if usr_resp=="1" or usr_resp=="H":
        __builtin__.SENSITIVITY_LVL=1
    if usr_resp=="2" or usr_resp=="M":
        __builtin__.SENSITIVITY_LVL=2
    if usr_resp=="3" or usr_resp=="L":
        __builtin__.SENSITIVITY_LVL=3
    if usr_resp=="4" or usr_resp=="C":
        __builtin__.SENSITIVITY_LVL=4
    if usr_resp=="0" or usr_resp=="D":
        ToDisplay=1
    if str(__builtin__.SENSITIVITY_LVL)=="1":
        tmpSENSITIVE=__builtin__.SENSITIVITY_LVL1
    if str(__builtin__.SENSITIVITY_LVL)=="2":
        tmpSENSITIVE=__builtin__.SENSITIVITY_LVL2
    if str(__builtin__.SENSITIVITY_LVL)=="3":
        tmpSENSITIVE=__builtin__.SENSITIVITY_LVL3
    if str(__builtin__.SENSITIVITY_LVL)=="4":
        tmpSENSITIVE=__builtin__.SENSITIVITY_LVL4
    if ToDisplay==0:
        ToDisplay=1
        if __builtin__.SENSITIVITY_LVL==1 or __builtin__.SENSITIVITY_LVL==2 or __builtin__.SENSITIVITY_LVL==3:
            __builtin__.THRESHOLD_DATA86=int(tmpSENSITIVE[0])
            __builtin__.THRESHOLD_DATAARP=int(tmpSENSITIVE[1])
            __builtin__.THRESHOLD_DATA94=int(tmpSENSITIVE[2])
            __builtin__.THRESHOLD_DATA98=int(tmpSENSITIVE[3])
            __builtin__.THRESHOLD_ASSOC=int(tmpSENSITIVE[4])
            __builtin__.THRESHOLD_DISASSOC=int(tmpSENSITIVE[5])
            __builtin__.THRESHOLD_REASSOC=int(tmpSENSITIVE[6])
            __builtin__.THRESHOLD_AUTH=int(tmpSENSITIVE[7])
            __builtin__.THRESHOLD_DEAUTH=int(tmpSENSITIVE[8])
            __builtin__.THRESHOLD_DEAUTH_AC=int(tmpSENSITIVE[9])
            __builtin__.THRESHOLD_EAPOL_STD=int(tmpSENSITIVE[10])
            __builtin__.THRESHOLD_EAPOL_START=int(tmpSENSITIVE[11])
            __builtin__.THRESHOLD_WPS=int(tmpSENSITIVE[12])
            __builtin__.THRESHOLD_QOS=int(tmpSENSITIVE[13])
            __builtin__.THRESHOLD=int(tmpSENSITIVE[14])
        if __builtin__.SENSITIVITY_LVL==4:
            tmpSENSITIVE[0] =AskQuestion("Threshold for Data86               : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[0])  + " >","N",tmpSENSITIVE[0],"0")
            tmpSENSITIVE[1] =AskQuestion("Threshold for DataARP (ARP)        : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[1])  + " >","N",tmpSENSITIVE[1],"0")
            tmpSENSITIVE[2] =AskQuestion("Threshold for Data94               : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[2])  + " >","N",tmpSENSITIVE[2],"0")
            tmpSENSITIVE[3] =AskQuestion("Threshold for Data98               : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[3])  + " >","N",tmpSENSITIVE[3],"0")
            tmpSENSITIVE[4] =AskQuestion("Threshold for Association          : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[4])  + " >","N",tmpSENSITIVE[4],"0")
            tmpSENSITIVE[5] =AskQuestion("Threshold for Disassociation       : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[5])  + " >","N",tmpSENSITIVE[5],"0")
            tmpSENSITIVE[6] =AskQuestion("Threshold for Reassociation        : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[6])  + " >","N",tmpSENSITIVE[6],"0")
            tmpSENSITIVE[7] =AskQuestion("Threshold for Authentication       : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[7])  + " >","N",tmpSENSITIVE[7],"0")
            tmpSENSITIVE[8] =AskQuestion("Threshold for Deauthentication     : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[8])  + " >","N",tmpSENSITIVE[8],"0")
            tmpSENSITIVE[9] =AskQuestion("Threshold for Deauthentication(AC) : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[9])  + " >","N",tmpSENSITIVE[9],"0")
            tmpSENSITIVE[10]=AskQuestion("Threshold for EAPOL Protocol       : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[10]) + " >","N",tmpSENSITIVE[10],"0")
            tmpSENSITIVE[10]=AskQuestion("Threshold for EAPOL Start          : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[11]) + " >","N",tmpSENSITIVE[11],"0")
            tmpSENSITIVE[11]=AskQuestion("Threshold for EAP Communication    : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[12]) + " >","N",tmpSENSITIVE[12],"0")
            tmpSENSITIVE[12]=AskQuestion("Threshold for Qos Data             : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[13]) + " >","N",tmpSENSITIVE[13],"0")
            tmpSENSITIVE[12]=AskQuestion("Threshold (Only in Analysis)       : ",fcolor.SWhite + "<current =" + str(tmpSENSITIVE[14]) + " >","N",tmpSENSITIVE[14],"0")
            __builtin__.TIMEOUT=AskQuestion("Refresh Timeout Rate               : ",fcolor.SWhite + "<current =" + str(__builtin__.TIMEOUT) + " >","N",__builtin__.TIMEOUT,"0")
            print ""
    if ToDisplay==1:
        printc ("i",fcolor.BBlue + "Detection Sensitivity Setting","")
        printc (" ",StdColor + "Threshold for Data86               : " + SelColor  + str(tmpSENSITIVE[0]) ,"")
        printc (" ",StdColor + "Threshold for DataARP (ARP)        : " + SelColor  + str(tmpSENSITIVE[1]) ,"")
        printc (" ",StdColor + "Threshold for Data94               : " + SelColor + str(tmpSENSITIVE[2]) ,"")
        printc (" ",StdColor + "Threshold for Data98               : " + SelColor  + str(tmpSENSITIVE[3]) ,"")
        printc (" ",StdColor + "Threshold for Association          : " + SelColor  + str(tmpSENSITIVE[4]) ,"")
        printc (" ",StdColor + "Threshold for Disassociation       : " + SelColor  + str(tmpSENSITIVE[5]) ,"")
        printc (" ",StdColor + "Threshold for Reassociation        : " + SelColor  + str(tmpSENSITIVE[6]) ,"")
        printc (" ",StdColor + "Threshold for Authentication       : " + SelColor  + str(tmpSENSITIVE[7]) ,"")
        printc (" ",StdColor + "Threshold for Deauthentication     : " + SelColor  + str(tmpSENSITIVE[8]) ,"")
        printc (" ",StdColor + "Threshold for Deauthentication(AC) : " + SelColor  + str(tmpSENSITIVE[9]) ,"")
        printc (" ",StdColor + "Threshold for EAPOL Protocol       : " + SelColor  + str(tmpSENSITIVE[10]),"")
        printc (" ",StdColor + "Threshold for EAPOL Start          : " + SelColor  + str(tmpSENSITIVE[11]),"")
        printc (" ",StdColor + "Threshold for EAP Communication    : " + SelColor  + str(tmpSENSITIVE[12]),"")
        printc (" ",StdColor + "Threshold for Qos Data             : " + SelColor  + str(tmpSENSITIVE[13]),"")
        printc (" ",StdColor + "Threshold (Only in Analysis)       : " + SelColor  + str(tmpSENSITIVE[14]),"")
        printc (" ",StdColor + "Refresh Timeout Rate               : " + SelColor  + str(__builtin__.TIMEOUT),"")
  
    SaveConfig("")
    LineBreak()
    if CMD=="":
        SetIDS_Sensitivity("")
    return

def LoadPktConfig():
    tmpList=[]
    if IsFileDirExist(PktConfig)=="F":
        __builtin__.ANALYSIS_SEARCH=[]
        __builtin__.ANALYSIS_IGNORE=[]
        __builtin__.ANALYSIS_MAC=[]
	with open(PktConfig,"r") as f:
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split("=")
                if len(tmpList)==2:
                    if tmpList[0]=="ANALYSIS_SEARCH" and tmpList[1]!="":
                        __builtin__.ANALYSIS_SEARCH.append (tmpList[1])
                    if tmpList[0]=="ANALYSIS_IGNORE" and tmpList[1]!="":
                        __builtin__.ANALYSIS_IGNORE.append (tmpList[1])
                    if tmpList[0]=="ANALYSIS_MAC" and tmpList[1]!="":
                        __builtin__.ANALYSIS_MAC.append (tmpList[1])
    else:
        SavePktConfig()

def SavePktConfig():
    open(PktConfig,"w").write("Captured Packet Analysis Configuration"+ "\n")
    x=0
    while x<len(__builtin__.ANALYSIS_SEARCH):
        open(PktConfig,"a+b").write("ANALYSIS_SEARCH=" + str(__builtin__.ANALYSIS_SEARCH[x]) + "\n")
        x += 1
    x=0
    while x<len(__builtin__.ANALYSIS_IGNORE):
        open(PktConfig,"a+b").write("ANALYSIS_IGNORE=" + str(__builtin__.ANALYSIS_IGNORE[x]) + "\n")
        x += 1
    x=0
    while x<len(__builtin__.ANALYSIS_MAC):
        open(PktConfig,"a+b").write("ANALYSIS_MAC=" + str(__builtin__.ANALYSIS_MAC[x]) + "\n")
        x += 1

def InsNum(StrVal):
    Rtn="[" + str(StrVal) + "]"
    Rtn=Rtn.ljust(6)
    Rtn=fcolor.SWhite + str(Rtn).replace(str(StrVal),fcolor.BWhite + str(StrVal) + fcolor.SWhite)
    return Rtn;

def SearchDBFiles(cmdType,SearchVal,SearchLen,SearchType,SearchTypelbl):
    DbMatchBSSIDCt=0
    DbMatchStationCt=0
    __builtin__.DbShowBSSIDList = []
    __builtin__.DbShowStationList = []
    tmpList= []
    print ""
    if cmdType=="MAC":
        SELECTTYPE="MAC"
        printc (".",fcolor.BWhite + "Search MAC Criteria (Database) : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        if IsFileDirExist(DBFile2)=="F":
	    with open(DBFile2,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=18:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[0])[-SearchLen:]==SearchVal:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (BSSID)"
        if IsFileDirExist(DBFile3)=="F":
	    with open(DBFile3,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=7:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[1])==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[1]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[1])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile4)=="F":
	    with open(DBFile4,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=3:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[0])[-SearchLen:]==SearchVal:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile1)=="F":
	    with open(DBFile1,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=6:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[1])==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[1]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[1])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[0])==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[0]).find(SearchVal)!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[0])[:SearchLen]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[1])[-SearchLen:]==SearchVal:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
    if cmdType=="NAME":
        SELECTTYPE="NAME"
        printc (".",fcolor.BWhite + "Search Name Criteria (Database) : " + fcolor.BRed + str(SearchVal) + fcolor.SWhite + " (" + str(__builtin__.SearchTypelbl) + ")" ,"")
        if IsFileDirExist(DBFile2)=="F":
	    with open(DBFile2,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=18:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[18]).upper()==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[18]).upper().find(SearchVal.upper())!=-1:
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[18]).upper()[:SearchLen]==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[18]).upper()[-SearchLen:]==SearchVal.upper():
                            if str(__builtin__.ShowBSSIDList2).find(tmpList[0])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[0])==-1:
                                __builtin__.DbShowBSSIDList.append (tmpList[0])
                                DbMatchBSSIDCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (BSSID)"
        if IsFileDirExist(DBFile3)=="F":
	    with open(DBFile3,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=7:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[6]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[6]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[6]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[6]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[6]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[6]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[6]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[6]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile4)=="F":
	    with open(DBFile4,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=3:
                        ToDisplay = 0
                        if __builtin__.SearchType=="0" and str(tmpList[2]).upper()==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="1" and str(tmpList[2]).upper().find(SearchVal.upper())!=-1:
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="2" and str(tmpList[2]).upper()[:SearchLen]==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if __builtin__.SearchType=="3" and str(tmpList[2]).upper()[-SearchLen:]==SearchVal.upper():
                            if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                __builtin__.DbShowStationList.append (tmpList[0])
                                DbMatchStationCt += 1
                                ToDisplay=1
                        if ToDisplay==1:
                            print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
        if IsFileDirExist(DBFile1)=="F":
	    with open(DBFile1,"r") as f:
                next(f)
    	        for line in f:
                    line=line.replace("\n","")
                    tmpList=str(line).split(";")
                    if len(tmpList)>=6:
                        if len(tmpList[1])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[5]).upper()==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[5]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[5]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[5]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowBSSIDList2).find(tmpList[1])==-1  and str(__builtin__.DbShowBSSIDList).find(tmpList[1])==-1:
                                    __builtin__.DbShowBSSIDList.append (tmpList[1])
                                    DbMatchBSSIDCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[1]) + fcolor.SGreen + " (BSSID)"
                        if len(tmpList[0])==17:
                            ToDisplay = 0
                            if __builtin__.SearchType=="0" and str(tmpList[5]).upper().upper()==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1  and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="1" and str(tmpList[5]).upper().find(SearchVal.upper())!=-1:
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="2" and str(tmpList[5]).upper()[:SearchLen]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if __builtin__.SearchType=="3" and str(tmpList[5]).upper()[-SearchLen:]==SearchVal.upper():
                                if str(__builtin__.ShowStationList2).find(tmpList[0])==-1 and str(__builtin__.DbShowStationList).find(tmpList[0])==-1:
                                    __builtin__.DbShowStationList.append (tmpList[0])
                                    DbMatchStationCt += 1
                                    ToDisplay=1
                            if ToDisplay==1:
                                print tabspacefull + fcolor.SGreen + "Found Match in DB : " + fcolor.SWhite + str(tmpList[0]) + fcolor.SGreen + " (STATION)"
    if DbMatchBSSIDCt>0 or DbMatchStationCt>0:
        printc ("+",fcolor.SWhite + "Duplication from active listing will be ignored.","")
        if DbMatchBSSIDCt>0:
            printc ("i","Total BSSID Matched in Database   : " + fcolor.BRed + str(DbMatchBSSIDCt),"")
        if DbMatchStationCt>0:
            printc ("i","Total Station Matched in Database : " + fcolor.BRed + str(DbMatchStationCt),"")
        print ""
        printc ("x","Press any key to display the listing detail...","")
    else:
        printc ("+",fcolor.SWhite + "Duplication from active listing will be ignored.","")
        if SELECTTYPE=="MAC":
            printc ("!!","The specified MAC address was not found in database files !!!","")
        if SELECTTYPE=="NAME":
            printc ("!!","The specified Name was not found in database files !!!","")
        LineBreak()
        return;
    if DbMatchBSSIDCt>0:
        x=0
        CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED ACCESS POINT LISTING [ " + str(len(__builtin__.DbShowBSSIDList)) + " ] FROM DATABASE")
        while x<len(DbShowBSSIDList):
            CenterText(fcolor.BBlack + fcolor.BGWhite, "ACCESS POINT MAC ADDRESS [ " + str(DbShowBSSIDList[x]) + "] DETAILED INFORMATION FROM DATABASE - RECORD " + str(x + 1) + "/" + str(len(__builtin__.DbShowBSSIDList)))
            print ""
            DisplayMACDetailFromFiles(DbShowBSSIDList[x])
            x += 1
    if DbMatchStationCt>0:
        x=0
        CenterText(fcolor.BWhite + fcolor.BGBlue, "MATCHED STATION LISTING [ " + str(len(__builtin__.DbShowStationList)) + " ] FROM DATABASE")
        while x<len(DbShowStationList):
            CenterText(fcolor.BBlack + fcolor.BGWhite, "STATION MAC ADDRESS [ " + str(DbShowStationList[x]) + "] DETAILED INFORMATION FROM DATABASE - RECORD " + str(x+1) + "/" + str(len(__builtin__.DbShowStationList)))
            print ""
            DisplayMACDetailFromFiles(DbShowStationList[x])
            x += 1

def DisplayMACDetailFromFiles (MACAddr):
    MAC_OUI=Check_OUI(MACAddr,"")
    tmpList=[]
    AsClientText=""
    AsAPText=""
    TimeColor=fcolor.SGreen
    ESSIDColor=fcolor.BPink
    BSSIDColor=fcolor.BRed
    RptColor=fcolor.SCyan
    OthColor=fcolor.BGreen
    LF = "\n"
    if IsFileDirExist(DBFile1)=="F":
        RecCt=0;DisplayText=""
	with open(DBFile1,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=6:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        ESSID=tmpList[5]
                        if ESSID=="":
                            ESSID=fcolor.IGray + "<<NO ESSID>>"
                        DText=InsNum(RecCt) + StdColor + "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + " ] is both a Station & Access Point [ " + ESSIDColor + str(ESSID) + StdColor + " ] on " + TimeColor + str(tmpList[2]) + StdColor + " as Access Point."
                        RecDetail="Recorded " + str(tmpList[4])
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        if len(tmpList[1])==17:
                            DisplayText=DisplayText + tabspacefull + StdColor + "The MAC is also found to be associated to Access Point [ " + BSSIDColor + str(tmpList[1]) + StdColor + " ] as a wireless client on " + TimeColor + str(tmpList[3]) + LF
                        else:
                            DisplayText=DisplayText + tabspacefull + StdColor + "The MAC was not found to be associated with any Access Point as on " + TimeColor + str(tmpList[3]) + LF
        if DisplayText!="":
            DisplayText = fcolor.BBlue + "Access Point & Station (History)\n" + fcolor.CReset + DisplayText
            print DisplayText 
    if IsFileDirExist(DBFile6)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile6,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=5:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[3])
                        DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + " ] ==> Initally associated to MAC [ " + fcolor.BBlue + str(tmpList[1]) + StdColor + " ] ESSID [ " + fcolor.BBlue + str(tmpList[4]) + StdColor +  " ]"
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        DText=StdColor + "\t\t\t\t  ==> Subsequently to MAC        [ " + fcolor.BRed + str(tmpList[2]) + StdColor + " ] ESSID [ " + fcolor.BRed + str(tmpList[5]) + StdColor +  " ]"
                        DisplayText=DisplayText + DText  + LF
        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
    if IsFileDirExist(DBFile2)=="F":
        RecCt=0;DisplayText=""
	with open(DBFile2,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=18:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[17])
                        ENRICHED=str(tmpList[1])
                        if ENRICHED=="Yes":
                            ENRICHED=fcolor.BRed + " *"
                        else:
                            ENRICHED=fcolor.BRed + "  "
                        BSSID=SelColor + str(tmpList[0]) + ENRICHED
                        ESSID=ESSIDColor + str(tmpList[18])
                        MODE=OthColor + str(tmpList[2])
                        FIRSTSEEN=RptColor +str(tmpList[3])
                        LASTSEEN=RptColor +str(tmpList[4])
                        CHANNEL=OthColor +str(tmpList[5])
                        PRIVACY=OthColor + str(tmpList[6]) + " / " + str(tmpList[7]) + " / " + str(tmpList[8])
                        RATES=str(OthColor + "Max : " + OthColor + str(tmpList[9]) + " Mb/s" + StdColor + " [" + fcolor.SGreen + str(tmpList[10]) + StdColor + "]").replace(" | ", StdColor + " | " + fcolor.SGreen)
                        SIGNAL=OthColor + str(tmpList[11])
                        GPS=OthColor + str(tmpList[12]) + StdColor + " / " + OthColor + str(tmpList[13]) + StdColor + " / " + OthColor + str(tmpList[14])
                        WPS=OthColor + str(tmpList[15]) + StdColor + " / " + OthColor + str(tmpList[16]) 
                        DText=InsNum(RecCt) + StdColor +  "BSSID      : " + str(BSSID) + "    " + StdColor +   "ESSID      : " + str(ESSID).ljust(35) + StdColor +    "MODE  : " + str(MODE).ljust(25) + StdColor +  "WPS : " + str(WPS)
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                        DText=tabspacefull + StdColor +   "Channel    : " + str(CHANNEL).ljust(30) + StdColor + "Privacy    : " + str(PRIVACY).ljust(35) + StdColor +  "Power : " + str(SIGNAL) + " dBm" + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "Bit Rates  : " + str(RATES) + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "First Seen : " + str(FIRSTSEEN).ljust(75) + StdColor + "Last Seen : " + str(LASTSEEN) + LF
                        DisplayText=DisplayText + DText 
                        DText=tabspacefull + StdColor +   "Lon/Lat/Alt: " + str(GPS) + LF
                        DisplayText=DisplayText + DText + LF
        if DisplayText!="":
            AsAPText = AsAPText + DisplayText 
#	with open(DBFile5,"r") as f:
#	    for line in f:
#
    if IsFileDirExist(DBFile3)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile3,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=7:
                    Signal=StdColor + " - Signal : " + OthColor + str(tmpList[4]) + " dBm"
                    ESSID=tmpList[6]
                    if ESSID=="":
                        ESSID=fcolor.IGray + "<<NO ESSID>>"
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        if tmpList[1]=="Not Associated":
                            DText=InsNum(RecCt) + StdColor + "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor +  " ] was not associated to any Access Point." + str(Signal) 
                            RecDetail="Recorded " + str(tmpList[5])
                            RC=int(RightEnd(DText))
                            DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                            DisplayText=DisplayText
                        else:
                            DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor +  " ] has associated to Access Point [ " + BSSIDColor + tmpList[1] + StdColor + " ] ESSID [ " + ESSIDColor + str(ESSID) + StdColor + " ]" + str(Signal) + StdColor + " before."
                            RecDetail="Recorded " + str(tmpList[5])
                            RC=int(RightEnd(DText))
                            DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
                    if tmpList[1]==MACAddr:
                        RecCt2 += 1
                        DText=InsNum(RecCt2) + StdColor + "Client MAC [ " + BSSIDColor + tmpList[0] + StdColor + " ] was connected to MAC [ " + SelColor + str(tmpList[1]) + StdColor + " ] ESSID [ " + ESSIDColor + str(ESSID) + StdColor + " ]" + str(Signal) 
                        RecDetail="Recorded " + str(tmpList[5])
                        RC=int(RightEnd(DText))
                        DisplayText2=DisplayText2 + DText + RptColor +  str(RecDetail).rjust(RC) + LF
        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
        if DisplayText2!="":
            AsAPText = AsAPText + DisplayText2 + LF
    if IsFileDirExist(DBFile4)=="F":
        RecCt=0;RecCt2=0;DisplayText="";DisplayText2=""
	with open(DBFile4,"r") as f:
            next(f)
	    for line in f:
                line=line.replace("\n","")
                tmpList=str(line).split(";")
                if len(tmpList)>=3:
                    if tmpList[0]==MACAddr:
                        RecCt += 1
                        RecDetail="Recorded " + str(tmpList[1])
                        DText=InsNum(RecCt) + StdColor +   "MAC ID [ " + SelColor + str(tmpList[0]) + StdColor + "] ==> " + fcolor.BBlue + "Probe " + StdColor + "[ " + fcolor.BPink + str(tmpList[2]) + StdColor +  " ]" 
                        RC=int(RightEnd(DText))
                        DisplayText=DisplayText + DText + RptColor +  str(RecDetail).rjust(RC) + LF
        if DisplayText!="":
            AsClientText = AsClientText + DisplayText + LF
    if AsAPText!="":
        CenterText(fcolor.BIGray, "As Access Point (History Logs)     ")
        DrawLine("v",fcolor.CReset + fcolor.Black,"",""); print ""
        AsAPText=AsAPText[:-2]
        print AsAPText
        LineBreak()
    if AsClientText!="":
        CenterText(fcolor.BIGray, "As Wireless Station (History Logs)     ")
        DrawLine("v",fcolor.CReset + fcolor.Black,"",""); print ""
        AsClientText=AsClientText[:-2]
        print AsClientText
        LineBreak()

def RightEnd(StrVal):
    curses.setupterm()
    TWidth=curses.tigetnum('cols')
    TWidth=TWidth-1
    SL = len(RemoveColor(StrVal))
    RL = int(TWidth) - SL 
    return int(RL)

def sha256(sVal,cmd):
    hash=hashlib.sha512()
    hash.update(sVal)
    result=hash.digest()
    if cmd=="h":
        result=''.join(x.encode('hex') for x in result)
        result=str(result).upper()
    return result

def sha512(sVal,cmd):
    hash=hashlib.sha512()
    hash.update(sVal)
    result=hash.digest()
    if cmd=="h":
        result=''.join(x.encode('hex') for x in result)
        result=str(result).upper()
    return result

def MD5(sVal,cmd):
    hash=hashlib.md5()
    hash.update(sVal)
    result=hash.digest()
    if cmd=="h":
        result=''.join(x.encode('hex') for x in result)
        result=str(result).upper()
    return result

def Hashing(sText):
    HashText=sText
    x=0
    while x<30:
        HashText=sha512(HashText,"");HashText2=sha256(HashText,"");H1=HashText[:32];H2=HashText[32:-64];H3=HashText[64:-32];H4=HashText[-32:];H5=HashText2[:32];H6=HashText2[-32:]
        HashText=H2 + H6 + H3 + __builtin__.HWID_ENC + __builtin__.USERHASH + H5 + H1 + H4;HashText=sha512(HashText,"");H1=HashText[:64];H2=HashText[-64:];HashText=sha256(H2 + H1,"")
        H1=HashText[:32];H2=HashText[-32:];HashText=sha512(H2 + H1,"")
        x=x+1
    HashText=MD5(HashText,"h")
    return HashText

def GetHardwareID():
    ps=subprocess.Popen("dmidecode | sed -n '/Handle 0x0000/,/Handle 0x0004/p'" , shell=True, stdout=subprocess.PIPE, stderr=open(os.devnull, 'w'))	
    hid=sha512(str(ps.stdout.read()),"")
    ps.wait();ps.stdout.close()
    __builtin__.HWID_ENC=str(hid)
    hid=MD5(hid,"h")
    __builtin__.HWID=(hid)
    return hid
################################
################################
__builtin__.STxt=fcolor.BRed
__builtin__.NTxt=fcolor.BYellow
__builtin__.col=";"
ColorStd=fcolor.SGreen
ColorStd2=fcolor.SWhite
ColorDev=fcolor.BBlue
Color1st=fcolor.BCyan
Color2nd=fcolor.BRed
SelColor=fcolor.BYellow
SelBColor=fcolor.BRed
StdColor=fcolor.SWhite
InfoColor=fcolor.SWhite
lblColor=fcolor.BGreen
txtColor=fcolor.SGreen
VendorColor=fcolor.Cyan
__builtin__.SHOW_CONNECTION_ALERT="Yes"
__builtin__.SHOW_SUSPICIOUS_LISTING="Yes"
__builtin__.SHOW_IDS="Yes"
__builtin__.DISABLE_BREAK="No"
__builtin__.HIDE_AFTER_MIN = 3
__builtin__.TOTALLY_REMOVE_MIN=10
__builtin__.HIDE_INACTIVE_SSID="Yes"
__builtin__.HIDE_INACTIVE_STN="Yes"
__builtin__.NETWORK_VIEW="4"   
__builtin__.ALERTSOUND="No"
__builtin__.TIMEOUT=30
__builtin__.TIMES_BEFORE_UPDATE_AP_DB=10
__builtin__.TIMES_BEFORE_UPDATE_STN_DB=5
__builtin__.UPDATE_STN_COUNT=0
__builtin__.TimeStart=""
__builtin__.TimeEnd=""
appdir="/SYWorks/WAIDPS/"
dbdir="/SYWorks/Database/"
savedir="/SYWorks/Saved/"
attackdir="/SYWorks/Captured/Attack/"
mondir="/SYWorks/Captured/Monitoring/"
tmpdir=appdir + "tmp/"
PathList = ['tmp/']
__builtin__.lookupdir=savedir
__builtin__.searchdir=[lookupdir,savedir,dbdir,attackdir,mondir,appdir]
__builtin__.FilenameHeader="WAIDPS-"
__builtin__.ConfigFile=appdir + "config.ini"
__builtin__.PktConfig=appdir + "pktconfig.ini"
__builtin__.MonitorMACfile=dbdir + "MonitorMAC.ini"
__builtin__.WhitelistFile=dbdir + "Whitelist.ini"
__builtin__.CommandHistory=tmpdir+"History"
__builtin__.HWID_ENC=""
__builtin__.HWID=""
__builtin__.HWID_Saved=""
__builtin__.USERNAME=""
__builtin__.USERHASH=""
__builtin__.USERPASS=""
__builtin__.ENCRYPTED_PASS=""
BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
__builtin__.MACOUI=dbdir + "mac-oui.db"
CautiousLog=dbdir + FilenameHeader + "Cautious.log"
AttackLog=dbdir + FilenameHeader + "Attacks.log"
SuspiciousLog=dbdir + FilenameHeader + "Suspicious.log"
DBFile1=dbdir + FilenameHeader + "APnStation.db"
DBFile2=dbdir + FilenameHeader + "AccessPoint.db"
DBFile3=dbdir + FilenameHeader + "Station.db"
DBFile4=dbdir + FilenameHeader + "Probes.db"
DBFile5=dbdir + FilenameHeader + "ConnectHistory.db"
DBFile6=dbdir + FilenameHeader + "SwitchedAP.db"
EncDBFile=dbdir + FilenameHeader + "Encrypted.enc"
__builtin__.SELECTED_MANIFACE_MAC=[]
__builtin__.SELECTED_IFACE_MAC=[]
__builtin__.SELECTED_MON_MAC=[]
__builtin__.MonitoringMACList=[]
__builtin__.WhiteMACList=[]
__builtin__.WhiteNameList=[]
__builtin__.ScriptName=os.path.basename(__file__)
__builtin__.ScriptFullPath=str(os.path.realpath(os.path.dirname(sys.argv[0]))) + "/" + str(os.path.basename(__file__))
__builtin__.IPSScript=appdir + "Stn.DeAuth.py"
__builtin__.RequiredFiles=['tshark', 'airodump-ng', 'aireplay-ng','aircrack-ng','iwconfig', 'ifconfig', 'xterm', 'wireshark','tcpdump']
__builtin__.Captured_CSV=tmpdir + "Collect-Dump-01.csv"
__builtin__.NewCaptured_CSV=tmpdir + "Dumps.csv"
__builtin__.NewCaptured_CSVFront=tmpdir + "Dumps-Front.csv"
__builtin__.SSID_CSV=tmpdir + "Dumps-SSID.csv"
__builtin__.Client_CSV=tmpdir + "Dumps-Client.csv"
__builtin__.Captured_Kismet=tmpdir + "Collect-Dump-01.kismet.csv"
__builtin__.NewCaptured_Kismet=tmpdir + "Dumps-kismet.csv"
__builtin__.WPS_DUMP=tmpdir + "WPS-Dump"
__builtin__.TMP_IWList_DUMP=tmpdir + "SSID.tmp"
__builtin__.IWList_DUMP=tmpdir + "SSID"
__builtin__.TCPDumpFile=tmpdir + "MON_TCPDump"
__builtin__.TSharkFile=tmpdir + "MON_TShark"
__builtin__.PacketDumpFile=tmpdir + "MON_PacketDump.cap"
__builtin__.PacketDumpFileBak=tmpdir + "BAK_PacketDump.cap"
__builtin__.PacketDumpFileBak2=tmpdir + "BAK_PacketDump.cap"
__builtin__.CurrentPacket=__builtin__.PacketDumpFileBak
__builtin__.TCPDumpFileBak=tmpdir + "BAK_TCPDump"
__builtin__.TSharkFileBak=tmpdir + "BAK_TSharkNew"
__builtin__.TSharkFileBak2=tmpdir + "BAK_TSharkNew2"
__builtin__.TSharkFileBak_Std=tmpdir + "BAK_TSharkStd"
__builtin__.WiresharkCap=tmpdir + "LiveCaptured.cap"
__builtin__.SavedTSharkFile=savedir + "_TShark_Analysed"
__builtin__.SavedTCPDumpFile=savedir + "_TCPDump_Analysed"
ToDisplay=""
__builtin__.ERRORFOUND=0
__builtin__.Infrastructure_DumpList = []
__builtin__.Client_DumpList = []
__builtin__.ListInfo_BSSIDTimes = []
__builtin__.ListInfo_ESSID = []
__builtin__.ListInfo_BSSID = []
__builtin__.ListInfo_ESS = []
__builtin__.ListInfo_Channel = []
__builtin__.ListInfo_APStandard = []
__builtin__.ListInfo_Cloaked = []
__builtin__.ListInfo_Privacy = []
__builtin__.ListInfo_Cipher = []
__builtin__.ListInfo_Auth = []
__builtin__.ListInfo_MaxRate = []
__builtin__.ListInfo_Beacon = []
__builtin__.ListInfo_Data = []
__builtin__.ListInfo_Total = []
__builtin__.ListInfo_FirstSeen = []
__builtin__.ListInfo_LastSeen = []
__builtin__.ListInfo_BestQuality = []
__builtin__.ListInfo_QualityRange = []
__builtin__.ListInfo_QualityPercent = []
__builtin__.ListInfo_BestSignal = []
__builtin__.ListInfo_BestNoise = []
__builtin__.ListInfo_GPSBestLat = []
__builtin__.ListInfo_GPSBestLon = []
__builtin__.ListInfo_GPSBestAlt = []
__builtin__.ListInfo_HiddenSSID = []
__builtin__.ListInfo_BSSID_OUI = []
__builtin__.ListInfo_ConnectedClient = []
__builtin__.ListInfo_Enriched = []
__builtin__.ListInfo_Freq = []
__builtin__.ListInfo_Quality = []
__builtin__.ListInfo_Signal = []
__builtin__.ListInfo_BitRate = []
__builtin__.ListInfo_WPAVer = []
__builtin__.ListInfo_PairwiseCipher = []
__builtin__.ListInfo_GroupCipher = []
__builtin__.ListInfo_AuthSuite = []
__builtin__.ListInfo_LastBeacon = []
__builtin__.ListInfo_Mode = []
__builtin__.ListInfo_EncKey = []
__builtin__.ListInfo_CESSID = []
__builtin__.ListInfo_COUI = []
__builtin__.ListInfo_CElapse = []
__builtin__.ListInfo_SSIDElapse = []
__builtin__.ListInfo_SSIDTimeGap = []
__builtin__.ListInfo_SSIDTimeGapFull = []
__builtin__.ListInfo_CFirstSeen = []
__builtin__.ListInfo_CLastSeen = []
__builtin__.ListInfo_STATION = []
__builtin__.ListInfo_CBSSID = []
__builtin__.ListInfo_STNStandard = []
__builtin__.ListInfo_CBSSIDPrev = []
__builtin__.ListInfo_CBSSIDPrevList = []
__builtin__.ListInfo_CBestQuality = []
__builtin__.ListInfo_CQualityRange = []
__builtin__.ListInfo_CQualityPercent = []
__builtin__.ListInfo_CPackets = []
__builtin__.ListInfo_PROBE = []
__builtin__.ListInfo_CTimeGap = []
__builtin__.ListInfo_CTimeGapFull = []
__builtin__.ListInfo_WPS = []
__builtin__.ListInfo_WPSVer = []
__builtin__.ListInfo_WPSLock = []
__builtin__.ListInfo_Exist = 0
__builtin__.ListInfo_Add = 0
__builtin__.ListInfo_CExist = 0
__builtin__.ListInfo_CAdd = 0
__builtin__.ListInfo_UnassociatedCount = 0
__builtin__.ListInfo_AssociatedCount = 0
__builtin__.ListInfo_ProbeCount = 0
__builtin__.ListInfo_WPSExist = 0
__builtin__.ListInfo_WPSAdd = 0
__builtin__.ListInfo_WPSCount = 0
__builtin__.ListInfo_AllMAC=[]
__builtin__.ListInfo_AllMAC_Dup=[]
__builtin__.MONList = []
__builtin__.MONListC = []
__builtin__.DumpProc=""
__builtin__.DumpProcPID=""
__builtin__.WashProc=""
__builtin__.IWListProc=""
__builtin__.WashProcPID=""
__builtin__.NETWORK_FILTER="ALL"
__builtin__.NETWORK_SIGNAL_FILTER="ALL"
__builtin__.NETWORK_CHANNEL_FILTER="ALL"
__builtin__.NETWORK_WPS_FILTER="ALL"
__builtin__.NETWORK_CLIENT_FILTER="ALL"
__builtin__.NETWORK_PROBE_FILTER="ALL"
__builtin__.NETWORK_UPROBE_FILTER="ALL"
__builtin__.NETWORK_ASSOCIATED_FILTER="ALL"
__builtin__.NETWORK_UNASSOCIATED_FILTER="ALL"
__builtin__.NETWORK_CSIGNAL_FILTER="ALL"
__builtin__.NETWORK_UCSIGNAL_FILTER="ALL"
__builtin__.MSG_HistoryConnection=""
__builtin__.MSG_AttacksLogging=""
__builtin__.MSG_SuspiciousListing=""
__builtin__.MSG_CombinationLogs=""
__builtin__.ShowBSSIDList = []
__builtin__.ShowStationList = []
__builtin__.SearchLen=""
__builtin__.DisplayNetworkFilter=""
__builtin__.DisplayClientFilter=""
__builtin__.DisplayUnassocFilter=""
__builtin__.DisplayAllFilter=""
__builtin__.AP_BSSIDList=[]
__builtin__.AP_FREQList=[]
__builtin__.AP_QUALITYList=[]
__builtin__.AP_SIGNALList=[]
__builtin__.AP_ENCKEYList=[]
__builtin__.AP_ESSIDList=[]
__builtin__.AP_MODEList=[]
__builtin__.AP_CHANNELList=[]
__builtin__.AP_ENCTYPEList=[]
__builtin__.ListInfo_CExist = 0
__builtin__.ListInfo_CAdd = 0
__builtin__.ListInfo_CRemoved = 0
__builtin__.ListInfo_BRemoved = 0
__builtin__.SHOWRESULT=0
__builtin__.ANALYSIS_PROBE=1
__builtin__.ANALYSIS_BEACON=1
__builtin__.ANALYSIS_ACK=1
__builtin__.ANALYSIS_SEARCH=[]
__builtin__.ANALYSIS_MAC=[]
__builtin__.ANALYSIS_IGNORE=[]
__builtin__.ANALYSIS_TYPE=['PROBE_REQUEST', 'PROBE_RESPONSE', 'BEACON','ACKNOWLEDGEMENT']
__builtin__.LASTCMD=""
__builtin__.LASTCMDLOG=""
__builtin__.TotalLine=0
__builtin__.UsableLine=0
__builtin__.LOAD_WPS="Yes"
__builtin__.LOAD_IWLIST="Yes"
__builtin__.LOAD_PKTCAPTURE="Yes"
__builtin__.SAVE_MONPKT="No"
__builtin__.SAVE_ATTACKPKT="Yes"
__builtin__.PCapProc=""
__builtin__.SearchType=""
__builtin__.SearchTypelbl=""
__builtin__.SearchLen==""
__builtin__.MatchBSSIDCt=0
__builtin__.MatchStationCt=0
__builtin__.ShowBSSIDList = []
__builtin__.ShowStationList = []
__builtin__.ShowBSSIDList2 = []
__builtin__.ShowStationList2 = []
__builtin__.SELECTTYPE=""
__builtin__.SearchVal=""
__builtin__.USearchVal=""
__builtin__.FilePath=""
__builtin__.FileName=""
__builtin__.FileNameOnly=""
__builtin__.FileExt=""
__builtin__.FileSize=""
__builtin__.List_ANALYZER=[]
__builtin__.List_FrMAC=[]
__builtin__.List_ToMAC=[]
__builtin__.List_BSSID=[]
__builtin__.List_DataARP=[]
__builtin__.List_Auth=[]
__builtin__.List_Deauth=[]
__builtin__.List_Deauth_AC=[]
__builtin__.List_Assoc=[]
__builtin__.List_Reassoc=[]
__builtin__.List_Disassoc=[]
__builtin__.List_RTS=[]
__builtin__.List_CTS=[]
__builtin__.List_ACK=[]
__builtin__.List_EAPOL_STD=[]
__builtin__.List_EAPOL_START=[]
__builtin__.List_WPS=[]
__builtin__.List_Beacon=[]
__builtin__.List_SSID=[]
__builtin__.List_SSIDCT=[]
__builtin__.List_IsAP=[]
__builtin__.List_PResp=[]
__builtin__.List_PReq=[]
__builtin__.List_ProbeName=[]
__builtin__.List_NULL=[]
__builtin__.List_QOS=[]
__builtin__.List_Data86=[]
__builtin__.List_Data98=[]
__builtin__.List_Data94=[]
__builtin__.OfInterest_List=[]
__builtin__.List_AttackingMAC=[]
__builtin__.List_MonitoringMAC=[]
__builtin__.List_AllMAC=[]
__builtin__.FoundFiles=[]
__builtin__.FoundFiles_Filtered=[]
__builtin__.ExtList= ['pcap','cap']
__builtin__.SENSITIVITY_LVL=2
__builtin__.THRESHOLD_DATA86=100
__builtin__.THRESHOLD_DATAARP=100
__builtin__.THRESHOLD_DATA94=100
__builtin__.THRESHOLD_DATA98=100
__builtin__.THRESHOLD_ASSOC=10
__builtin__.THRESHOLD_DISASSOC=10
__builtin__.THRESHOLD_REASSOC=10
__builtin__.THRESHOLD_AUTH=10
__builtin__.THRESHOLD_DEAUTH=10
__builtin__.THRESHOLD_DEAUTH_AC=10
__builtin__.THRESHOLD_EAPOL_STD=10
__builtin__.THRESHOLD_EAPOL_START=10
__builtin__.THRESHOLD_WPS=10
__builtin__.THRESHOLD_QOS=10
__builtin__.THRESHOLD=10
__builtin__.FIXCHANNEL=0
__builtin__.AutoComplete=[]
__builtin__.ExtReadOut=""
__builtin__.SENSITIVITY_LVL1= ['50' ,'50' ,'50' ,'50' ,'5' ,'5' ,'5' ,'5' ,'10','5' ,'5' ,'5' ,'5' ,'10',10]   # HIGH
__builtin__.SENSITIVITY_LVL2= ['100','100','100','100','10','10','10','10','20','10','10','10','10','20',10]   # MEDIUM
__builtin__.SENSITIVITY_LVL3= ['200','200','200','200','20','20','20','20','30','20','20','20','20','40',10]   # LOW
__builtin__.SENSITIVITY_LVL4= [__builtin__.THRESHOLD_DATA86,__builtin__.THRESHOLD_DATAARP,__builtin__.THRESHOLD_DATA94,__builtin__.THRESHOLD_DATA98,__builtin__.THRESHOLD_ASSOC,__builtin__.THRESHOLD_DISASSOC,__builtin__.THRESHOLD_REASSOC,__builtin__.THRESHOLD_AUTH,__builtin__.THRESHOLD_DEAUTH,__builtin__.THRESHOLD_DEAUTH_AC,__builtin__.THRESHOLD_EAPOL_STD,__builtin__.THRESHOLD_EAPOL_START,__builtin__.THRESHOLD_WPS,__builtin__.THRESHOLD_QOS,__builtin__.THRESHOLD]   # CUSTOM
__builtin__.MSG_IDSDetection=""
__builtin__.CURRENT_LOC=""
__builtin__.tabspace="   "
__builtin__.tabspacefull="      "
__builtin__.PrintToFile=""
__builtin__.tabspace="   "
__builtin__.tabspacefull="      "
__builtin__.spacing=""
__builtin__.DEBUG=0
original_sigint=""
if __name__ == '__main__':
    try:
        Main()
    except KeyboardInterrupt: print '\n (^C) interrupted\n'
    except EOFError:          print '\n (^D) interrupted\n'
    exit_gracefully(0)
