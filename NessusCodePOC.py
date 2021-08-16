#!/usr/bin/python3
# -*- coding: utf-8 -*-
import ipaddress
from os import remove, write
from typing import OrderedDict
from lxml import etree
from socket import inet_aton
import struct
import ipaddress
import nmap


if __name__ == '__main__':
    hacker = '''
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX                                                                          XX
XX   MMMMMMMMMMMMMMMMMMMMMssssssssssssssssssssssssssMMMMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMss                                ssMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMyy''                                    ''yyMMMMMMMMMMMM   XX
XX   MMMMMMMMyy''                                            ''yyMMMMMMMM   XX
XX   MMMMMy''                                                    ''yMMMMM   XX
XX   MMMy'                                                          'yMMM   XX
XX   Mh'                                                              'hM   XX
XX   -                                                                  -   XX
XX                                                                          XX
XX   ::                                                                ::   XX
XX   MMhh.        ..hhhhhh..                      ..hhhhhh..        .hhMM   XX
XX   MMMMMh   ..hhMMMMMMMMMMhh.                .hhMMMMMMMMMMhh..   hMMMMM   XX
XX   ---MMM .hMMMMdd:::dMMMMMMMhh..        ..hhMMMMMMMd:::ddMMMMh. MMM---   XX
XX   MMMMMM MMmm''      'mmMMMMMMMMyy.  .yyMMMMMMMMmm'      ''mmMM MMMMMM   XX
XX   ---mMM ''             'mmMMMMMMMM  MMMMMMMMmm'             '' MMm---   XX
XX   yyyym'    .              'mMMMMm'  'mMMMMm'              .    'myyyy   XX
XX   mm''    .y'     ..yyyyy..                  ..yyyyy..     'y.    ''mm   XX
XX           MN    .sMMMMMMMMMss.   .    .   .ssMMMMMMMMMs.    NM           XX
XX           N`    MMMMMMMMMMMMMN   M    M   NMMMMMMMMMMMMM    `N           XX
XX            +  .sMNNNNNMMMMMN+   `N    N`   +NMMMMMNNNNNMs.  +            XX
XX              o+++     ++++Mo    M      M    oM++++     +++o              XX
XX                                oo      oo                                XX
XX           oM                 oo          oo                 Mo           XX
XX         oMMo                M              M                oMMo         XX
XX       +MMMM                 s              s                 MMMM+       XX
XX      +MMMMM+            +++NNNN+        +NNNN+++            +MMMMM+      XX
XX     +MMMMMMM+       ++NNMMMMMMMMN+    +NMMMMMMMMNN++       +MMMMMMM+     XX
XX     MMMMMMMMMNN+++NNMMMMMMMMMMMMMMNNNNMMMMMMMMMMMMMMNN+++NNMMMMMMMMM     XX
XX     yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy     XX
XX   m  yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy  m   XX
XX   MMm yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy mMM   XX
XX   MMMm .yyMMMMMMMMMMMMMMMM     MMMMMMMMMM     MMMMMMMMMMMMMMMMyy. mMMM   XX
XX   MMMMd      hhhhh       odddo          obbbo        hhhh        dMMMM   XX
XX   MMMMMd             'hMMMMMMMMMMddddddMMMMMMMMMMh'             dMMMMM   XX
XX   MMMMMMd              'hMMMMMMMMMMMMMMMMMMMMMMh'              dMMMMMM   XX
XX   MMMMMMM-               ''ddMMMMMMMMMMMMMMdd''               -MMMMMMM   XX
XX   MMMMMMMM                   '::dddddddd::'                   MMMMMMMM   XX
XX   MMMMMMMM-                                                  -MMMMMMMM   XX
XX   MMMMMMMMM                                                  MMMMMMMMM   XX
XX   MMMMMMMMMy                                                yMMMMMMMMM   XX
XX   MMMMMMMMMMy.                                            .yMMMMMMMMMM   XX
XX   MMMMMMMMMMMMy.                                        .yMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMy.                                    .yMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMs.                                .sMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMss.           ....           .ssMMMMMMMMMMMMMMMMMM   XX
XX   MMMMMMMMMMMMMMMMMMMMNo         oNNNNo         oNMMMMMMMMMMMMMMMMMMMM   XX
XX                                                                          XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
'''
print(hacker)
options = {}
options['Upload File Path'] = 'Upload File Path'
options['Nessus Target Ripper'] = 'Nessus Target Ripper'
options['Nessus Target Hostname'] = 'Nessus Target Hostname'
options['Nessus Target Port'] = 'Nessus Target Port'
options['Nessus Remove from Export'] = 'Nessus Remove from Export'
options['Strip Services'] = 'Strip Services'
options['Exit'] = 'Exit'


def fileSelect():
    global file
    file = ''
    if file == '':
        inputValid2 = False
        while not inputValid2:
            inputRaw2 = input('File:')
            inputRaw2 = inputRaw2.strip()
            file = inputRaw2
            if file.endswith('.nessus'):
                print(file)
                inputValid2 = True
                askuser(options)
            else:
                print('Not a nessus file make sure the file extension is \'.nessus\'')
    else:
        print('Please add a file')




def hostname():
    hostnames = []
    sorted_ips = []
    fileopen = open(file, 'r')
    doc = etree.parse(file)
    lst = doc.xpath('//ReportHost')
    for i in lst:
        sorted_ips.append(i.xpath('@name')[0])
    fileopen.close
    sorted_ips.sort(reverse=True)
    for sort in sorted_ips:

        try:
            if ipaddress.ip_address(sort).version:
                value = '0'
                while value in sorted_ips:
                    sorted_ips.remove(value)
            sorted_ips = sorted(sorted_ips, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        except ValueError:
            
            index = sorted_ips.index(sort)
            sorted_ips.remove(sort)
            sorted_ips.insert(index, '0')
            hostnames.append(sort)
    
    hostnames.sort()

    for host in hostnames:
        sorted_ips.append(host)

    for ip in sorted_ips:
            path_ = '//ReportHost[@name="'+ip+'"]'
            path2 = './/tag[@name="host-rdns"]'
            
            host = doc.xpath(path_)[0]
            hostpath = host.xpath(path2)

            for it in hostpath:
                hostname = (it.xpath('text()')[0])
                if hostname != ip:
                    print('The hostname for host \t' + ip + ' is ' + hostname)
    option = askuser(options)





def targetripper():
    sorted2 = []
    hostnames = []
    fileopen = open(file, 'r')
    doc = etree.parse(file)
    lst = doc.xpath('//ReportHost')
    
    for i in lst:
        sorted2.append(i.xpath('@name')[0])
        sorted2.sort(reverse=True)
    fileopen.close

    for sort in sorted2:

        try:
            if ipaddress.ip_address(sort).version:
                value = '0'
                while value in sorted2:
                    sorted2.remove(value)
            sorted2 = sorted(sorted2, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        except ValueError:
            
            index = sorted2.index(sort)
            sorted2.remove(sort)
            sorted2.insert(index, '0')
            hostnames.append(sort)
    
    hostnames.sort()


    for i in sorted2:
        print(i)
    option = askuser(options)





def target_port():
    
    sorted_ips = []
    hostnames = []
    fileopen = open(file, 'r')
    doc = etree.parse(file)
    lst = doc.xpath('//ReportHost')

    for i in lst:
        sorted_ips.append(i.xpath('@name')[0])
        sorted_ips.sort(reverse=True)
    fileopen.close


    for sort in sorted_ips:

        try:
            if ipaddress.ip_address(sort).version:
                value = '0'
                while value in sorted_ips:
                    sorted_ips.remove(value)
            sorted_ips = sorted(sorted_ips, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        except ValueError:
            
            index = sorted_ips.index(sort)
            sorted_ips.remove(sort)
            sorted_ips.insert(index, '0')
            hostnames.append(sort)
    
    hostnames.sort()

    for host in hostnames:
        sorted_ips.append(host)

    for ip in sorted_ips:
        ports = []
        
        path_ = '//ReportHost[@name="'+ip+'"]'
        path2 = './/ReportItem'

        host = doc.xpath(path_)[0]
        hostpath = host.xpath(path2)
        
        for it in hostpath:
            port = (it.xpath('@port')[0])
    
            if port not in ports or port == 0:
                if port != '0':
                    ports.append(port)

        ports_int = list(map(int, ports))
        
        ports_sorted = sorted(ports_int)

        if len(ports_sorted) != 0:
                print('For host ' + ip + ' the following ports were discovered:')
                for port in ports_sorted:
                    print ("  " + str(port))

    option = askuser(options)


def removeExcess():
    fileopen = open(file, 'r+')
    doc = etree.parse(file)
    write = open('testwrite.nessus', 'a')
    

    for severity in (doc.xpath('//ReportItem')):
        severity2 = (severity.xpath('.//@severity'))
        if severity2[0] == '0':
            severity.getparent().remove(severity)

    fileopen.seek(0)
    fileopen.write(etree.tostring(doc, pretty_print=True).decode())
    fileopen.truncate()
    
    print("File Saved to "  + file)
    fileopen.close

    option = askuser(options)


def stripservices():
    sorted_ips = []
    hostnames = []
    fileopen = open(file, 'r')
    doc = etree.parse(file)
    lst = doc.xpath('//ReportHost')

    #Gets IP addresses from each Item and appends to sortedIP. Sorts IP addresses.
    for i in lst:
        sorted_ips.append(i.xpath('@name')[0])
        sorted_ips.sort(reverse=True)
    fileopen.close

    #Sorts IP addresses 
    for sort in sorted_ips:

        try:
            #Gets IP address version
            if ipaddress.ip_address(sort).version:
                value = '0'
                #Removes IP addresses without a value
                while value in sorted_ips:
                    sorted_ips.remove(value)
            #Sorts IP address
            sorted_ips = sorted(sorted_ips, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        except ValueError:
            #If IP address cannot be sorted (i.e not IPV4/6) removes item, adds to new list and sorts the hostnames into order.clet
            index = sorted_ips.index(sort)
            sorted_ips.remove(sort)
            sorted_ips.insert(index, '0')
            hostnames.append(sort)
    
    hostnames.sort()

    #adds hostnames to the bottom of IP addresses
    for host in hostnames:
        sorted_ips.append(host)
    #Gets Report Host from IP address in list
    for ip in sorted_ips:
        ports = {}
        path_ = '//ReportHost[@name="'+ip+'"]'
        path2 = './/ReportItem'

        host = doc.xpath(path_)[0]
        hostpath = host.xpath(path2)
        #Gets Port from nessus file and gets the plugin.
        for it in hostpath:
            port = it.xpath('@port')[0]
            getservice = (it.xpath('@pluginFamily')[0])
            port = int(port)
            #Port is not in ports and port doesnt equal 0 adds port to dictionary with blank secondary value
            portlist =  port not in ports
            if portlist == True:
                if port != 0:
                    port = int(port)
                    ports[port] = ''
               # if service is 'service detection' get svc_name from xml 
            if getservice == 'Service detection':
                    ports[port] = (it.xpath('@svc_name')[0])
   

        port_sort = sorted(ports.items(), key=lambda x: x[0])    
        ports_sorted = OrderedDict(sorted(ports.items(), key=lambda x: x[0]))
      

        if len(port_sort) != 0:
            for key, value in ports_sorted.items():
                print (ip + " | " + str(value) + " | " + str(key))
            print("\n")
    askuser(options)


def askuser(options):
    global inputNo

    index = 0
    indexValidList = []
    print('Select a option:')
    for optionName in options:
        index = index + 1
        indexValidList.extend([options[optionName]])
        print(str(index) + ') ' + optionName)
    inputValid = False
    while not inputValid:
        inputRaw = input('option' + ': ')
        inputNo = int(inputRaw) - 1
        if inputNo > -1 and inputNo < len(indexValidList):
            selected = indexValidList[inputNo]
            print('Selected option: ' + selected)
            inputValid = True
        else:
            print('Please select a valid number')

    match inputNo:
        case 0:
            fileSelect()
        case 1:
            targetripper()
        case 2:
            hostname()
        case 3:
            target_port()
        case 4:
            removeExcess()
        case 5:
            stripservices()
        case 6:
            exit()
option = askuser(options)
