"""
Sia Network Data Analytics API

A control layer for software-defined network measurement (SDNM); named after the 
Egyptian god of foresight.

Author:  Michael P. McGarry, and Christopher Mendoza
Version: 0.99
Date:    June 6, 2019

List of features to add:
1. Data aggregation capabilities across time and space (creating composite flow records)
2. Create event monitoring functions
"""
import time
import datetime
import math
import socket
import json
import requests
import sys
import os
import io
import subprocess
import urllib.request
import shutil
import zipfile
import networkx as nx
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import sklearn.cluster
import sklearn.neighbors
import seaborn as sns
import re
import xmltodict
from netmiko import ConnectHandler
import paramiko

if sys.platform != 'win32':
    import easysnmp
    import ssh


# path to CSV files containing IP address data (AS data, geo data), UPDATE FOR YOUR SYSTEM
csvpath = './'

# IP addresses for REST API of OpenTap instrument locations
LOCAL = { 'name': 'local', 'ipaddr': '127.0.0.1', 'portnum': '2020' }

##############################################################
#                                                            #
#        SDNM Interface to Infrastructure Functions          #
#       (Measurement devices, switches, stored data)         #
#                                                            #
##############################################################

def ipRow(rows):
    dicts = []
    for row in rows:
        # split start IP address from subnet size
        networkSplit = row.split('/')
        # Convert starting IP address from dotted decimal to an integer
        ipDotted = networkSplit[0]
        startIP = dotToDec(ipDotted)
        # Determine ending IP address from subnet size
        subnetSize = int(networkSplit[1])
        endIP = startIP + (1 << (32 - subnetSize)) - 1
        dicts.append({'startIP':int(startIP), 'endIP':int(endIP)})
    return pd.DataFrame(dicts)

#
# Function: updateGeoData
#
def updateGeoData(directory = csvpath):
    """
    Update IP to Geographic data by acquiring latest free database from MaxMind
    Input:  directory - Directory to place data (defaults to the csvpath variable)
    Output: None, just creates the iplocation.csv file used by Sia
    """
    url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip'
    file_name = 'GeoLite2-City-CSV'
    print("Warning: This entire process can take about an hour. We hope to reduce this time in a future version of Sia.")
    print("Retrieving data from MaxMind...")
    #Download the file from `url` and save it locally under `file_name`:
    with urllib.request.urlopen(url) as response, open(file_name + '.zip', 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
    
    #Extract files
    print("Uncompressing data...")
    myzipfile = zipfile.ZipFile(file_name + '.zip')
    path = '.' + file_name
    myzipfile.extractall(path)
    
    #Load datasets and merge
    print("Merging data...")
    subdir = os.walk(path)
    subdir = [x for x in subdir]
    subdir = subdir[0][1][0]
    df1 = pd.read_csv(path + '/' + subdir + '/GeoLite2-City-Blocks-IPv4.csv',index_col = 1)
    df2 = pd.read_csv(path + '/' + subdir + '/GeoLite2-City-Locations-en.csv',index_col = 0)
    df = df1.join(df2)
    df = df.loc[:, ['network', 'latitude', 'longitude', 'city_name', 'subdivision_1_name', 'country_name', 'continent_name']]
    df.columns = ['network', 'latitude', 'longitude', 'city', 'region', 'country', 'continent']
    #df = df.drop(columns = ['geoname_id'])
    df = df.reset_index()
    print("Converting IP addresses...")
    newdf = ipRow(df['network'].tolist())
    df = pd.concat([df.reset_index(drop = True), newdf.reset_index(drop = True)], axis = 1)
    df = df.loc[:, ['startIP', 'endIP', 'network', 'latitude', 'longitude', 'city', 'region', 'country', 'continent']]
    print("Done.")
    df.to_csv(directory + 'iplocation.csv', index=False)

#
# Function: updateASData
#
def updateASData(directory = csvpath):
    """
    Update IP to AS data by acquiring latest free database from MaxMind
    Input:  directory - Directory to place data (defaults to the csvpath variable)
    Output: None, just creates the as.csv file used by Sia
    """
    url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip'
    file_name = 'GeoLite2-ASN-CSV'
    print("Retrieving data from MaxMind...")
    #Download the file from `url` and save it locally under `file_name`:
    with urllib.request.urlopen(url) as response, open(file_name + '.zip', 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
    
    #Extract files
    print("Uncompressing data...")
    myzipfile = zipfile.ZipFile(file_name + '.zip')
    path = directory + file_name
    myzipfile.extractall(path)

    #Load dataset and convert IP addresses
    print("Converting IP addresses...")
    subdir = os.walk(path)
    subdir = [x for x in subdir]
    subdir = subdir[0][1][0]
    df = pd.read_csv(path + '/' + subdir + '/GeoLite2-ASN-Blocks-IPv4.csv')
    df.columns = ['network', 'asNum', 'organization']
    newdf = ipRow(df['network'].tolist())
    df = pd.concat([df.reset_index(drop = True), newdf.reset_index(drop = True)], axis = 1)
    df = df.loc[:, ['startIP', 'endIP', 'network', 'asNum', 'organization']]
    print("Done.")
    df.to_csv(directory + 'as.csv', index=False)

#
# Function: openTapCapture
#
def openTapCapture(datatype,startTime,stopTime,captureID='auto',observationPt='',location=INSTR_LOC_VIRGO):
    """
    Start an OpenTap data capture
    Input:  datatype - packet, netflow, temp
            startTime - start time of capture in UTC UNIX seconds  
            stopTime - start time of capture in UTC UNIX seconds  
            captureID - Capture ID or filename (default is 'auto'; autogenerated ID)
            observationPt - observation point value for data capture (default is '')
            location - dictionary containing OpenTap instrument data 'name', 'ipaddr', 'portnum' (default is INSTR_LOC_VIRGO)
    Output: Capture ID
    """
    if captureID == 'auto':
        captureID = datatype + '_' + observationPt + '_' + str(startTime) + '_' + str(stopTime)
    
    # Setup the REST API URL string
    #
    if observationPt == '':
        apiString = 'http://' + location['ipaddr'] + ':' + str(location['portnum']) + '/capture/' + datatype + '?id=' + str(captureID) + '&start=' + str(startTime) + '&stop=' + str(stopTime)
    else:
        apiString = 'http://' + location['ipaddr'] + ':' + str(location['portnum']) + '/capture/' + datatype + '?id=' + str(captureID) + '&start=' + str(startTime) + '&stop=' + str(stopTime) + '&observationPt=' + observationPt

    # Make the REST API Request
    resp = requests.get(apiString)

    # Retrieve and return the measurement task ID
    print('URL: ' + apiString)
    print('RESP: ' + resp.text)
    return captureID

#
# Function: openTapRetrieve
#
def openTapRetrieve(capturetype,captureID,location=INSTR_LOC_VIRGO):
    """
    Retrieve data from an OpenTap device
    Input:  capturetype - packet, netflow, temp
            captureID - Capture ID or filename
            location - dictionary containing OpenTap instrument data 'name', 'ipaddr', 'portnum' (default is INSTR_LOC_VIRGO)
    Output: PANDAS DataFrame containing retrieved data
    """
    # Setup the REST API URL string
    #
    apiString = 'http://' + location['ipaddr'] + ':' + str(location['portnum']) + '/retrieve?id=' + captureID

    # Make the REST API Request
    resp = requests.get(apiString)
    status_code = resp.status_code
    content_type = resp.headers['Content-Type']
    
    if status_code == 200:
        # Received a positive response
        print("Received " + str(sys.getsizeof(resp.content)) + " bytes from OpenTap server.")
        print("Received " + str(resp.text.count('\n')) + " lines of text from OpenTap server.")
        if resp.text.count('\n') < 5:
            print("RESP: " + resp.text)
            return pd.DataFrame()
        if content_type == 'text/csv':
            csvFile = io.StringIO(resp.text)
            if capturetype == 'netflow':
                netflowData = pd.read_csv(csvFile)
                if set(['ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'ipkt', 'ibyt']).issubset(netflowData.columns):
                    # Netflow data is in NFDUMP format, convert it
                    netflowData = nfdumpToNetflow(netflowData)
                return netflowData
            elif capturetype == 'temperature':
                tempData = pd.read_csv(csvFile)
                tempData['time'] = pd.to_datetime(tempData['time'])
                return tempData
            elif capturetype == 'ethernet':
                ethernetData = pd.read_csv(csvFile)
                ethernetData['time'] = pd.to_datetime(ethernetData['time'])
                return ethernetData
            else:
                print("Unsupported data type: " + capturetype)
                return pd.DataFrame()
        else:
            # Server did not return a CSV file
            # Return a NULL PANDAS data frame
            print('OpenTap server returned: "' + resp.text + '"')
            return pd.DataFrame()
    else:    
        # Error from server, return response string
        print("Error response from OpenTap device ("+str(status_code)+")")
        print('OpenTap server returned: "' + resp.text + '"')
        return pd.DataFrame()

#
# Function: netflowLoad
#
def netflowLoad(filename):
    """
    Load Netflow records from a CSV file; includes NFDUMP CSV format and flow-tools format
    Input:  CSV filename
    Output: Netflow records as a PANDAS data frame
    """
    try:
        netflowData = pd.read_csv(filename, parse_dates=True, infer_datetime_format=True)
        if set(['ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'ipkt', 'ibyt']).issubset(netflowData.columns):
            # Netflow data is in NFDUMP format, convert it
            netflowData = nfdumpToNetflow(netflowData)

    except UnicodeDecodeError:
        netflowData = netflowFlowtoolsLoad(filename)
    netflowData['first'] = pd.to_datetime(netflowData['first'])
    netflowData['last'] = pd.to_datetime(netflowData['last'])
    
    return netflowData
    
#
# Function: netflowStore
#
def netflowStore(netflowData,filename):
    """
    Store Netflow records to a CSV file
    Input:  netflowData - Netflow records as a PANDAS data frame
            filename - CSV filename
    Output: Error code from to_csv() PANDAS method
    """
    return netflowData.to_csv(filename, index=False)
    
#
# Function: netflowFlowtoolsLoad
#
def netflowFlowtoolsLoad(filename):
    """
    Convert Flow-tools Netflow records in a file format to our Netflow v5 CSV format
    Input:  Filename containing NetFlow records in flow-tools format
    Output: PANDAS data frame containing NetFlow records in our format
    """
    # Check if flow-tools is installed
    res = subprocess.run(['which','flow-export'])
    if res.returncode != 0:
        print("flow-export not found: flow-tools package needs to be installed: go to https://code.google.com/archive/p/flow-tools/ to download the source code.")
        # return empty NetFlow dataframe
        netflowData = pd.DataFrame(columns=['first','last','duration','srcaddr','dstaddr','srcport','dstport','prot','dPkts','dOctets'])
    else:
        convertString = "flow-export -f2 -mUNIX_SECS,UNIX_NSECS,SYSUPTIME,DPKTS,DOCTETS,FIRST,LAST,SRCADDR,DSTADDR,SRCPORT,DSTPORT,PROT < "
        # result = os.system(convertString+"ft-v05.2017-03-15.000000-0400 > ft-v05.2017-03-15.000000-0400.csv")
        # Use flow-export to perform conversion to a CSV file
        # Check if flow-tools is available
        if os.system(convertString+filename+" > "+filename+".csv"+" 2> /dev/null") == 0:
            netflowData = pd.read_csv(filename+".csv")
            # Reorder columns
            netflowData = netflowData[['#:unix_secs','unix_nsecs','sysuptime','first','last','srcaddr','dstaddr','srcport','dstport','prot','dpkts','doctets']]
            # Rename these columns:
            netflowData.columns = ['unix_secs','unix_nsecs','sys_time','first','last','srcaddr','dstaddr','srcport','dstport','prot','dPkts','dOctets']
            netflowData['boot_time'] = netflowData['unix_secs'] * 1000 + netflowData['unix_nsecs'] / 1000000 - netflowData['sys_time'] # compute boot time in milliseconds
            netflowData['boot_time'] = netflowData['boot_time'].astype(int)
            # Convert first and last to UNIX epoch time values
            netflowData['first'] = netflowData['first'] + netflowData['boot_time']
            netflowData['last'] = netflowData['last'] + netflowData['boot_time']
            netflowData['duration'] = netflowData['last'] - netflowData['first']
            netflowData = netflowData.loc[:, ['first', 'last', 'duration', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'prot', 'dPkts', 'dOctets']]
        else:
            print("Invocation of flow-export to convert flow-tools format to NetFlow CSV failed.")
            # return empty NetFlow dataframe
            netflowData = pd.DataFrame(columns=['first','last','duration','srcaddr','dstaddr','srcport','dstport','prot','dPkts','dOctets'])
    return netflowData

#
# Function: nfdumpToNetflow
#
def nfdumpToNetflow(nfdumpData):
    """
    Convert Netflow records in NFDUMP CSV file format to our Netflow v5 format
    Input:  PANDAS data frame containing NetFlow records in NFDUMP format
    Output: PANDAS data frame containing NetFlow records in our format
    """
    # Removes the Summary data from the last 3 rows:
    nfdumpData = nfdumpData[:(len(nfdumpData.index)-3)]

    # Keep only the columns of interest:
    nfdumpData = nfdumpData[['ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'ipkt', 'ibyt']]

    # Rename these columns:
    nfdumpData.columns = ['first','last','duration','srcaddr','dstaddr','srcport','dstport','prot','dPkts','dOctets']
    
    # Make sure the column types are correct:
    nfdumpData['first'] = nfdumpData['first'].astype(str)
    nfdumpData['last'] = nfdumpData['last'].astype(str)
    nfdumpData['first'] = pd.to_datetime(nfdumpData['first'])
    nfdumpData['last'] = pd.to_datetime(nfdumpData['last'])
    nfdumpData['duration'] = nfdumpData['duration'].astype(float) * 1000
    nfdumpData['duration'] = nfdumpData['duration'].astype(int)
    nfdumpData['srcaddr'] = nfdumpData['srcaddr'].astype(str)
    nfdumpData['dstaddr'] = nfdumpData['dstaddr'].astype(str)
    nfdumpData['srcport'] = nfdumpData['srcport'].astype(int)
    nfdumpData['dstport'] = nfdumpData['dstport'].astype(int)
    nfdumpData['prot'] = nfdumpData['prot'].astype(str).str.lower()
    nfdumpData['dPkts'] = nfdumpData['dPkts'].astype(int)
    nfdumpData['dOctets'] = nfdumpData['dOctets'].astype(int)

    return nfdumpData

#
# Function: xmlToCsv
#
def xmlToCsv(xmlString):
    """
    Converts XML string from NS-3 flowmon to our NetFlow format.
    input: XML string
    output: Netflow dataframe
    """
    mapper = {
            '@timeFirstTxPacket':'first',
            '@timeLastTxPacket':'last',
            'duration':'duration',
            '@sourceAddress':'srcaddr',
            '@destinationAddress':'dstaddr',
            '@sourcePort':'srcport',
            '@destinationPort':'dstport',
            '@protocol':'prot',
            '@rxPackets':'dPkts',
            '@rxBytes':'dOctets'
            }
    
    flows = xmltodict.parse(xmlString)['FlowMonitor']
    flowStats = pd.DataFrame(flows['FlowStats']['Flow'])
    flowClassifier = pd.DataFrame(flows['Ipv4FlowClassifier']['Flow'])
    df = flowStats.merge(flowClassifier).drop(['Dscp'],axis=1)
    for x in df:
        try:
            df[x] = df[x].str.replace('ns','')
            df[x] = df[x].str.replace('+','')
        except AttributeError:
            pass
    for x in df:
        try:
            df[x] = df[x].astype(float)
        except:
            pass
    df['tput'] = df['@rxBytes']*8/(df['@timeLastRxPacket'] - df['@timeFirstRxPacket'])*1000000000
    df['duration'] = (df['@timeLastRxPacket'] - df['@timeFirstRxPacket'])*1000000000
    df = df[df['tput'] != np.inf]
    df = df.dropna()
    df.rename(mapper, axis = 1, inplace = True)
    df = df[list(mapper.values())]
    
    return df

#
# Function: snmpWalk
#
def snmpWalk(ipAddr, rootOID, community = 'public', version = 2):
    """
    Collect the switch data via SNMP starting at a root OID (i.e., SNMP walk)
    Input:  ipAddr - IP address of switch to collect data from
            rootOID - root OID to start SNMP walk
            community - SNMP community value (default is 'public')
            version - SNMP version (default is 2)
    Output: Dictionary containing SNMP data starting at root OID
    """
    if sys.platform == 'win32':
        print('This function is not currently supported on Windows.')
        return -1
    
    session = easysnmp.Session(hostname=ipAddr, community='public', version=2)
    req = session.walk(rootOID)
    snmpDict = {}
    currOID = ''
    for variable in req:
        if variable.oid == currOID:
            # another index for the current OID
            snmpDict[variable.oid].append(variable.value)
        else:
            # create the new dictionary key for the new OID
            currOID = variable.oid
            snmpDict[variable.oid] = []
            snmpDict[variable.oid].append(variable.value)

    return snmpDict

#
# Function: getSwitchData
#
def getSwitchData(mgmtIpAddr, datatype='intf', protocol='snmp'):
    """
    Collect switch data via SNMP or CLI using pneumonics for different data types
    Input:  mgmtIpAddr - IP address of switch to collect data from
            datatype - data type to collect: 'intf', 'info', 'ip', 'tcp', 'udp', 'transmission' (default is 'intf')
            protocol - protocol to use to collect data: SNMP or CLI (default is 'snmp')
    Output: Dictionary containing switch data
    """
    if protocol == 'snmp':
        if datatype == 'intf':
            enetDict = snmpWalk(mgmtIpAddr, '1.3.6.1.2.1.2')
            print(enetDict)
            #enetDict = snmpWalk(mgmtIpAddr, 'mib-2')
            counters = []
            for port in range(int(enetDict['ifNumber'][0])):
                portDict = {}
                portDict['Descr'] = enetDict['ifDescr'][port]
                portDict['Type'] = enetDict['ifType'][port]
                portDict['Mtu'] = int(enetDict['ifMtu'][port])
                portDict['Speed'] = int(enetDict['ifSpeed'][port])
                portDict['PhysAddress'] = enetDict['ifPhysAddress'][port]
                portDict['OperStatus'] = int(enetDict['ifOperStatus'][port])
                portDict['InOctets'] = int(enetDict['ifInOctets'][port])
                portDict['InDiscards'] = int(enetDict['ifInDiscards'][port])
                portDict['OutOctets'] = int(enetDict['ifOutOctets'][port])
                portDict['OutDiscards'] = int(enetDict['ifOutDiscards'][port])
                counters.append(portDict)
                return counters
        elif datatype == 'info':
            mgmtDict = snmpWalk(mgmtIpAddr, 'system')
            infoDict = {}
            infoDict['sysName'] = mgmtDict['sysName']
            infoDict['sysLocation'] = mgmtDict['sysLocation']
            infoDict['sysContact'] = mgmtDict['sysContact']
            infoDict['sysDescr'] = mgmtDict['sysDescr']
            return infoDict
        elif datatype == 'ip':
            ipDict = snmpWalk(mgmtIpAddr, 'ip')
            return ipDict
        elif datatype == 'tcp':
            tcpDict = snmpWalk(mgmtIpAddr, 'tcp')
            return tcpDict
        elif datatype == 'udp':
            udpDict = snmpWalk(mgmtIpAddr, 'udp')
            return udpDict
        elif datatype == 'transmission':
            udpDict = snmpWalk(mgmtIpAddr, 'transmission')
            return udpDict
    return 0

#
# Function: lldpTopologyDetect
#
def lldpTopologyDetect(ipAddr):
    """
    This function will visualize and return network topology data by using LLDP.
    All switches must be configured with LLDP enabled and SNMP enables. The managment address must be broadcast over LLDP for all switches.
    Input: ipAddr - IP address of switch to start search
    Output: two dataframes containing node and connection information
    """
    if sys.platform == 'win32':
            print('This function is not currently supported on Windows.')
            return -1
    links = pd.DataFrame()
    nodes = []
    
    rootIPs = [ipAddr]
    searchedIPs = []
    connections = []
    baseOID = 'iso.0.8802.1.1.2.1.4'
    
    suffixOID = {
                'Port':baseOID + '.1.1.8',
                'Name':baseOID + '.1.1.9', #name
                'Description':baseOID + '.1.1.10', #description
                'SysCapabilities':baseOID + '.2.1.3', #syscapabilities
            }
    
    def ipSearch(ipList,searchedIPs = searchedIPs, connections = connections):
        for ip in ipList:
            session = easysnmp.Session(hostname=ip, community='public', version=2)
            try:
                lldpReq = session.walk(baseOID)
            except:
                print('Could not connect to ', ip)
                searchedIPs.append(ip)
                break
            uniqueRD = []
            for item in lldpReq:
                ID = item.oid.split('.')[11]
                if ID not in uniqueRD:
                    uniqueRD.append(ID)
            for u in uniqueRD:
                tempDict = {}
                for item in lldpReq:
                    for key in suffixOID:
                        if u in item.oid and suffixOID[key] in item.oid:
                            tempDict[key] = item.value
                            if key == 'SysCapabilities':
                                ipList = item.oid.split('.')[-4:]
                                tempDict['IP Address 2'] = '.'.join(ipList)
                tempDict['IP Address 1'] = ip
                connections.append(tempDict)
                
                otherDict = {}
                otherDict['IP Address'] = tempDict['IP Address 2']
                otherDict['Description'] = tempDict['Description'] 
                otherDict['Name'] = tempDict['Name'] 
                nodes.append(otherDict)
                
            searchedIPs.append(ip)
            
    def describeRoots(ipList):
        for ip in ipList:
            otherDict = {}
            otherDict['IP Address'] = ip
            session = easysnmp.Session(hostname=ip, community='public', version=2)
            try:
                description = session.walk('1.3.6.1.2.1.1.1')
                for item in description:
                    otherDict['Description'] = item.value
                description = session.walk('1.3.6.1.2.1.1.5')
                for item in description:
                    otherDict['Name'] = item.value
                nodes.append(otherDict)
            except:
                print('Could not connect to ', ip)
       
    describeRoots(rootIPs)
    ipSearch(rootIPs)
        
    while True:
        links = pd.DataFrame(connections)
        foundIPs = pd.unique(links[['IP Address 1', 'IP Address 2']].values.ravel('K')).tolist()
        for sIP in searchedIPs:
            try:
                foundIPs.remove(sIP)
            except ValueError:
                pass
        if len(foundIPs) == 0:
            break
        else:
            ipSearch(foundIPs)
            
            
    switches = pd.DataFrame(nodes).drop_duplicates(['IP Address'])
    foundIPs = pd.unique(links[['IP Address 1', 'IP Address 2']].values.ravel('K')).tolist() 
    unique_connections = links.groupby(['IP Address 1', 'IP Address 2']).size().reset_index()       
    G = nx.Graph()
    G.add_nodes_from(foundIPs)
    addedLinks = []
    for index, row in unique_connections.iterrows():
        if (row['IP Address 1'],row['IP Address 2']) not in addedLinks and (row['IP Address 2'],row['IP Address 1']) not in addedLinks:
            G.add_edge(row['IP Address 1'],row['IP Address 2'])
            addedLinks.append((row['IP Address 1'],row['IP Address 2']))
    nx.draw(G, with_labels=True)
    plt.show()
    return {'links':links, 'nodes':switches}


##############################################################
#                                                            #
#              SDNM Filtering/Splitting Functions            #
#                                                            #
##############################################################

#
# Function: netflowRemoveNoise
#
def netflowRemoveNoise(netflowData,bytes=256,packets=2):
    """
    Remove Netflow records that we classify as noise based on dOctets and dPkts
    Input:  netflowData - NetFlow data as a PANDAS dataframe
            bytes - minimum number of bytes (default is 256)
            packets - minimum number of packets (default is 2)
    Output: Subset of Netflow records that meet requirements to remove 'noise'
    """
    return netflowData[(netflowData['dOctets'] >= bytes) & (netflowData['dPkts'] >= packets)]

#
# Function: netflowIsolateNoise
#
def netflowIsolateNoise(netflowData,bytes=256,packets=2):
    """
    Isolate Netflow records that we classify as noise based on dOctets and dPkts
    Input:  netflowData - NetFlow data as a PANDAS dataframe
            bytes - maximum number of bytes, exclusive (default is 256)
            packets - maximum number of packets, exclusive (default is 2)
    Output: Subset of Netflow records that meet requirements for 'noise'
    """
    return netflowData[(netflowData['dOctets'] < bytes) & (netflowData['dPkts'] < packets)]

#
# Function: distrRemoveNoise
#
def distrRemoveNoise(distrData,probThresh=0.001):
    """
    Remove distribution values that fall below a certain threshold
    Input:  distrData - Distribution data
            probThresh - probability threshold (default = 0.001)
    Output: Subset of distribution values that meet requirements to remove 'noise'
    """
    newDistrData = {}
    for key in distrData:
        if distrData[key] > probThresh:
            newDistrData[key] = distrData[key]
    return newDistrData

#
# Function: distrIsolateNoise
#
def distrIsolateNoise(distrData,probThresh=0.33):
    """
    Remove distribution values that fall above a certain threshold
    Input:  distrData - Distribution data
            probThresh - probability threshold (default = 0.33)
    Output: Subset of distribution values that meet requirements for 'noise'
    """
    newDistrData = {}
    for key in distrData:
        if distrData[key] < probThresh:
            newDistrData[key] = distrData[key]
    return newDistrData

#
# Function: splitNetflowTime
#
def splitNetflowTime(netflowData,splitNum,splitField='first'):
    """
    Split Netflow records across time
    Input:  netflowData - NetFlow data as a PANDAS dataframe
            splitNum - number of smaller dataframes to create
            splitField - NetFlow time field to split on: 'first', 'last' (default is 'first')
    Output: A list of smaller dataframes split according to specified criteria
    """
    netflowList = []
    if splitField == 'first':
        # Calculate time range for this dataframe
        minval = netflowData['first'].astype(np.int64).min() / int(1e6) # convert from datetime[ns] to integer [ms]
        maxval = netflowData['first'].astype(np.int64).max() / int(1e6) # convert from datetime[ns] to integer [ms]
        timerange = maxval - minval
        timeinterval = math.ceil(timerange / splitNum)
        for i in range(splitNum):
            if i != splitNum - 1:
                subDF = netflowData[((netflowData['first'].astype(np.int64) / int(1e6)) >= minval + i*timeinterval) & ((netflowData['first'].astype(np.int64) / int(1e6)) < minval + (i+1)*timeinterval)]
            else:
                subDF = netflowData[((netflowData['first'].astype(np.int64) / int(1e6)) >= minval + i*timeinterval) & ((netflowData['first'].astype(np.int64) / int(1e6)) <= maxval)]
            netflowList.append(subDF)
    elif splitField == 'last':
        # Calculate time range for this dataframe
        minval = netflowData['last'].astype(np.int64).min() / int(1e6) # convert from datetime[ns] to integer [ms]
        maxval = netflowData['last'].astype(np.int64).max() / int(1e6) # convert from datetime[ns] to integer [ms]
        timerange = maxval - minval
        timeinterval = math.ceil(timerange / splitNum)
        for i in range(splitNum):
            if i != splitNum - 1:
                subDF = netflowData[((netflowData['last'].astype(np.int64) / int(1e6)) >= minval + i*timeinterval) & ((netflowData['last'].astype(np.int64) / int(1e6)) < minval + (i+1)*timeinterval)]
            else:
                subDF = netflowData[((netflowData['last'].astype(np.int64) / int(1e6)) >= minval + i*timeinterval) & ((netflowData['last'].astype(np.int64) / int(1e6)) <= maxval)]
            netflowList.append(subDF)
                
    return netflowList

#
# Function: splitNetflowSpace (Continent or Country or Region or City, Source or Destination)
#
def splitNetflowSpace(df, level, direction):
    """
    Splits netflow across space.
    Input: level - the space level to split by e.g. city, region, country or continent
           direction - specify source or destination
    Output: A dictionary with a dataframe for each unique item found for given query.
    """
    re = {}
    di = {'src':'src', 'dst':'dst', 'source':'src', 'destination':'dst'}
    column = di[direction] + '_' + level
    for item in df[column].unique():
        re[item] = df[df[column] == item]
    return re

##############################################################
#                                                            #
#              SDNM Join Functions                           #
#                                                            #
##############################################################

#
# Function: netflowJoin
#
def netflowJoin(netflowData, extData='app'):
    """
    Adds application data to Netflow records
    Input:  netflowData - Netflow records as a PANDAS data frame
            extData - external data to join with: 'app', 'asgeo' (default is 'app')
    Output: Netflow records (with application data) as a PANDAS data frame
    """
    if extData == 'app':
        loadPortnumData()
        netflowData = netflowAddApplication(netflowData)
    elif extData == 'asgeo':
        netflowData = netflowAddASGeo(netflowData)
    return netflowData

#
# These two functions (appDecision and appConflict) are helper functions to add application data to NetFlow
#
def appDecision(src, dst):
    if pd.isna(src):
        return dst
    elif pd.isna(dst):
        return src
    elif src == dst:
        return src
    else:
        return np.nan

def appConflict(row):
    # Maybe select the application that is most popular? (A crude way to do that is to go in favor of the smaller port number)
    if row['srcport'] < row['dstport']:
        row['app'] = row['src_app']
    else:
        row['app'] = row['dst_app']
    return row

#
# Function: netflowAddApplication
#
def netflowAddApplication(netflowData):
    """
    Adds application data to Netflow records
    Input:  Netflow records as a PANDAS data frame
    Output: Netflow records (with application data) as a PANDAS data frame
    """
    # Join with port number data for source and destination
    if netflowData['prot'].dtype == 'int64':
        portnumLookup = portnum[['portnum','prot','name']]
    else:
        netflowData['prot'] = netflowData['prot'].str.lower()
        portnumLookup = portnum[['portnum','ipproto','name']]
    portnumLookup.columns = ['srcport','prot','src_app']
    netflowData = netflowData.merge(portnumLookup, on=('srcport','prot'), how='left')
    portnumLookup.columns = ['dstport','prot','dst_app']
    netflowData = netflowData.merge(portnumLookup, on=('dstport','prot'), how='left')
    netflowData = netflowData.reindex()
    
    # Combine the source and destination application data into one column, where there is a conflict make it NULL
    srcAppData = netflowData['src_app']
    dstAppData = netflowData['dst_app']
    netflowData['app']  = srcAppData.combine(dstAppData, appDecision)
    
    # 
    # Handle the conflicts between source and destination information
    #
    # Split the dataframe
    mask = netflowData['app'].isna() & netflowData['src_app'].notna() & netflowData['dst_app'].notna()
    netflowDataAppGood = netflowData[~mask]
    netflowDataAppConflict = netflowData[mask]
    netflowDataAppConflict = netflowDataAppConflict.apply(appConflict,axis='columns')
    # Merge DataFrames back together
    netflowData = pd.concat([netflowDataAppGood, netflowDataAppConflict])
    netflowData = netflowData.sort_index()

    return netflowData

#
# Function: netflowAddASGeo
#
def netflowAddASGeo(netflowData):
    """
    Annotate Netflow records with AS and geographic information
    Input:  Netflow records as a PANDAS data frame
    Output: Netflow records (with AS and Geo data) as a PANDAS data frame
    """
    # For each unique source IP address, perform a lookup
    srcIp = pd.DataFrame(columns=['srcaddr', 'src_as', 'src_org', 'src_lat', 'src_long', 'src_city', 'src_region', 'src_country', 'src_continent'])
    srcaddr = netflowData['srcaddr'].unique().astype(str).tolist()
    for addr in srcaddr:
        srcIpData = ipLookup(addr)
        srcIp = srcIp.append({'srcaddr': addr, 'src_as': int(srcIpData['asnum']), 'src_org': srcIpData['orgname'], 'src_lat': srcIpData['latitude'], 'src_long': srcIpData['longitude'], 'src_city': srcIpData['city'], 'src_region': srcIpData['region'], 'src_country': srcIpData['country'], 'src_continent': srcIpData['continent']}, ignore_index=True)
    # Join the data
    netflowData = netflowData.merge(srcIp, on=('srcaddr'), how='left')
    # For each unique source IP address, perform a lookup
    dstIp = pd.DataFrame(columns=['dstaddr', 'dst_as', 'dst_org', 'dst_lat', 'dst_long', 'dst_city', 'dst_region', 'dst_country', 'dst_continent'])
    dstaddr = netflowData['dstaddr'].unique().astype(str).tolist()
    for addr in dstaddr:
        dstIpData = ipLookup(addr)
        dstIp = dstIp.append({'dstaddr': addr, 'dst_as': int(dstIpData['asnum']), 'dst_org': dstIpData['orgname'], 'dst_lat': dstIpData['latitude'], 'dst_long': dstIpData['longitude'], 'dst_city': dstIpData['city'], 'dst_region': dstIpData['region'], 'dst_country': dstIpData['country'], 'dst_continent': dstIpData['continent']}, ignore_index=True)
    # Join the data
    netflowData = netflowData.merge(dstIp, on=('dstaddr'), how='left')

    return netflowData


##############################################################
#                                                            #
#              SDNM Aggregating Functions                    #
#                                                            #
##############################################################

#
# Function: trafficMatrix
#
def trafficMatrix(netflowData, agg = 'as'):
    """
    Create a traffic matrix from Netflow records with Geo and AS information
    Input:  netflowData - Netflow records as a PANDAS data frame
            agg - aggregation level (continent, country, AS)
    Output: Dictionary with traffic matrix ['data'], src/dst label indices ['src'] and ['dst'], and values indices ['values']
    """
    matrix = {}
    agg = agg.lower()
    unique = netflowData.groupby([f'src_{agg}', f'dst_{agg}']).size().index.tolist()
    matrix['src'] = list(set([x[0] for x in unique]))
    matrix['dst'] = list(set([x[1] for x in unique]))
    matrix['src'] = sorted(matrix['src'])
    matrix['dst'] = sorted(matrix['dst'])
    if agg == 'as':
        matrix['src'] = list(map(int, matrix['src']))
        matrix['dst'] = list(map(int, matrix['dst']))
    matrix['data'] = np.zeros((len(matrix['src']),len(matrix['dst']),3))
    matrix['values'] = ['bytes','packets', 'flows']
    
    for pair in unique:
        indb = (matrix['src'].index(pair[0]), matrix['dst'].index(pair[1]), 0)
        indp = (matrix['src'].index(pair[0]), matrix['dst'].index(pair[1]), 1)
        indfc = (matrix['src'].index(pair[0]), matrix['dst'].index(pair[1]), 2)
        temp = netflowData.query(f'src_{agg} == "{pair[0]}" and dst_{agg} == "{pair[1]}"')
        matrix['data'][indb] = temp['dOctets'].sum()
        matrix['data'][indp] = temp['dPkts'].sum()
        matrix['data'][indfc] = len(temp)
        
    return matrix

#
# Function: inspectTrafficMatrix
#
def inspectTrafficMatrix(matrix, src, dst, values = 'flows'):
    """
    Helper function to inspect contents of a traffic matrix (handles indexing the NumPy array)
    Input:  matrix - traffic matrix
            src - source to index
            dst - destination to index
            values - value to index (i.e., 'bytes', 'packets', 'flows')
    Output: Indexed value in traffic matrix
    """
    try:
        value = matrix['data'][matrix['src'].index(src), matrix['dst'].index(dst), matrix['values'].index(values)]
    except ValueError:
        if src not in matrix['src']:
            print(str(src)+' not a source in the traffic matrix')
        if dst not in matrix['dst']:
            print(str(dst)+' not a destination in the traffic matrix')
        if values not in matrix['values']:
            print(str(values)+' not a value type in the traffic matrix')
        return -1
    return value

#
# Function: netflowSummary
#
def netflowSummary(netflowData):
    """
    Summarize NetFlow data (byte distribution over applications/organizations)
    Input:  Netflow records as a PANDAS data frame
    Output: Dictionary with byte distributions over applications and organizations
    """
    print("Warning: This function takes a while to complete. We will try to improve the performance in a future update.")
    apps = netflowData.app.unique()
    apps = apps[pd.notnull(apps)]
    apps = np.sort(apps)
    appByteCount = {}
    totalBytes = 0
    for app in apps:
        appByteCount[app] = netflowData[netflowData['app'] == app]['dOctets'].sum()
        totalBytes = totalBytes + appByteCount[app]
    appDistr = {}
    for app in apps:
        appDistr[app] = float(netflowData[netflowData['app'] == app]['dOctets'].sum() / totalBytes)
    orgSRC = netflowData.src_org.unique()
    orgDST = netflowData.dst_org.unique()
    orgs = np.concatenate((orgSRC,orgDST))
    orgs = orgs[pd.notnull(orgs)]
    orgs = np.unique(orgs)
    orgs = np.sort(orgs)
    orgByteCount = {}
    totalBytes = 0
    for org in orgs:
        orgByteCount[org] = netflowData[(netflowData['src_org'] == org) | (netflowData['dst_org'] == org)]['dOctets'].sum()
        totalBytes = totalBytes + orgByteCount[org]
    orgDistr = {}
    for org in orgs:
        orgDistr[org] = float(netflowData[(netflowData['src_org'] == org) | (netflowData['dst_org'] == org)]['dOctets'].sum() / totalBytes)
    return { 'appBytes': appByteCount, 'appDistr': appDistr, 'orgBytes': orgByteCount, 'orgDistr': orgDistr }

#
# Function: netflowAppDistr
#
def netflowAppDistr(netflowData):
    """
    Obtain application distribution over bytes, packets, and flows from NetFlow data
    Input:  Netflow records as a PANDAS data frame
    Output: Dictionary with app distributions over bytes, packets, and flows
    """
    # Use groupby() to split NetFlow records by application, then apply sum() or count()
    # as appropriate
    appDistrFlows = netflowData.groupby('app')['dPkts'].count()
    appDistrFlows = appDistrFlows / appDistrFlows.sum()
    appDistrFlows = appDistrFlows.sort_values(ascending=False)
    appDistrPackets = netflowData.groupby('app')['dPkts'].sum()
    appDistrPackets = appDistrPackets / appDistrPackets.sum()
    appDistrPackets = appDistrPackets.sort_values(ascending=False)
    appDistrBytes = netflowData.groupby('app')['dOctets'].sum()
    appDistrBytes = appDistrBytes / appDistrBytes.sum()
    appDistrBytes = appDistrBytes.sort_values(ascending=False)

    return { 'flows': appDistrFlows, 'packets': appDistrPackets, 'bytes': appDistrBytes }
    

##############################################################
#                                                            #
#           SDNM Event Detection Functions                   #
#                                                            #
##############################################################

#
# Function: netflowDetectIntrusion
#
def netflowDetectIntrusion(netflowData, method="sshcure_v2"):
    """
    Detect system intrusions in NetFlow data (uses SSHCure rules [University of Twente])
    Input:  Netflow records as a PANDAS data frame
    Output: A dictionary containing data regarding the SSH system intrusions detected
    """
    if method == "sshcure":
        return netflowDetectSSHIntrusion(netflowData)
    elif method == "sshcure_v2":
        return netflowDetectSSHIntrusion_v2(netflowData)
    else:
        print("Invalid method")
        return {}

#
# Function: netflowDetectSSHIntrusion
#
def netflowDetectSSHIntrusion(netflowData):
    """
    Detect system intrusions via SSH in NetFlow data (uses SSHCure rules [University of Twente])
    Input:  Netflow records as a PANDAS data frame
    Output: A dictionary containing data regarding the SSH system intrusions detected
    """
    ### Dictonary to hold all the intrusion info
    intrusion_dict = {}    
    
    ssh = netflowData
    #Sort out only SSH connections
    ssh = netflowData[(netflowData.srcport==22) | (netflowData.dstport==22)]

    #Set rules for scan phase detection
    scan = ssh[(ssh.dPkts <= 2)]
    BF = ssh[(ssh.dPkts >= 8) & (ssh.dPkts <= 14)]

    #Sort the dataframe in chronological order
    scansorted = scan.sort_values(['first','dstaddr'])
    BFsorted = BF.sort_values(['first','dstaddr'])

    #Get values for how many times a certain IP address appears as a source
    srccount = scansorted['srcaddr'].value_counts()
    BFsrccount = BFsorted['srcaddr'].value_counts()

    #Get values for how many times a certain IP address appears as a destination
    dstcount = scansorted['dstaddr'].value_counts()
    BFdstcount = BFsorted['dstaddr'].value_counts()

    #How many times X amount of dPkts show up
    DPcount = scansorted.dPkts.value_counts()
    DPBFCount = BFsorted.dPkts.value_counts()

    #Calculate if an IP address appears more than X amount of times
    ScanYN = dstcount + srccount >= 200
    BFYN = BFdstcount + srccount  >= 20
    
    #List IP addresses that show up more than X amount of times to determine wether to scan or not
    ScanYN = ScanYN[(ScanYN.values) == True]
    BFYN = BFYN[(BFYN.values) == True]
    
    #List all the IP addresses that meet a criteria
    scaniplist = list(ScanYN.index)
    
    ### Add entry to dictionary
    #intrusion_dict['Potential Scan Attackers'] = scaniplist    
    
    BFiplist = list(BFYN.index)
    
    ### Add entry to dictionary    
    #intrusion_dict['Potential Brute Force Attackers'] = BFiplist
    
    IPNum = len(scaniplist)
    BFIPNum = len(BFiplist)

    #Go through the list and find out if there are enough connections to suspect a port scan attack

    x=0
    scanattackerlist = []

    for x in range (0,IPNum):
        newNFD = scansorted[(scansorted.srcaddr == scaniplist[x]) | (scansorted.dstaddr == scaniplist[x])]
        maxtime = newNFD['first'].max()
        mintime = newNFD['first'].min()
        totaltime = (maxtime - mintime)/1000
        average = len(newNFD)/totaltime
        tmin = mintime
        while (tmin <= maxtime):
            tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
            tmin = tmin + 60000
          #  print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))
            if (len(tDF) >= 200):
                if scaniplist[x] not in scanattackerlist:
                    scanattackerlist.append(scaniplist[x])
                    
                    
    #BruteForce Algorithm

    y=0
    BFattackerlist = list()

    for y in range (0,BFIPNum):
        newNFD = BFsorted[(BFsorted.srcaddr == BFiplist[y]) | (BFsorted.dstaddr == BFiplist[y])]
        maxtime = newNFD['first'].max()
        mintime = newNFD['first'].min()
        totaltime = (maxtime - mintime)/1000
        average = len(newNFD)/totaltime
        tmin = mintime
        while (tmin <= maxtime):
            tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
            tmin = tmin + 60000
           # print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))
            if (len(tDF) >= 20):
                if BFiplist[y] not in BFattackerlist:
                    BFattackerlist.append(BFiplist[y])
                    
    ### Add entry to dictionary
    intrusion_dict['port_scan'] = scanattackerlist
    intrusion_dict['brute_force'] = BFattackerlist

    #
    #Die off phase with potential compromised IP addresses
    #
    z = 0
    CompList = list()
    BFLength = len(BFattackerlist)
    for z in range (0,BFLength):
        compDF = ssh[(ssh.srcaddr == BFattackerlist[z]) | (ssh.dstaddr == BFattackerlist[z])]
        compDF = compDF[((compDF.dPkts < 8) | (compDF.dPkts > 14)) & (compDF.duration > 4000)]
        CompList = np.unique(compDF[['srcaddr','dstaddr']])
        NewCompList = CompList.tolist()
        NewCompList.remove(BFattackerlist[z])
        NewCompList.sort
        
        ### Add entry to dictionary       
        intrusion_dict['compromise'] = NewCompList
        

    n = 0
    m = 0
    ScanLength = len(scanattackerlist)
    BF_d = {}
    scan_d = {}
    bf_attackers = list(set(BFattackerlist))
    scan_attackers = list(set(scanattackerlist))
    
    for n in range (0,BFLength):
        BF_d[bf_attackers[n]] = {}
        dicdf = ssh[ssh.srcaddr == bf_attackers[n]]
        BF_d[bf_attackers[n]]['org'] = dicdf.iloc[0]['src_org']
        BF_d[bf_attackers[n]]['city'] = dicdf.iloc[0]['src_city']
        BF_d[bf_attackers[n]]['country'] = dicdf.iloc[0]['src_country']
        
        intrusion_dict['brute_force'] = BF_d
        
    for m in range (0, ScanLength):    
        scan_d[scan_attackers[m]] = {}
        dicdf = ssh[ssh.srcaddr == scan_attackers[m]]
        scan_d[scan_attackers[m]]['org'] = dicdf.iloc[0]['src_org']
        scan_d[scan_attackers[m]]['city'] = dicdf.iloc[0]['src_city']
        scan_d[scan_attackers[m]]['country'] = dicdf.iloc[0]['src_country']
        
        intrusion_dict['port_scan'] = scan_d
    
        
    return intrusion_dict

#
# Function: netflowDetectSSHIntrusion_v2
#
def netflowDetectSSHIntrusion_v2(netflowData):
    """
    Detect system intrusions via SSH in NetFlow data (uses SSHCure rules [University of Twente])
    Input:  Netflow records as a PANDAS data frame
    Output: A dictionary containing data regarding the SSH system intrusions detected
    """
    ### Dictonary to hold all the intrusion info
    intrusion_dict = {}

    #Sort out only SSH connections
    ssh = netflowData[(netflowData.dstport==22)]
    Port22 = netflowData[(netflowData.dstport==22) | (netflowData.srcport==22)]
    
    BruteForceAttackers = []
    AllCompromises = []
    compromisedIPs = []
    
    if ssh.shape[0] > 0:
        #Set rules for brute force phase detection
        BF = ssh[(ssh.dPkts >= 11) & (ssh.dPkts <= 51)]
        
        if BF.shape[0] > 0:
            #Sort the dataframe in chronological order
            Reorder = BF.sort_values(['srcaddr','dstaddr','first'])
            BFsorted = Reorder.reset_index(drop = True)
            
            #Set Variables
            LoginGraceTime = 200000
            baseline = BFsorted['dPkts'].value_counts().idxmax()
            
            #Detect Brute Force Attackers
            p = len(BFsorted) - 1
            q = 0
            for q in range (0,p):
                if ((BFsorted.dPkts[q] == BFsorted.dPkts[q + 1]) & (BFsorted.srcaddr[q] == BFsorted.srcaddr[q + 1]) & (BFsorted.dstaddr[q] == BFsorted.dstaddr[q + 1])):  
                    if BFsorted.srcaddr[q] not in BruteForceAttackers:
                        BruteForceAttackers.append(BFsorted.srcaddr[q])
                        
            k = 0
            BruteForceLength = len(BruteForceAttackers)
            
            # if duration is of timedelta type, convert it to milliseconds
            if Port22.duration.dtype == 'timedelta64[ns]':
                Port22['duration'] = int(Port22['duration'].dt.microseconds / 1000)

            for k in range (0,BruteForceLength):
                tempDF = Port22[Port22.dstaddr == BruteForceAttackers[k]]
                tempDF = tempDF[tempDF.duration != LoginGraceTime]
                temporary = tempDF.srcaddr.unique()
                tempCompIP = temporary.tolist()
                AllCompromises.extend(tempCompIP)
            AllCompromises.sort()
            for w in AllCompromises:
                if w not in compromisedIPs:
                    compromisedIPs.append(w)

    intrusion_dict['brute_force'] = BruteForceAttackers
    intrusion_dict['port_scan'] = BruteForceAttackers
    intrusion_dict['compromised'] = compromisedIPs
    
    return intrusion_dict

#
# Function: netflowDetectTputAnomalies
#
def netflowDetectTputAnomalies(netflowData, method, variables=['duration', 'dOctets', 'dPkts'], hist_bins=500, hist_thresh=sys.float_info.epsilon, nneighbors=5, neighradius=1.0, neighalgo='auto', nnthresh=1):
    """
    Detect throughput anomalies in NetFlow data (uses general anomaly detection techniques)
    Statistical techniques (IQR and Histogram are uni-variate [tput], NN and LOF have a multi-variate feature space [duration, dOctets, dPkts] by default)
    Input:  netflowData - Netflow records as a PANDAS data frame
            method - anomaly detection method: inter-quartile range 'iqr', histogram 'hist', nearest neighbor 'nn', local outlier factor 'lof'
            variables - NetFlow variables to use for anomaly detection (used only for nearest neighbor and local outlier factor)
            iqr method (uses tput variable)
            hist method (uses tput variable)
                hist_bins - number of bins for histogram (default = 500)
                hist_thresh - bin probability threshold for anomaly classification (default = sys.float_info.epsilon)
            nn method (uses the set of variables specified in variables argument)
                nneighbors - number of neighbors (default = 5)
                neighradius - neighborhood radius (default = 1.0)
                neighalgo - algorithm used to compute nearest neighbors: 'auto', 'ball_tree', 'kd_tree', 'brute' (default = 'auto')
                nnthresh - number of neighbors threshold for declaring an anomaly (default = 1)
            lof method (uses the set of variables specified in variables argument)
    Output: Anomalous Netflow records as a PANDAS dataframe
    """
    # Add throughput column and eliminate all records with no throughput value
    netflowData = netflowAddThroughput(netflowData)
    netflowData = netflowData.loc[netflowData['tput'] != np.nan]
    netflowData = netflowData.loc[netflowData['tput'] != np.inf]
    if len(netflowData.index) == 0:
        print("No NetFlow records with throughput values.")
        return netflowData
    netflowData['tput'] = netflowData['tput'].astype(float)
    print(str(len(netflowData))+" NetFlow records with throughput values.")
    
    if method == 'iqr':
        #
        # Anomalies are those values that lie far outside the Inter-Quartile Range (IQR)
        #
        print(" ")
        print("<IQR Boxplot>")
        # Find summary statistics, IQR, lower, and upper ranges
        stats = netflowData['tput'].describe(include=all)
        stats = stats.to_frame().transpose()
        IQR = (stats['75%'] - stats['25%']).values
        IQR = IQR[0]
        lw_range = (stats['25%'] - (1.5*IQR)).values
        lw_range = lw_range[0]
        up_range = (stats['75%'] + (1.5*IQR)).values
        up_range = up_range[0]
        
        # Outliers are values that are higher or lower than the upper range or lower range
        outliers = netflowData.loc[netflowData['tput'] > up_range]
        outliers = outliers.loc[outliers['tput'] < lw_range]
        print('Lower range: '+str(lw_range)+" Upper range: "+str(up_range))

    elif method == 'hist':
        #
        # Anomalies are those values that lie in low probability regions of the empirical distribution
        #
        print(" ")
        print("<Histogram>")
        # Build a histogram from the data, associate NetFlow records to the bins, label records associated
        # with low proabability bins as outliers/anomalies
        
        
        # Return list with list left edges of bins +1 right edge of last bin with list counts for each bin
        # Make throughputs into list and make a fixed number of bins from them
        tputList = netflowData['tput'].tolist()
        bins = np.linspace(math.ceil(min(tputList)), 
                       math.floor(max(tputList)),
                       hist_bins) # fixed number of bins

        # Plot histogram using Matplotlib (optional)
        plt.xlim([min(tputList), max(tputList)])
        print(bins)
        (count, bins, patches) = plt.hist(tputList, bins=bins, alpha=0.7, normed=True)
        plt.title('Throughput')
        plt.xlabel('Value')
        plt.ylabel('Frequency')
        plt.show()
        
        sns.distplot(netflowData['tput'], kde = False)
        
        # Make density histogram using numpy
        (density, bins) = np.histogram(tputList, bins=hist_bins, density=True)
        
        # Make a list of labels for each record 
        indecies = np.digitize(tputList, bins)

        # Construct Python dictionary that relates the bin label with its density
        keys = list(set(indecies))
        values = list(density)
        dictionary = dict(zip(keys, values))
        
        # Create a probability list using this dictionary...
        probList = [dictionary.get(item,item)  for item in indecies]
        # ...and stitch it to the dataframe
        netflowData['Probability'] = pd.Series(probList, index=netflowData.index)
        
        # Filter outliers (anything with probability <= to the probability threshold)
        outliers = netflowData.loc[netflowData['Probability'] <= hist_thresh]

    elif method == 'nn':
        #
        # Anomalies are those points in the feature space
        #
        print(" ")
        print("<Nearest Neighbors>")
        netflowData = netflowData.reset_index()
        data = netflowData[variables].values
        neighbors = sklearn.neighbors.NearestNeighbors(n_neighbors=nneighbors, radius=neighradius, algorithm=neighalgo).fit(data)
        
        kdistances, kindices = neighbors.kneighbors(data, nneighbors)
        # indicies contains the indicies of the 'nneighbors' (default 5)
        # nearest neighbours to each point in the data.
        radiusnn = neighbors.radius_neighbors(data, neighradius)
        # radiusnn is an object where the first element is an object of
        # distances corresponding to all point within a 'neighradius' radius of
        # each point in the data, and the second element is those points' idxs.
        radiusnn = np.ndarray.tolist(radiusnn[1])
        
        # Outliers will be points that have 1 or less points in their vicinity
        # defined by 'neighradius'
        outlieridx = []
        for idx,item in enumerate(radiusnn):
            if len(item)<=nnthresh:
                outlieridx.append(idx)  
        outliers = netflowData.ix[outlieridx]

    elif method == 'lof':
        #
        # Anomalies are those points in the feature space with an LOF score higher than a threshold
        #
        print(" ")
        print("<Local Outlier Factor>")
        #netflowData = netflowData.reset_index()
        data = netflowData[variables].values
        
        lof = sklearn.neighbors.LocalOutlierFactor(n_neighbors=20)
        lof_labels = lof.fit_predict(data)  # Fits the model to the training set "data" and returns the labels (1 inlier, -1 outlier) on the training set according to the LOF score and the contamination parameter.
        lof_scores = lof.negative_outlier_factor_ # Returns the scores for each point in "data"
        netflowData['LOF'] = lof_scores   # Add a local outlier factor score column
        netflowData['LOFlbl'] = lof_labels  # Add a label column
        # As stated above, outliers are those that are identified with a -1.
        outliers = netflowData.loc[netflowData['LOFlbl'] == -1] 

    print("Found "+str(len(outliers))+" outliers.")
    return outliers


##############################################################
#                                                            #
#              SDNM Visualization Functions                  #
#                                                            #
##############################################################

#
# Function: plotDistribution
#
def plotDistribution(distrData):
    """
    Plot distribution data using Matplotlib
    Input:  Distribution data
    Output: Plot (on screen)
    """
    plt.bar(range(len(distrData)), list(distrData.values()), align='center')
    plt.xticks(range(len(distrData)), distrData.keys())
    plt.show()
    return plt
    
#
# Function: plotClusters
#
def plotClusters(netflowData,numClusters=4,cols=['srcport', 'dstport', 'dOctets']):
    """
    Plot color coded scatter plot of clusters using Matplotlib and Axes3D
    Input:  netflowData - NetFLow records as a PANDAS dataframe
            numClusters - number of clusters (default = 4)
            cols - columns (variables) to use for clustering (default = ['srcport', 'dstport', 'dOctets'])
    Output: Plot (on screen)
    """
    numCols = len(cols)
    if numCols != 2 and numCols != 3:
        print("ERROR: Cannot plot " + str(numCols) + "-dimensional data")
        return -1

    netflowData2 = netflowData.loc[:, cols]    # subset the data using the columns
    netflowData2 = netflowData2.fillna(0)
    netflowMatrix = netflowData2.as_matrix()
    km = sklearn.cluster.KMeans(n_clusters=numClusters)
    clusters = km.fit_predict(netflowMatrix)
    
    if numCols == 2:
        plt.xlabel(cols[0])
        plt.ylabel(cols[1])
        plt.scatter(x=netflowMatrix[:,0],y=netflowMatrix[:,1],c=clusters)
        plt.show()
        return plt
    elif numCols == 3:
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')
        ax.scatter(xs=netflowMatrix[:,0],ys=netflowMatrix[:,1],zs=netflowMatrix[:,2],c=clusters)
        # Set axis labels using column names
        ax.set_xlabel(cols[0])
        ax.set_ylabel(cols[1])
        ax.set_zlabel(cols[2])
        plt.show()
        return plt
    return 0

#
# Function: printIntrusion
#
def printIntrusion(intrusions):
    """
    Print contents of intrusion vector
    Input:  Intrusion vector
    Output: Print-out (on screen) of system intrusion data
    """
    print("Brute force attackers:")
    for x in intrusions['brute_force']:
        ipInfo = ipLookup2(x)
        print(x+" ["+ipInfo['orgname']+": "+ipInfo['city']+", "+ipInfo['country']+"]")
    print("Port scan attackers:")
    for x in intrusions['port_scan']:
        ipInfo = ipLookup2(x)
        print(x+" ["+ipInfo['orgname']+": "+ipInfo['city']+", "+ipInfo['country']+"]")
    if 'compromised' in intrusions:
        print("Potentially compromised systems:")
        for x in intrusions['compromised']:
            ipInfo = ipLookup2(x)
            print(x+" ["+ipInfo['orgname']+": "+ipInfo['city']+", "+ipInfo['country']+"]")
    return 0


##############################################################
#                                                            #
#              SDNM Utility Functions                        #
#                                                            #
##############################################################

#
# Function: netflowConvertProtoStr2Num
#
def netflowConvertProtoStr2Num(netflowData):
    """
    Convert IP protocol field (prot) of Netflow records from a string to a number
    Input:  Netflow records as a PANDAS data frame
    Output: Netflow records as a PANDAS data frame with prot field converted
    """
    for lab, row in netflowData.iterrows():
        if not row['prot'].isnumeric():
            netflowData.loc[lab, 'prot'] = protoData.index(row['prot'].upper())
        else:
            netflowData.loc[lab, 'prot'] = int(row['prot'])
    return netflowData

#
# Function: netflowConvertProtoNum2Str
#
def netflowConvertProtoNum2Str(netflowData):
    """
    Convert IP protocol field (prot) of Netflow records from a number to a string
    Input:  Netflow records as a PANDAS data frame
    Output: Netflow records as a PANDAS data frame with prot field converted
    """
    for lab, row in netflowData.iterrows():
        netflowData.loc[lab, 'prot'] = protoData[row['prot']]
    return netflowData

#
# Function: netflowAddThroughput
#
def netflowAddThroughput(netflowData):
    """
    Add throughput column to Netflow records
    Input:  Netflow records as a PANDAS data frame
    Output: Netflow records as a PANDAS data frame (with 'tput' column)
    """
    # Check if there is already a duration column, if not compute it as last - first
    if 'duration' in netflowData.columns:
        netflowData['tput'] = (netflowData['dOctets']*8) / (netflowData['duration']/1000)
    else:
        print("ERROR: duration column does not exist")
    return netflowData


#
# Function: dotToDec
#
def dotToDec(x):
    """
    Convert an IP address in dotted decimal (string) to an integer
    """
    splitIP = x.split('.')
    output = (int(splitIP[0]) << 24) + (int(splitIP[1]) << 16) + (int(splitIP[2]) << 8) + int(splitIP[3])
    return output

#
# Function: loadPortnumData
#
def loadPortnumData():
    """
    Load IANA Port Number Convention Data
    """
    if not 'portnum' in globals():
        try:
            global portnum
            portnum = pd.read_csv(csvpath+'portnum.csv')
            portnum = portnum.drop_duplicates(subset=['portnum','ipproto']) # remove duplicate entries in port num data
            portnum = portnum.loc[:,[True,True,True,True,False]]
            #print('Loading IANA port number data for the first time')
        except OSError:
            if 'portnum' in globals():
                del portnum
            print('portnum CSV file not found')
    return

#
# Function: loadIPLookupData
#
def loadIPLookupData():
    """
    Load IP address lookup data files (AS number and geographic data)
    """
    # Check if the files are already loaded
    if not 'asnum' in globals():
        try:
            global asnum
            asnum = pd.read_csv(csvpath+'as.csv')
            #print('Loading AS number data for the first time')
        except OSError:
            del asnum
            print('asnum CSV file not found')
    if not 'iploc' in globals():
        try:
            global iploc
            iploc = pd.read_csv(csvpath+'iplocation.csv')
            #print('Loading IP location data for the first time')
        except OSError:
            del asnum
            del iploc
            print('iploc CSV file not found')
    return

#
# Function: ipLookup
#
def ipLookup(ip):
    """
    Lookup AS number and geographic data for an IP address using local CSV files or UTEP REST service
    Input:  IP address in dotted decimal (string) or integer
    Output: A dictionary with IP address data: 'orgname', 'asnum', 'latitude', 'longitude', 'city', 'region', 'country', 'continent'
    """
    # First try using CSV file data
    loadIPLookupData()
    if not 'asnum' in globals():
        # If CSV file data is not available, then use UTEP IP lookup REST API
        print('Looking up IP data using REST API [much slower than CSV lookup]')
        apiString = 'http://engrapps.utep.edu/amis/scripts/ipdata.php?ip=' + ip
        resp = requests.get(apiString)
        resultsData = resp.json()
        return resultsData
    else:
        #print('Looking up IP data using CSV files')
        # Lookup the data in the CSV files
        if type(ip) == str:
            ipAddrVal = dotToDec(ip)
        else:
            ipAddrVal = ip
        asnumVal = asnum[(asnum['startIP'] <= ipAddrVal) & (asnum['endIP'] >= ipAddrVal)]
        iplocVal = iploc[(iploc['startIP'] <= ipAddrVal) & (iploc['endIP'] >= ipAddrVal)]
        if not asnumVal.empty :
            asVal = asnumVal['asNum'].tolist()
            asVal = int(asVal[0])
            orgVal = asnumVal['organization'].tolist()
            orgVal = orgVal[0]
        else :
            asVal = 0
            orgVal = ""
        if not iplocVal.empty :
            latVal = iplocVal['latitude'].tolist()
            latVal = latVal[0]
            longVal = iplocVal['longitude'].tolist()
            longVal = longVal[0]
            cityVal = iplocVal['city'].tolist()
            cityVal = cityVal[0]
            regionVal = iplocVal['region'].tolist()
            regionVal = regionVal[0]
            countryVal = iplocVal['country'].tolist()
            countryVal = countryVal[0]
            continentVal = iplocVal['continent'].tolist()
            continentVal = continentVal[0]
        else :
            latVal = 0.0
            longVal = 0.0
            cityVal = ""
            regionVal = ""
            countryVal = ""
            continentVal = ""
        resultsData = { 'orgname': orgVal, 'asnum': asVal, 'latitude': latVal, 'longitude': longVal, 'city': cityVal, 'region': regionVal, 'country': countryVal, 'continent': continentVal }
        return resultsData

#
# Function: asLookup
#
def asLookup(AS):
    """
    Lookup AS data
    Input:  AS number
    Output: A dictionary with AS data: 'orgname', 'latitude', 'longitude', 'city', 'region', 'country', 'continent'
    """
    # Compile AS organization and location information
    return { 'orgname': orgname, 'latitude': latitude, 'longitude': longitude, 'city': city, 'region': region, 'country': country, 'continent': continent }

#
# Function: appLookup
#
def appLookup(port,prot):
    """
    Lookup application name using port number and IP protocol number
    Input:  port - Port number 
            prot - IP protocol number
    Output: Application name (string)
    """
    loadIPLookupData()
    if not 'portnum' in globals():
        return 'no lookup data'
    else:
        portnumVal = portnum[(portnum['portnum'] == port) & (portnum['prot'] == prot)]
        if not portnumVal.empty :
            portnumVal = portnumVal.iloc[0]     # only look at the first row in the data frame
            if portnumVal['name'] != "" :
                # add the application name
                return portnumVal['name']
            else :
                # try a match to an application that is not associated with any IP protocol
                portnumVal = portnum[(portnum['portnum'] == port) & (portnum['prot'] == 255)]
                if not portnumVal.empty :
                    portnumVal = portnumVal.iloc[0]     # only look at the first row in the data frame
                    if portnumVal['name'] != "" :
                        # add the application name
                        return portnumVal['name']
                    else :
                        # add the application name "unknown"
                        return 'unknown'
                else :
                    # add the application name "unknown"
                    return 'unknown'
        else :
            # try a match to an application that is not associated with any IP protocol
            portnumVal = portnum[(portnum['portnum'] == port) & (portnum['prot'] == 255)]
            if not portnumVal.empty :
                portnumVal = portnumVal.iloc[0]     # only look at the first row in the data frame
                if portnumVal['name'] != "" :
                    # add the application name
                    return portnumVal['name']
                else :
                    # add the application name "unknown"
                    return 'unknown'
            else :
                # add the application name "unknown"
                return 'unknown'
    return 'unknown'
    
# IP Protocol number data
protoData = ('HOPOPT','ICMP','IGMP','GGP','IP-in-IP','ST','TCP','CBT','EGP','IGP','BBN-RCC-MON','NVP-II',
'PUP','ARGUS','EMCON','XNET','CHAOS','UDP','MUX','DCN-MEAS','HMP','PRM','XNS-IDP','TRUNK-1','TRUNK-2',
'LEAF-1','LEAF-2','RDP','IRTP','ISO-TP4','NETBLT','MFE-NSP','MERIT-INP','DCCP','3PC','IDPR','XTP','DDP',
'IDPR-CMTP','TP++','IL','IPv6','SDRP','IPv6-Route','IPv6-Frag','IDRP','RSVP','GRE','DSR','BNA','ESP',
'AH','I-NLSP','SWIPE (deprecated)','NARP','MOBILE','TLSP','SKIP','IPv6-ICMP','IPv6-NoNxt','IPv6-Opts',
'','CFTP','','SAT-EXPAK','KRYPTOLAN','RVD','IPPC','','SAT-MON','VISA','IPCV','CPNX','CPHB','WSN','PVP',
'BR-SAT-MON','SUN-ND','WB-MON','WB-EXPAK','ISO-IP','VMTP','SECURE-VMTP','VINES','TTP/IPTM','NSFNET-IGP',
'DGP','TCF','EIGRP','OSPFIGP','Sprite-RPC','LARP','MTP','AX.25','IPIP','MICP (deprecated)','SCC-SP',
'ETHERIP','ENCAP','','GMTP','IFMP','PNNI','PIM','ARIS','SCPS','QNX','A/N','IPComp','SNP','Compaq-Peer',
'IPX-in-IP','VRRP','PGM','','L2TP','DDX','IATP','STP','SRP','UTI','SMP','SM (deprecated)','PTP',
'ISIS over IPv4','FIRE','CRTP','CRUDP','SSCOPMCE','IPLT','SPS','PIPE','SCTP','FC','RSVP-E2E-IGNORE',
'Mobility Header','UDPLite','MPLS-in-IP','manet','HIP','Shim6','WESP','ROHC')

#
# Function: protLookup
#
def protLookup(prot):
    """
    Lookup transport layer protocol name using IP protocol number
    Input:  IP protocol number
    Output: Transport layer protocol name (string)
    """
    return protoData[prot]

#
# Function: protoLookup
#
def protoLookup(prot):
    """
    Lookup transport layer protocol name using IP protocol number
    Input:  IP protocol number
    Output: Transport layer protocol name (string)
    """
    return protoData[prot]
