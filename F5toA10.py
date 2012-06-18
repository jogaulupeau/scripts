#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
##############################################################################
#
# F5toA10.py
#
##############################################################################
#
# Ce script permet de transposer rapidement une conf F5 Big-IP en conf A10.
# Tous les paramètres ne sont pas pris en charge mais le script permet d'avoir
# une configuration de base solide.
# 
##############################################################################
# 
# Auteur        : Jonathan GAULUPEAU
# Version       : 0.1
# Date          : 13/06/2012
#
##############################################################################
#
# Ce script est diffusé sous la licence EUPL v1.1
#
# This script is released under EUPL v1.1
#
# http://ec.europa.eu/idabc/eupl
#
##############################################################################
#
# Ce programme est un logiciel libre ; vous pouvez le re-distribuer et/ou le
# modifier au titre des clauses de la European Union Public Licence (EUPL) 
# version 1.1, telle que publiée par l'Union Européenne.
#
# Ce programme est distribué dans l'espoir qu'il sera utile, 
# mais SANS AUCUNE GARANTIE ; sans même une garantie implicite de 
# COMMERCIABILITÉ ou DE CONFORMITÉ À UNE UTILISATION PARTICULIÈRE. 
# Voir la EUPL version 1.1 pour plus de détails.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the European Union Public Licence (EUPL) version 1.1 
# as published by the European Union.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the EUPL version 1.1 for more details.
#
##############################################################################

import argparse
import sys
import re

parser = argparse.ArgumentParser(description='Transformation conf F5 en A10')
parser.add_argument('-i', type=str, required=True, metavar='conf_F5.conf', help='fichier de conf F5')
parser.add_argument('-o', type=str, required=True, metavar='conf_A10.conf', help='fichier de conf A10')

args = parser.parse_args()

f = open(args.i, 'r')
f5 = f.readlines()
f.close()
a10 = open(args.o, 'w+')
confVip = []
confNode = []
confMonitor = []
listeIp = []
ports = {
        'mysql': '3306',
        'ftp': '21',
        'ssh': '22',
        'pop3': '110',
        'smtp': '25',
        'ms-sql-s': '1433',
        'ms-sql-m': '1434',
        'webcache': '8080',
        'http': '80',
        'https': '443',
        'any': '0',
        }


class Monitor():
        def __init__(self):
                self.name = ''
                self.defaults = ''
                self.interval = ''
                self.timeout = ''
                self.alias = ''
                self.alias_ip = ''
                self.alias_port = ''
                self.recv = ''
                self.send = ''
                self.host = ''
                self.toWrite = False

        def write(self):
                if len(self.timeout)>0 and len(self.interval)>0:
                        a10.write('health monitor %s timeout %s interval %s\n' %(self.name, self.timeout, self.interval))
                elif len(self.timeout)>0:
                         a10.write('health monitor %s timeout %s\n' %(self.name, self.timeout))
                elif len(self.interval)>0:
                        a10.write('health monitor %s interval %s\n' %(self.name, self.interval))
                else:
                        a10.write('health monitor %s\n' %self.name)
                if len(self.host)>0:
                       a10.write('method %s url GET "%s" expect "%s" host "%s"\n' %(self.defaults, self.send, self.recv, self.host))
                else:
                        a10.write('method %s url GET "%s" expect "%s"\n' %(self.defaults, self.send, self.recv))
                if len(self.alias)>0:
                        a10.write('override-ipv4 %s\n' %self.alias_ip)
                        a10.write('override-port %s\n' %self.alias_port)
                a10.write('!\n')
                

class Vip():
        def __init__(self):
                self.dest = ''
                self.port = ''
                self.persist = ''
                self.pool = ''
                self.name = ''
                self.rule = ''
                self.toWrite = False

        def write(self):
                a10.write('slb virtual-server %s %s\n' %(self.name, self.dest))
                if self.port == '80':
                        a10.write('\tport 80 http\n')
                else:
                        a10.write('\tport %s tcp\n' %self.port)
                if len(self.pool)>0:
                        a10.write('\t\tservice-group %s\n' %self.pool)
                a10.write('\t\tuse-rcv-hop-for-resp\n')
                if len(self.persist)>0:
                        if 'source_addr' in self.persist:
                                a10.write('\t\ttemplate persist source-ip %s\n' %self.persist)
                        else:
                                a10.write('\t\ttemplate persist cookie %s\n' %self.persist)
                if len(self.rule)>0:
                        a10.write('\t\taflex %s\n' %self.rule)
                a10.write('!\n')
                

class Pool():
        def __init__(self):
                self.name = ''
                self.members = []
                self.toWrite = False
                self.monitor = ''
                self.method = ''
        
        def write(self):
                a10.write('slb service-group %s tcp\n' %self.name)
                if self.method:
                        a10.write('\tmethod %s\n' %self.method)
                if self.monitor:
                        a10.write('\thealth-check %s\n' %self.monitor)
                for m in self.members:
                        a10.write('\tmember %s:%s' %(m.ip, m.port))
                        if m.disable:
                                a10.write(' disable')
                        if len(m.priority) > 0:
                                a10.write(' priority %s' % m.priority)
                        a10.write('\n')
                a10.write('!\n')


class Node():
        def __init__(self):
                self.ip = ''
                self.port = ''
                self.disable = False
                self.priority = ''
        
        def write(self):
                a10.write('slb server %s %s\n' %(self.ip, self.ip))
                a10.write('\tport %s tcp\n' %self.port)
                a10.write('!\n')


def readMonitorConf():
        m = Monitor()
        for l in f5:
                if l.startswith('monitor'):
                        m.name = l.split()[1]
                        m.toWrite = True
                if l.lstrip().startswith('defaults from'):
                        m.defaults = l.split()[2]
                if l.lstrip().startswith('interval'):
                        m.interval = l.split()[1]
                if l.lstrip().startswith('timeout'):
                        m.timeout = l.split()[1]
                if l.lstrip().startswith('dest'):
                        try:
                                m.alias = l.split()[1]
                                m.alias_ip = m.alias.split(':')[0]
                                m.alias_port = m.alias.split(':')[1]
                        except:
                                m.toWrite = False
                                print >> sys.stderr, 'Monitor non standard : %s, non pris en compte par le script' % m.name
                if l.lstrip().startswith('recv'):
                        m.recv = l.split('"')[1].replace('"', '')
                if l.lstrip().startswith('send'):
                        m.send = l.split()[2].replace('"', '')
                        if 'Host' in l:
                                try:
                                        m.host = l.split('\\n')[1].split()[1].replace('\\r', '')
                                except:
                                        m.toWrite = False
                                        print l
                if '}' in l:
                        if m.toWrite:
                                confMonitor.append(m)
                        m = Monitor()
        for m in confMonitor:
                m.write()

        
def readPoolConf():
        p = Pool()
        confPool = []
        for l in f5:
                if l.startswith('pool'):
                        p.name = l.split()[1]
                        p.toWrite = True
                        if len(p.name) > 63:
                                p.toWrite = False
                                print >> sys.stderr, 'Nom de Pool trop long : %s, non pris en compte par le script.' % p.name
                if p.toWrite:
                        if l.lstrip().startswith('member'):
                                n = Node()
                                n.ip = l.split()[1].split(':')[0]
                                n.port = l.split()[1].split(':')[1]
                                if 'disable' in l:
                                        n.disable = True
                                if 'priority' in l:
                                        n.priority = re.findall(r'priority (\d+)', l)[0]
                                if re.search('\d+', n.port):
                                        pass
                                elif ports.has_key(n.port):
                                        n.port = ports.get(n.port)
                                else:
                                        p.toWrite = False
                                        print >> sys.stderr, 'Pool non standard : %s, non prise en compte par le script.' % p.name
                                p.members.append(n)
                                confNode.append(n)
                        if l.lstrip().startswith('monitor'):
                                if ' and ' in l:
                                        p.toWrite = False
                                        print >> sys.stderr, 'Pool non standard : %s, sera pris en compte sans ses monitors.' % p.name 
                                elif l.split()[2] != 'tcp':
                                        p.monitor = l.split()[2]
                        if l.strip().startswith('lb method fastest'):
                                p.method = 'fastest-response'
                        if '}' in l:
                                if p.toWrite:
                                        confPool.append(p)
                                p = Pool()
        for n in confNode:
                n.write()
        for p in confPool:
                p.write()


def readVipConf():
        v = Vip()
        for l in f5:
                if l.startswith('virtual') and 'address' not in l:
                        v.name = l.split()[1]
                        v.toWrite = True
                        if len(v.name) > 63:
                                v.toWrite = False
                                print >> sys.stderr, 'Nom de VIP trop long : %s, non pris en compte par le script.' % v.name
                if v.toWrite:
                        if 'destination' in l:
                                v.dest = l.split()[1].split(':')[0]
                                if v.dest == 'any':
                                        v.toWrite = False
                                        print >> sys.stderr, 'Vip non standard : %s, non prise en compte par le script.' % v.name
                                v.port = l.split()[1].split(':')[1]
                                if re.search('\d+', v.port):
                                        pass
                                elif ports.has_key(v.port):
                                        v.port = ports.get(v.port)
                                else :
                                        v.toWrite = False
                                        print >> sys.stderr, 'Vip non standard : %s, non prise en compte par le script.' % v.name
                                if v.toWrite:
                                        listeIp.append(v.dest)
                        if 'persist' in l:
                                v.persist = l.split()[1]
                        if 'pool' in l:
                                v.pool = l.split()[1]
                        if 'rule' in l:
                                v.rule = l.split()[1]
                        if '}' in l:
                                confVip.append(v)
                                v = Vip()
        for v in confVip:
                if listeIp.count(v.dest) == 1:
                        v.write()
                        listeIp.remove(v.dest)
                else:
                        if v.name.find('https') > 0:
                                v.name = v.name.replace('https', 'httpx').replace('_443', '')
                        else:
                                v.name = v.name.replace('http', 'httpx')
                        v.write()
                                
                                
readMonitorConf()
readPoolConf()
readVipConf()
a10.close()
