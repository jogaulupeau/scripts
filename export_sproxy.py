#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# 
##############################################################################
#
# export_sproxy.py
#
##############################################################################
#
# Ce script permet de recuperer quelques informations importantes a partir 
# d'un export XML de la configuration de sProxy ou rWeb 4.1
# 
##############################################################################
# 
# Auteur        : Jonathan GAULUPEAU
# Version       : 0.1
# Date          : 11/05/2013
#
##############################################################################
#
# Ce script est diffuséous la licence EUPL v1.1
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

from BeautifulSoup import BeautifulStoneSoup
from subprocess import call
import argparse
import re, base64
 

class ReadConfsProxy:
    def __init__(self, export_file):
        self.listeApps = []
        self.listeSecuProfiles = []
        self.listeHttpProfiles = []
        self.listeBlacklists = []
        self.apps = None
        self.policies = None
        self.services = None
        self.vhosts = None
        self.secuProfiles = None
        self.httpProfiles = None
        self.blacklists = None
        self.instances = None
        self.certificates = None
        self.files = None

        self.parseConf(export_file)

     
    def getPolicy(self, policy_id): 
        '''RECUPERATION D'UNE POLICY PAR SON ID
        policy_id
        name
        url
        alias
        vhost_id
        acceleration_profile_id
        authentication_profile_id
        security_profile_id
        outgoing_url
        out_service_id
        pooling_out_service_id
        pt_outgoing_service_id
        auto_down_if
        type
        proxy_authentication
        proxy_option
        proxy_ssl_ciphers
        proxy_ssl_protocols
        proxy_preserve_host
        proxy_forward_ntlm
        sync_crypto_app_id
        backend_address
        backend_port
        incoming_address
        incoming_interface
        outgoing_address
        outgoing_interface
        use_global_log_settings
        traffic_recording
        full_traffic_recording
        errors_log_level
        log_rotate_max_age
        log_rotate_max_size
        custom_blocked_page
        manual_ssl_out'''
        keys = []
        for k in self.policies.find('daws:schema'):
            keys.append(k.text)
     
        try:
            return dict(zip(keys, self.policies.find(text=re.compile(policy_id)).parent.parent))
        except:
            return None


    def getService(self, service_id): 
        '''RECUPERATION D'UN SERVICE PAR SON ID
        service_id
        address
        port'''
        keys = []
        for k in self.services.find('daws:schema'):
            keys.append(k.text)
     
        try:
            return  dict(zip(keys, self.services.find(text=re.compile(service_id)).parent.parent))
        except:
            return None
     
     
    def getVhost(self, vhost_id): 
        '''RECUPERATION D'UN VHOST PAR SON ID
        vhost_id
        instance_id
        host
        cert_id
        default_vhost'''
        keys = []
        for k in self.vhosts.find('daws:schema'):
            keys.append(k.text)

        try:
            return dict(zip(keys, self.vhosts.find(text=re.compile(vhost_id)).parent.parent))
        except:
            return None


    def getInstance(self, instance_id): 
        '''RECUPERATION D'UNE INSTANCE PAR SON ID
        instance_id
        service_id
        incoming
        polling_service_id
        pt_incoming_service_id
        polling_timeout
        pending_config_id
        running_config_id
        status'''
        keys = []
        for k in self.instances.find('daws:schema'):
            keys.append(k.text)
     
        try:
            return  dict(zip(keys, self.instances.find(text=re.compile(instance_id)).parent.parent))
        except:
            return None


    def getCertificate(self, certificate_id): 
        '''RECUPERATION DES CERTIFICATS
        certificate_id
        name
        description
        generation_date
        expiration_date
        CSR_file
        CERT_file
        CHAIN_file
        private_key_file'''
        keys = []
        for k in self.certificates.find('daws:schema'):
            keys.append(k.text)
     
        try:
            return  dict(zip(keys, self.certificates.find(text=re.compile(certificate_id)).parent.parent))
        except:
            return None


    def getFile(self, file_id):
        '''RECUPERATION D'UN FICHIER PAR SON ID (CERTIFICATS & CO.)
        name
        type'''
        try:
            return base64.b64decode(self.files.find("file", {'name': file_id}).text.replace('\'', ''))
        except:
            return None


    def parseConf(self, xmlFile):
        call(['tar', 'xzf', xmlFile])
        f = open('xml')
        xml = f.read()
        soup = BeautifulStoneSoup(xml)
        self.apps = soup.find('daws:table', {'name': 'applications'})
        self.policies = soup.find('daws:table', {'name': 'policies'})
        self.services = soup.find('daws:table', {'name': 'services'})
        self.vhosts = soup.find('daws:table', {'name': 'vhosts'})
        self.secuProfiles = soup.find('daws:table', {'name': 'security_profiles'})
        self.httpProfiles = soup.find('daws:table', {'name': 'http_profiles'})
        self.blacklists = soup.find('daws:table', {'name': 'blacklists'})
        self.instances = soup.find('daws:table', {'name': 'instances'})
        self.certificates = soup.find('daws:table', {'name': 'ssl_certificates'})
        self.files = soup.find('daws:certs')
         
         
        # RECUPERATION DES APPLICATIONS
        # application_id
        # name
        # description
        # email
        # security_mode
        # running_policy_id
        # pending_policy_id
        # backup_policy_id
        # status
        # last_start
        # salt
        # password
         
        keys = []
        for k in self.apps.find('daws:schema'):
            keys.append(k.text)
         
        for a in self.apps.findAll('daws:row'):
            self.listeApps.append(dict(zip(keys, a)))
         
         

         
        # RECUPERATION DES SECURITY PROFILES
        # profile_id
        # name
        # description
        # newer_version
        # xml_profile_id
        # http_profile_id
         
        keys = []
        for k in self.secuProfiles.find('daws:schema'):
                keys.append(k.text)
         
        for a in self.secuProfiles.findAll('daws:row'):
            self.listeSecuProfiles.append(dict(zip(keys, a)))
         
         
        # RECUPERATION DES HTTP PROFILES
        # profile_id
        # name
        # description
        # newer_version
        # buffer_size
        # dynamic_size
        # block_when_truncated
        # check_uri_encoding
        # http_form_translation
        # http_json_translation
        # uc_decode_hh
        # uc_decode_uHHHH
        # uc_decode_xHH
        # uc_decode_html
        # uc_remove_path
        # uc_convert_cr_lf
        # pc_decode_hh
        # pc_decode_uHHHH
        # pc_decode_xHH
        # pc_decode_html
        # pc_remove_path
        # pc_convert_cr_lf
        # pc_decode_trim
        # hc_decode_hh
        # hc_decode_uHHHH
        # hc_decode_xHH
        # hc_decode_html
        # hc_convert_cr_lf
        # hc_decode_trim
        # allowed_methods
        # header_name_size
        # header_value_size
        # limit_body_size
        # limit_fields
        # limit_field_size
        # limit_lines
        # discard_comments
        # custom_error_code
        # disable_backend_compression
        # links_tracking_entry_point
        # links_tracking_match
        # links_tracking_exception
        # parameter_tracking_form_action
        # parameter_tracking_match
        # parameter_tracking_level
        # cookie_tracking_match
        # cookie_tracking_name_exception
        # cookie_tracking_block
        # cookie_tracking_encrypt
        # http_only
        # blacklist_id
        # warn_for_new_bl_rules
        # use_precomputed_regex_patterns
        # whitelist_id
        # scoring_list_id
        # command_injection
        # command_injection_dynamic
        # http_flood_occurences
        # http_flood_period
        # http_flood_action
        # http_flood_blacklist
        # site_crawling_occurences
        # site_crawling_period
        # site_crawling_action
        # site_crawling_blacklist
        # brute_force_occurences
        # brute_force_period
        # brute_force_action
        # brute_force_blacklist
        # restricted_access_action
        # restricted_access_blacklist
        # direct_access_action
        # direct_access_blacklist
        # cookie_theft_action
        # cookie_theft_blacklist
        # slowdown_delay_initial
        # slowdown_delay_increase
        # slowdown_delay_max
        # ubt_response_code
        # redirect_uri
        # detour_url
        # bl_slowdown_delay_initial
        # bl_slowdown_delay_increase
        # bl_slowdown_delay_max
        # activate_filtering_logs
        # validate_json
        # ubt_sec_filter_blacklists
        # ubt_flood_threshold
        # flood_protect_no_ext
        # crawl_protect_no_ext
        # hpp_separator
        # hc_decode_base64
        # scoring_list_protect_request_headers
        # response_splitting
        # response_splitting_use_request_headers
        # response_splitting_aggressive_mode
        # response_splitting_protect_request_headers
        # script_injection
        # script_injection_java
        # script_injection_php
        # script_injection_ssi
        # script_injection_javascript
        # script_injection_protect_request_headers
        # directory_traversal
        # arithmetic_calculation
        # sqlisec_activated
        # sqlisec_prefixes
        # htmlsec_activated
        # htmlsec_HTML4_block_tags_attrs
        # htmlsec_HTML4_block_std_events
        # htmlsec_HTML4_block_non_std_events
        # htmlsec_HTML5_block_tags_attrs
        # htmlsec_HTML5_block_std_events
        # backend_errors
        # backend_errors_block_500
        # backend_errors_iis
        # backend_errors_tomcat
        # backend_errors_php
        # backend_errors_oracledb
        # backend_errors_mssqlserver
        # backend_errors_mysql
        # backend_errors_postgresql

        keys = []
        for k in self.httpProfiles.find('daws:schema'):
            keys.append(k.text)
         
        for a in self.httpProfiles.findAll('daws:row'):
            self.listeHttpProfiles.append(dict(zip(keys, a)))
         

        # RECUPERATION DES BLACKLISTS
        # id
        # name
        # type
        # description
        # static_file_id
        # dynamic_file_id
        keys = []
        for k in self.blacklists.find('daws:schema'):
                keys.append(k.text)
         
        for a in self.blacklists.findAll('daws:row'):
            self.listeBlacklists.append(dict(zip(keys, a)))
 
 


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recupere le nom de l\'export')
    parser.add_argument('-f', '--file', help='export_rweb', required=True)
    args = parser.parse_args()
    conf = ReadConfsProxy(args.file)
    for a in conf.listeApps:
        app = {}
        vhost = ''
        instance = ''
        service = ''
        app['id'] =  a['application_id'].text.replace('\'', '')
        app['name'] = a['name'].text.replace('\'', '')
        app['policy_id'] = a['running_policy_id'].text.replace('\'', '')
        policy = conf.getPolicy(a['running_policy_id'].text)
        if policy:
            vhost = conf.getVhost(policy['vhost_id'].text)
            app['vhost_id'] = policy['vhost_id'].text.replace('\'', '')
        if vhost:
            instance = conf.getInstance(vhost['instance_id'].text)
            certificate = conf.getCertificate(vhost['cert_id'].text)
            app['servername'] = vhost['host'].text.replace('\'', '')
            app['instance_id'] = vhost['instance_id'].text.replace('\'', '')
        if instance:
            service = conf.getService(instance['service_id'].text)
            app['service_id'] = instance['service_id'].text.replace('\'', '')
        if certificate:
            app['cert_id'] = certificate['CERT_file'].text.replace('\'', '')
            app['chain_id'] = certificate['CHAIN_file'].text.replace('\'', '')
            app['private_key_id'] = certificate['private_key_file'].text.replace('\'', '')
            app['private_key'] = conf.getFile(certificate['private_key_file'].text.replace('\'', ''))
            app['chain'] = conf.getFile(certificate['CHAIN_file'].text.replace('\'', ''))
            app['cert'] = conf.getFile(certificate['CERT_file'].text.replace('\'', ''))
        if policy:
            app['proxypass'] = policy['outgoing_url'].text.replace('\'', '')
        if service:
            app['ip'] = service['address'].text.replace('\'', '')
            app['port'] = service['port'].text.replace('\'', '')
        print '#'*80
        print 'Name           :', app['name']
        print 'ServerName     :', app['servername']
        print 'ProxyPass      :', app['proxypass']
        print 'Listen on      :', app['ip'] + ':' + app['port']
        print 'Certificat     :\n', app['cert']
        print 'Private Key    :\n', app['private_key']
        print 'Chain          :\n', app['chain']
        print 'Policy ID      :', app['policy_id']
        if vhost:
            print 'VHost ID       :', app['vhost_id']
        if instance:
            print 'Instance ID    :', app['instance_id']
        if service:
            print 'Service ID     :', app['service_id']
        if certificate:
            print 'Certificat ID  :', app['cert_id']
            print 'Private Key ID :', app['private_key_id']
            print 'Chain ID       :', app['chain_id']
        print '#'*80

