#!/usr/bin/python2.7
from BeautifulSoup import BeautifulStoneSoup
from subprocess import call
import argparse
import re, base64
 
parser = argparse.ArgumentParser(description='Recupere le nom de l\'export')
parser.add_argument('-f', '--file', help='export_rweb', required=True)
args = parser.parse_args()
 
call(['tar', 'xzf', args.file])
f = open('xml')
xml = f.read()
soup = BeautifulStoneSoup(xml)
apps = soup.find('daws:table', {'name': 'applications'})
policies = soup.find('daws:table', {'name': 'policies'})
services = soup.find('daws:table', {'name': 'services'})
vhosts = soup.find('daws:table', {'name': 'vhosts'})
secuProfiles = soup.find('daws:table', {'name': 'security_profiles'})
httpProfiles = soup.find('daws:table', {'name': 'http_profiles'})
blacklists = soup.find('daws:table', {'name': 'blacklists'})
instances = soup.find('daws:table', {'name': 'instances'})
certificates = soup.find('daws:table', {'name': 'ssl_certificates'})
files = soup.find('daws:certs')
 
listeApps = []
listeSecuProfiles = []
listeHttpProfiles = []
listeBlacklists = []
 
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
for k in apps.find('daws:schema'):
    keys.append(k.text)
 
for a in apps.findAll('daws:row'):
    listeApps.append(dict(zip(keys, a)))
 

# RECUPERATION DES POLICIES
# policy_id
# name
# url
# alias
# vhost_id
# acceleration_profile_id
# authentication_profile_id
# security_profile_id
# outgoing_url
# out_service_id
# pooling_out_service_id
# pt_outgoing_service_id
# auto_down_if
# type
# proxy_authentication
# proxy_option
# proxy_ssl_ciphers
# proxy_ssl_protocols
# proxy_preserve_host
# proxy_forward_ntlm
# sync_crypto_app_id
# backend_address
# backend_port
# incoming_address
# incoming_interface
# outgoing_address
# outgoing_interface
# use_global_log_settings
# traffic_recording
# full_traffic_recording
# errors_log_level
# log_rotate_max_age
# log_rotate_max_size
# custom_blocked_page
# manual_ssl_out
def getPolicy(policy_id): 
    keys = []
    for k in policies.find('daws:schema'):
        keys.append(k.text)
 
    try:
        return dict(zip(keys, policies.find(text=re.compile(policy_id)).parent.parent))
    except:
        return None
 
 
# RECUPERATION DES SERVICES
# service_id
# address
# port
def getService(service_id): 
    keys = []
    for k in services.find('daws:schema'):
        keys.append(k.text)
 
    try:
        return  dict(zip(keys, services.find(text=re.compile(service_id)).parent.parent))
    except:
        return None
 
 
# RECUPERATION DES VHOSTS
# vhost_id
# instance_id
# host
# cert_id
# default_vhost
def getVhost(vhost_id): 
    keys = []
    for k in vhosts.find('daws:schema'):
        keys.append(k.text)

    try:
        return dict(zip(keys, vhosts.find(text=re.compile(vhost_id)).parent.parent))
    except:
        return None

 
# RECUPERATION DES SECURITY PROFILES
# profile_id
# name
# description
# newer_version
# xml_profile_id
# http_profile_id
 
keys = []
for k in secuProfiles.find('daws:schema'):
        keys.append(k.text)
 
for a in secuProfiles.findAll('daws:row'):
    listeSecuProfiles.append(dict(zip(keys, a)))
 
 
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
for k in httpProfiles.find('daws:schema'):
    keys.append(k.text)
 
for a in httpProfiles.findAll('daws:row'):
    listeHttpProfiles.append(dict(zip(keys, a)))
 

# RECUPERATION DES BLACKLISTS
# id
# name
# type
# description
# static_file_id
# dynamic_file_id
keys = []
for k in blacklists.find('daws:schema'):
        keys.append(k.text)
 
for a in blacklists.findAll('daws:row'):
    listeBlacklists.append(dict(zip(keys, a)))
 
 
# RECUPERATION DES INSTANCES
# instance_id
# service_id
# incoming
# polling_service_id
# pt_incoming_service_id
# polling_timeout
# pending_config_id
# running_config_id
# status
def getInstance(instance_id): 
    keys = []
    for k in instances.find('daws:schema'):
        keys.append(k.text)
 
    try:
        return  dict(zip(keys, instances.find(text=re.compile(instance_id)).parent.parent))
    except:
        return None


# RECUPERATION DES CERTIFICATS
# certificate_id
# name
# description
# generation_date
# expiration_date
# CSR_file
# CERT_file
# CHAIN_file
# private_key_file
def getCertificate(certificate_id): 
    keys = []
    for k in certificates.find('daws:schema'):
        keys.append(k.text)
 
    try:
        return  dict(zip(keys, certificates.find(text=re.compile(certificate_id)).parent.parent))
    except:
        return None


# RECUPERATION DES FICHIERS (CERTIFICATS & CO.)
# name
# type
def getFile(file_id):
    try:
        return base64.b64decode(files.find("file", {'name': file_id}).text.replace('\'', ''))
    except:
        return None


for a in listeApps:
    app = {}
    vhost = ''
    instance = ''
    service = ''
    app['id'] =  a['application_id'].text.replace('\'', '')
    app['name'] = a['name'].text.replace('\'', '')
    policy = getPolicy(a['running_policy_id'].text)
    if policy:
        vhost = getVhost(policy['vhost_id'].text)
    if vhost:
        instance = getInstance(vhost['instance_id'].text)
        certificate = getCertificate(vhost['cert_id'].text)
        app['servername'] = vhost['host'].text.replace('\'', '')
    if instance:
        service = getService(instance['service_id'].text)
    if certificate:
        app['private_key'] = getFile(certificate['private_key_file'].text.replace('\'', ''))
        app['chain'] = getFile(certificate['CHAIN_file'].text.replace('\'', ''))
        app['cert'] = getFile(certificate['CERT_file'].text.replace('\'', ''))
    if policy:
        app['proxypass'] = policy['outgoing_url'].text.replace('\'', '')
    if service:
        app['ip'] = service['address'].text.replace('\'', '')
        app['port'] = service['port'].text.replace('\'', '')
    print '#'*80
    print 'Name        :', app['name']
    print 'ServerName  :', app['servername']
    print 'ProxyPass   :', app['proxypass']
    print 'Listen on   :', app['ip'] + ':' + app['port']
    print 'Certificat  :\n', app['cert']
    print 'Private Key :\n', app['private_key']
    print 'Chain       :\n', app['chain']
    print '#'*80

 
#for a in listeApps:
#    print '#'*80
#    print 'App ID        :', a['application_id'].text
#    print 'App Name      :', a['name'].text
#    print 'App Policy ID :', a['running_policy_id'].text
#    print 'App Status    :', a['status'].text
#    print '#'*80
# 
#for a in listePolicies:
#    print '#'*80
#    print 'Policy ID           :', a['policy_id'].text
#    print 'Security Profile ID :', a['security_profile_id'].text
#    print 'Service ID          :', a['out_service_id'].text
#    print 'VHost ID          :', a['vhost_id'].text
#    print 'ProxyPass           :', a['outgoing_url'].text
#    print '#'*80
# 
#for a in listeServices:
#    print '#'*80
#    print 'Service ID :', a['service_id'].text
#    print 'IP:Port    :', a['address'].text + ':' + a['port'].text
#    print '#'*80
# 
#for a in listeVhosts:
#    print '#'*80
#    print 'Vhost ID       :', a['vhost_id'].text
#    print 'Host           :', a['host'].text
#    print 'Instance ID    :', a['instance_id'].text
#    print 'Cert ID        :', a['cert_id'].text
#    print '#'*80
#
#for a in listeSecuProfiles:
#    print '#'*80
#    print 'Secu Profile ID    :', a['profile_id'].text
#    print 'Http Profile ID    :', a['http_profile_id'].text
#    print '#'*80
#
#for a in listeHttpProfiles:
#    print '#'*80
#    print 'Http Profile ID    :', a['profile_id'].text
#    print 'Blacklist ID       :', a['blacklist_id'].text
#    print 'Whitelist ID       :', a['whitelist_id'].text
#    print '#'*80
#
#for a in listeBlacklists:
#    print '#'*80
#    print 'Blacklist ID    :', a['id'].text
#    print 'Name            :', a['name'].text
#    print '#'*80
#
#for a in listeInstances:
#    print '#'*80
#    print 'Instance ID    :', a['instance_id'].text
#    print 'Service ID            :', a['service_id'].text
#    print '#'*80

