#!/usr/bin/env rspec
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE LINUX GmbH.

# Authors:      Howard Guo <hguo@suse.com>

ENV['Y2DIR'] = File.expand_path('../../src', __FILE__)

require 'yast'
require 'yast/rspec'
require 'pp'
require 'authserver/krb/mit'

describe MITKerberos do
  it 'gen_common_conf' do
    match = '[libdefaults]
        # "dns_canonicalize_hostname" and "rdns" are better set to false for improved security.
        # If set to true, the canonicalization mechanism performed by Kerberos client may
        # allow service impersonification, the consequence is similar to conducting TLS certificate
        # verification without checking host name.
        # If left unspecified, the two parameters will have default value true, which is less secure.
        dns_canonicalize_hostname = false
        rdns = false
        default_realm = EXAMPLE.COM

[realms]
        EXAMPLE.COM = {
                kdc = krb.example.com
                admin_server = krb.example.com
        }

[domain_realm]
        .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM

[logging]
    kdc = FILE:/var/log/krb5/krb5kdc.log
    admin_server = FILE:/var/log/krb5/kadmind.log
    default = SYSLOG:NOTICE:DAEMON
'
    expect(MITKerberos.gen_common_conf('EXAMPLE.COM', 'krb.example.com')).to eq(match)
  end

  it 'gen_kdc_comf' do
    match = '[kdcdefaults]
        kdc_ports = 750,88

[realms]
        EXAMPLE.COM = {
                database_module = contact_ldap
        }

[dbdefaults]

[dbmodules]
        contact_ldap = {
                db_library = kldap
                ldap_kdc_dn = "cn=kdc"
                ldap_kadmind_dn = "cn=adm"
                ldap_kerberos_container_dn = "cn=container"
                ldap_service_password_file = /pass
                ldap_servers = ldaps://dir.example.net
        }

[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
'
    expect(MITKerberos.gen_kdc_conf('EXAMPLE.COM', 'cn=kdc', 'cn=adm', 'cn=container', '/pass', 'dir.example.net')).to eq(match)
  end
end