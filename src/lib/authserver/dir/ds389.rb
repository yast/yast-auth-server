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

require 'yast'
require 'open3'
require 'fileutils'

# DS_SETUP_LOG_PATH is the path to progress and debug log file for setting up a new directory instance.
DS_SETUP_LOG_PATH = '/root/yast2-auth-server-dir-setup.log'
# DS_SETUP_INI_PATH is the path to parameter file for setting up new directory instance.
# Place the file under root directory because there are sensitive details in it.
DS_SETUP_INI_PATH = '/root/yast2-auth-server-dir-setup.ini'

# DS389 serves utility functions for setting up a new instance of 389 directory server.
class DS389
  include Yast

  # install_pkgs installs software packages mandatory for setting up 389 directory server.
  def self.install_pkgs
    Yast.import 'Package'
    # DoInstall never fails
    Package.DoInstall(['389-ds', 'openldap2-client'].delete_if{|name| Package.Installed(name)})
  end

  # get_instance_names returns an array of directory instance names already present in the system.
  def self.get_instance_names
    return Dir['/etc/dirsrv/slapd-*'].map {|full_path| File.basename(full_path).sub('slapd-', '')}
  end

  # gen_setup_ini generates INI file content with parameters for setting up directory server.
  def self.gen_setup_ini(fqdn, instance_name, suffix, dm_dn, dm_pass)
    return "[General]
FullMachineName=#{fqdn}
SuiteSpotUserID=dirsrv
SuiteSpotGroup=dirsrv

[slapd]
ServerPort=389
ServerIdentifier=#{instance_name}
Suffix=#{suffix}
RootDN=#{dm_dn}
RootDNPwd=#{dm_pass}
AddSampleEntries=No
"
  end

  # exec_setup runs setup-ds.pl using input parameters file content.
  # The output of setup script is written into file /root/yast2-auth-server-dir-setup.log
  # Returns true only if setup was successful.
  def self.exec_setup(content)
    open(DS_SETUP_INI_PATH, 'w') {|fh| fh.puts(content)}
    _, stdouterr, result = Open3.popen2e('/usr/sbin/setup-ds.pl', '--silent', '-f', DS_SETUP_INI_PATH)
    append_to_log(stdouterr.gets)
    return result.value.exitstatus == 0
  end

  # remove_setup_ini removes the setup INI file.
  def self.remove_setup_ini
    File.delete(DS_SETUP_INI_PATH)
  end

  # append_to_log appends current time and content into log file placed under /root/.
  def self.append_to_log(content)
    open(DS_SETUP_LOG_PATH, 'a') {|fh|
      fh.puts(Time.now)
      fh.puts(content)
    }
  end

  # enable_krb_schema enables kerberos schema in the directory server and then restarts the directory server.
  # Returns true only if server restarted successfully.
  def self.enable_krb_schema(instance_name)
    ::FileUtils.copy('/usr/share/dirsrv/data/60kerberos.ldif', '/etc/dirsrv/slapd-ldapdom/schema/60kerberos.ldif')
    return self.restart(instance_name)
  end

  # restart the directory service specified by the instance name. Returns true only on success.
  def self.restart(instance_name)
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'restart', 'dirsrv@'+instance_name)
    return result.value.exitstatus == 0
  end

  # install_tls_in_nss copies the specified CA and pkcs12 certificate+key into NSS database of 389 instance.
  def self.install_tls_in_nss(instance_name, ca_path, p12_path)
    instance_dir = '/etc/dirsrv/slapd-' + instance_name
    # Put CA certificate into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/certutil', '-A', '-d', instance_dir, '-n', 'ca_cert', '-t', 'C,,', '-i', ca_path)
    append_to_log(stdouterr.gets)
    if result.value.exitstatus != 0
      return false
    end
    # Put TLS certificate and key into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/pk12util', '-d', instance_dir, '-W', '', '-K', '', '-i', p12_path)
    append_to_log(stdouterr.gets)
    if result.value.exitstatus != 0
      return false
    end
    return true
  end

  # get_enable_tls_ldif returns LDIF data that can be
  def self.get_enable_tls_ldif
    return 'dn: cn=encryption,cn=config
changetype: modify
replace: nsSSL3
nsSSL3: off
-
replace: nsSSLClientAuth
nsSSLClientAuth: allowed
-
add: nsSSL3Ciphers
nsSSL3Ciphers: +all

dn: cn=config
changetype: modify
add: nsslapd-security
nsslapd-security: on
-
replace: nsslapd-ssl-check-hostname
nsslapd-ssl-check-hostname: off

dn: cn=RSA,cn=encryption,cn=config
changetype: add
objectclass: top
objectclass: nsEncryptionModule
cn: RSA
nsSSLPersonalitySSL: Server-Cert
nsSSLToken: internal (software)
nsSSLActivation: on'
  end
end