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

# KDC_SETUP_LOG_PATH is the path to progress and debug log file for setting up a new KDC.
KDC_SETUP_LOG_PATH = '/root/yast2-auth-server-kdc-setup.log'

# MITKerberos serves utility functions for setting up a new directory connected KDC.
class MITKerberos
  include Yast

  # install_pkgs installs software packages mandatory for setting up MIT Kerberos server.
  def self.install_pkgs
    Yast.import 'Package'
    # DoInstall never fails
    Package.DoInstall(['krb5-client', 'krb5-server', 'krb5-plugin-kdb-ldap'].delete_if{|name| Package.Installed(name)})
  end

  # is_configured returns true only if there kerberos configuration has been altered.
  def self.is_configured
    # If manual changes were made in config files, RPM verification will see them.
    _, _, result = Open3.popen2e('rpm', '-V', 'krb5-server')
    return result.value.exitstatus == 0
  end

  # gen_client_conf generates /etc/krb5.conf content for setting up a new KDC.
  def self.gen_common_conf(realm_name, fqdn)
    return "[libdefaults]
        # \"dns_canonicalize_hostname\" and \"rdns\" are better set to false for improved security.
        # If set to true, the canonicalization mechanism performed by Kerberos client may
        # allow service impersonification, the consequence is similar to conducting TLS certificate
        # verification without checking host name.
        # If left unspecified, the two parameters will have default value true, which is less secure.
        dns_canonicalize_hostname = false
        rdns = false
        default_realm = #{realm_name}

[realms]
        #{realm_name} = {
                kdc = #{fqdn}
                admin_server = #{fqdn}
        }

[domain_realm]
        .#{realm_name.downcase} = #{realm_name}
    #{realm_name.downcase} = #{realm_name}

[logging]
    kdc = FILE:/var/log/krb5/krb5kdc.log
    admin_server = FILE:/var/log/krb5/kadmind.log
    default = SYSLOG:NOTICE:DAEMON
"
  end

  # gen_kdc_conf generates /var/lib/kerberos/krb5kdc/kdc.conf content for setting up a new KDC.
  def self.gen_kdc_conf(realm_name, kdc_dn, admin_dn, container_dn, pass_file_path, ldaps_addr)
    return "[kdcdefaults]
        kdc_ports = 750,88

[realms]
        #{realm_name} = {
                database_module = contact_ldap
        }

[dbdefaults]

[dbmodules]
        contact_ldap = {
                db_library = kldap
                ldap_kdc_dn = \"#{kdc_dn}\"
                ldap_kadmind_dn = \"#{admin_dn}\"
                ldap_kerberos_container_dn = \"#{container_dn}\"
                ldap_service_password_file = #{pass_file_path}
                ldap_servers = ldaps://#{ldaps_addr}
        }

[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
"
  end

  # save_password_into_file saves a password into a password stash file for KDC to consume.
  # Returns tuple of command output and boolean (success or not).
  def self.save_password_into_file(dn, pass, file_path)
    stdin, stdouterr, result = Open3.popen2e('/usr/lib/mit/sbin/kdb5_ldap_util', 'stashsrvpw', '-f', file_path, '-w', pass, dn)
    # The utility asks for password input and repeat to verify
    stdin.puts(pass)
    stdin.puts(pass)
    stdin.close
    succeeded = result.value.exitstatus == 0
    if !succeeded
      return [stdouterr.readlines.join('\n'), false]
    end
    File.chmod(0600, file_path)
    return [stdouterr.readlines.join('\n'), true]
  end

  # init_dir uses kerberos LDAP utility to prepare a directory server for kerberos operation.
  # Returns tuple of command output and boolean (success or not).
  def self.init_dir(ldaps_addr, dir_admin_dn, dir_admin_pass, realm_name, container_dn, master_pass)
    #puts ['/usr/lib/mit/sbin/kdb5_ldap_util', '-H', 'ldaps://'+ldaps_addr, '-D', dir_admin_dn, '-w', dir_admin_pass, 'create', '-r', realm_name, '-subtrees', container_dn, '-s', '-P', master_pass].join(' ')
    stdin, stdouterr, result = Open3.popen2e('/usr/lib/mit/sbin/kdb5_ldap_util', '-H', 'ldaps://'+ldaps_addr, '-D', dir_admin_dn, '-w', dir_admin_pass, 'create', '-r', realm_name, '-subtrees', container_dn, '-s', '-P', master_pass)
    stdin.close
    return [stdouterr.readlines.join('\n'), result.value.exitstatus == 0]
  end

  # restart_kdc restarts KDC system service. Returns true only on success.
  def self.restart_kdc
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'restart', 'krb5kdc')
    return result.value.exitstatus == 0
  end

  # restart_kadmind restarts kerberos administration service. Returns true only on success.
  def self.restart_kadmind
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'restart', 'kadmind')
    return result.value.exitstatus == 0
  end

  # enable KDC system service. Returns true only on success.
  def self.enable_kdc
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'enable', 'krb5kdc')
    return result.value.exitstatus == 0
  end

  # enable kerberos administration service. Returns true only on success.
  def self.enable_kadmind
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'enable', 'kadmind')
    return result.value.exitstatus == 0
  end

  # append_to_log appends current time and content into log file placed under /root/.
  def self.append_to_log(content)
    open(KDC_SETUP_LOG_PATH, 'a') {|fh|
      fh.puts(Time.now)
      fh.puts(content)
    }
  end
end
