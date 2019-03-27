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
# 		William Brown <wbrown@suse.de>

require 'yast'
require 'open3'
require 'fileutils'

# DS_SETUP_INI_PATH is the path to parameter file for setting up new directory instance.
# Place the file under root directory because there are sensitive details in it.
DS_SETUP_INI_PATH = '/root/yast2-auth-server-dir-setup.ini'

# DS389 serves utility functions for setting up a new instance of 389 directory server.
class DS389
  include Yast
  include Yast::Logger

  # install_pkgs installs software packages mandatory for setting up 389 directory server.
  def self.install_pkgs
    Yast.import 'Package'
    # DoInstall never fails
    Package.DoInstall(['389-ds', 'openldap2-client'].delete_if {|name| Package.Installed(name)})
  end

  # get_instance_names returns an array of directory instance names already present in the system.
  def self.get_instance_names
    return Dir['/etc/dirsrv/slapd-*'].map {|full_path| File.basename(full_path).sub('slapd-', '')}
  end

  # gen_setup_ini generates INI file content with parameters for setting up directory server.
  def self.gen_setup_ini(fqdn, instance_name, suffix, dm_pass)
    return "# Generated by yast-auth-server
[general]
config_version = 2
full_machine_name = #{fqdn}
# This may be need to be tweaked, it could break setups ...
# strict_host_checking = true/false

[slapd]
root_password = #{dm_pass}
instance_name = #{instance_name}

[backend-userroot]
sample_entries = yes
suffix = #{suffix}
"
  end

  # exec_setup runs setup-ds.pl using input parameters file content.
  # The output of setup script is written into file .y2log or /var/log/YaST/y2log
  # Returns true only if setup was successful.
  def self.exec_setup(content)
    append_to_log('Beginning YAST auth server installation ...')

    open(DS_SETUP_INI_PATH, 'w') {|fh| fh.puts(content)}
    # dry run first to see if it breaks ...
    stdin, stdouterr, result = Open3.popen2e('/usr/sbin/dscreate', '-v', 'from-file', '-n', DS_SETUP_INI_PATH)
    stdouterr.readlines.map { |l| append_to_log(l) }

    if result.value.exitstatus != 0
        return false
    end

    # Right do the real thing.
    stdin, stdouterr, result = Open3.popen2e('/usr/sbin/dscreate', '-v', 'from-file', DS_SETUP_INI_PATH)
    stdouterr.readlines.map { |l| append_to_log(l) }
    stdin.close
    return result.value.exitstatus == 0
  end

  # remove_setup_ini removes the setup INI file.
  def self.remove_setup_ini
    File.delete(DS_SETUP_INI_PATH)
  end

  # append_to_log appends current time and content into log file placed under /root/.
  def self.append_to_log(content)
    log.debug(content)
  end

  # restart the directory service specified by the instance name. Returns true only on success.
  def self.restart(instance_name)
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'restart', 'dirsrv@' + instance_name)
    return result.value.exitstatus == 0
  end

  # install_tls_in_nss copies the specified CA and pkcs12 certificate+key into NSS database of 389 instance.
  def self.install_tls_in_nss(instance_name, ca_path, p12_path)
	  # #We may need to clear content from the NSS DB first ... as 389 adds ssca
    instance_dir = '/etc/dirsrv/slapd-' + instance_name
    # Put CA certificate into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/certutil', '-A', '-d', instance_dir, '-n', 'ca_cert', '-t', 'C,,', '-i', ca_path)
    stdouterr.readlines.map { |l| append_to_log(l) }
    if result.value.exitstatus != 0
      return false
    end
    # Put TLS certificate and key into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/pk12util', '-d', instance_dir, '-W', '', '-K', '', '-i', p12_path)
    stdouterr.readlines.map { |l| append_to_log(l) }
    if result.value.exitstatus != 0
      return false
    end
    return true
  end

end
