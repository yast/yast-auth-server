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

require 'open3'

# LDAPClient serves utility functions for using LDAP command line client to interact with 389 directory server.
class LDAPClient
  # Initialise a client with specified connectivity details.
  def initialize(url, bind_dn, bind_pw)
    @url = url
    @bind_dn = bind_dn
    @bind_pw = bind_pw
  end

  # modify invokes ldapmodify and returns tuple of command output and boolean (success or not).
  def modify(ldif_input, ignore_existing)
    stdin, stdouterr, result = Open3.popen2e('/usr/bin/ldapmodify', '-H', @url, '-x', '-D', @bind_dn, '-w', @bind_pw)
    stdin.puts(ldif_input)
    stdin.close
    # Error code 20 means an attribute being added already exists
    return [stdouterr.gets, result.value.exitstatus == 0 || ignore_existing && result.value.exitstatus == 20]
  end

  # add invokes ldapadd and returns tuple of command output and boolean (success or not).
  def add(ldif_input, ignore_existing)
    stdin, stdouterr, result = Open3.popen2e('/usr/bin/ldapadd', '-H', @url, '-x', '-D', @bind_dn, '-w', @bind_pw)
    stdin.puts(ldif_input)
    stdin.close
    # Error code 68 means an entry already exists
    return [stdouterr.gets, result.value.exitstatus == 0 || ignore_existing && result.value.exitstatus == 68]
  end

  # create_person invokes ldapadd to create LDAP user of "person" class.
  # Most directory servers require LDAPS or StartTLS for this operation.
  # Returns tuple of command output and boolean (success or not).
  def create_person(dn_prefix, cnsn, suffix)
    return self.add("dn: #{dn_prefix},#{suffix}
objectClass: person
objectClass: top
sn: #{cnsn}", true)
  end

  # change_password changes user password for a directory object.
  # Most directory servers require LDAPS or StartTLS for this operation.
  # Returns tuple of command output and boolean (success or not).
  def change_password(dn, new_pass)
    stdin, stdouterr, result = Open3.popen2e('/usr/bin/ldappasswd', '-H', @url, '-x', '-D', @bind_dn, '-w', @bind_pw, '-s', new_pass, dn)
    stdin.close
    return [stdouterr.gets, result.value.exitstatus == 0]
  end

  # aci_allow_modify adds an ACI rule that allows user to modify a tree.
  # Returns tuple of command output and boolean (success or not).
  def aci_allow_modify(dn, rule_nickname, user_dn)
    return self.modify("dn: #{dn}
changetype: modify
add: aci
aci: (target=\"ldap:///#{dn}\")(targetattr=*)
     (version 3.0; acl \"#{rule_nickname}\"; allow (all)
     userdn = \"ldap:///#{user_dn}\";)", true)
  end
end