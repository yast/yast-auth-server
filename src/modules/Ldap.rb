# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2006-2012 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------

# File:	modules/Ldap.ycp
# Module:	Configuration of LDAP client
# Summary:	LDAP client configuration data, I/O functions.
# Authors:	Thorsten Kukuk <kukuk@suse.de>
#		Anas Nashif <nashif@suse.de>
#
# $Id$
require "yast"
require "uri"

module Yast
  class LdapClass < Module
    def main
      Yast.import "UI"
      textdomain "ldap-client"

      Yast.import "Autologin"
      Yast.import "Directory"
      Yast.import "FileUtils"
      Yast.import "DNS"
      Yast.import "Hostname"
      Yast.import "Label"
      Yast.import "Message"
      Yast.import "Mode"
      Yast.import "Nsswitch"
      Yast.import "Package"
      Yast.import "Pam"
      Yast.import "Popup"
      Yast.import "ProductFeatures"
      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Service"
      Yast.import "Stage"
      Yast.import "String"
      Yast.import "Summary"
      Yast.import "URL"

      # show popups with error messages?
      @use_gui = true

      # DN of base configuration object
      @base_config_dn = ""


      Yast.include self, "ldap/routines.rb"

      # Required packages for this module to operate
      # -- they are now required only when LDAP is set for authentication
      @required_packages = []

      # Write only, used during autoinstallation.
      # Don't run services and SuSEconfig, it's all done at one place.
      @write_only = false

      # Are LDAP services available via nsswitch.conf?
      @start = false
      @old_start = false

      # Is NIS service available? If yes, and LDAP client will be enabled, warn
      # user (see bug #36981)
      @nis_available = false

      # If no, automounter will not be affected.
      @_autofs_allowed = true
      # Start automounter and import the settings from LDAP
      @_start_autofs = false

      # If login of LDAP uses to local machine is enabled
      @login_enabled = true

      # which attribute have LDAP groups for list of members
      @member_attribute = ""
      @old_member_attribute = ""

      # IP addresses of LDAP server.
      @server = ""
      @old_server = ""

      # local settings modified?
      @modified = false

      # /etc/openldap/ldap.conf modified?
      @openldap_modified = false

      # base DN
      @base_dn = ""
      @old_base_dn = nil
      @base_dn_changed = false

      @ldap_tls = true
      @ldaps = false
      # Openldap configuration option TLS_REQCERT
      @request_server_certificate = 'demand'

      # CA certificates for server certificate verification
      # At least one of these are required if tls_checkpeer is "yes"
      @tls_cacertdir = ""
      @tls_cacertfile = ""
      # Require and verify server certificate (yes/no)
      @tls_checkpeer = "yes"

      # Which crypt method should be used?
      @pam_password = "exop"

      # lines of /etc/passwd, starting with +/-
      @plus_lines_passwd = []

      @default_port = 389

      # If home directories of LDAP users are stored on this machine
      @file_server = false

      # settings from ldap.conf
      @nss_base_passwd = ""
      @nss_base_shadow = ""
      @nss_base_group = ""
      @nss_base_automount = ""
      # settings from LDAP configuration objects
      @user_base = ""
      @group_base = ""
      @autofs_base = ""

      # stored values of /etc/nsswitch.conf
      @nsswitch = {
        "passwd"        => [],
        "group"         => [],
        "passwd_compat" => [],
        "group_compat"  => []
      }

      # are we binding anonymously?
      @anonymous = false

      # bind password for LDAP server
      @bind_pass = nil

      # DN for binding to LDAP server
      @bind_dn = ""

      # DN of currently edited configuration module
      @current_module_dn = ""
      # DN of currently edited template
      @current_template_dn = ""

      # if LDAP configuration objects should be created automaticaly
      @create_ldap = false

      # if eDirectory is used as server
      @nds = false

      # if crypted connection was switched of after failure (#330054)
      @tls_switched_off = false

      @nds_checked = false

      # if OES is used as a client
      @oes = false

      # expert ui means "server product"
      @expert_ui = false

      # defaults for adding new config objects and templates
      @new_objects = {
        "suseUserConfiguration"  => {
          "suseSearchFilter"      => ["objectClass=posixAccount"],
          "susePasswordHash"      => ["SSHA"],
          "suseSkelDir"           => ["/etc/skel"],
          "suseMinUniqueId"       => ["1000"],
          "suseNextUniqueId"      => ["1000"],
          "suseMaxUniqueId"       => ["60000"],
          "suseMinPasswordLength" => ["5"],
          "suseMaxPasswordLength" => ["8"]
        },
        "suseGroupConfiguration" => {
          "suseSearchFilter" => ["objectClass=posixGroup"],
          "suseMinUniqueId"  => ["1000"],
          "suseNextUniqueId" => ["1000"],
          "suseMaxUniqueId"  => ["60000"]
        },
        "suseUserTemplate"       => {
          "objectClass"         => [
            "top",
            "suseObjectTemplate",
            "suseUserTemplate"
          ],
          "suseNamingAttribute" => ["uid"],
          "suseDefaultValue"    => [
            "homeDirectory=/home/%uid",
            "loginShell=/bin/bash"
          ],
          "susePlugin"          => ["UsersPluginLDAPAll"]
        },
        "suseGroupTemplate"      => {
          "objectClass"         => [
            "top",
            "suseObjectTemplate",
            "suseGroupTemplate"
          ],
          "suseNamingAttribute" => ["cn"],
          "susePlugin"          => ["UsersPluginLDAPAll"]
        }
      }

      @base_template_dn = @base_config_dn

      # settings saved at LDAP server modified
      @ldap_modified = false

      @config_modules = {}
      @templates = {}

      @bound = false

      # DN's of groups (posixGroups) in LDAP
      @groups_dn = []

      # Map of object classes (from schema). Indexed by names.
      @object_classes = {}

      # Map of atribute types (from schema). Indexed by names.
      @attr_types = {}

      # encryption schemes supported by slappasswd
      @hash_schemas = ["CLEAR", "CRYPT", "SHA", "SSHA", "MD5", "SMD5"]

      # Available configuration modules (objectClass names)
      # TODO update
      @available_config_modules = [
        "suseUserConfiguration",
        "suseGroupConfiguration"
      ]

      # The defualt values, which should replace the ones from Read ()
      # Used during instalation, when we want to do a reasonable proposal
      @initial_defaults = {}

      # If the default values, used from ldap-server module were used
      # to configure ldap-client
      @initial_defaults_used = false

      @schema_initialized = false

      @ldap_initialized = false

      # was LDAP connection initialized with TLS?
      @tls_when_initialized = false

      # If false, do not read settings already set from outside
      # used e.g. for Users YaPI. see bug #60898
      @read_settings = true

      # if sshd should be restarted during write phase
      @restart_sshd = false

      # if /etc/passwd was read
      @passwd_read = false

      # if pam_mkhomedir is set in /etc/pam.d/commond-session
      @mkhomedir = false

      # packages needed for pam_ldap/nss_ldap configuration
      @pam_nss_packages = ["pam_ldap", "nss_ldap"]

      # packages needed for sssd configuration
      @sssd_packages = ["sssd"]

      # packages needed for sssd + kerberos configuration
      @kerberos_packages = ["krb5-client"]

      # if sssd is used instead of pam_ldap/nss_ldap (fate#308902)
      @sssd = true

      # enable/disable offline authentication ('cache_credentials' key)
      @sssd_cache_credentials = false

      # if kerberos should be set up for sssd
      @sssd_with_krb = false

      # Kerberos default realm (for sssd)
      @krb5_realm = ""

      # adress of KDC (key distribution centre) server for default realm
      @krb5_server = ""

      # ldap_schema argument of /etc/sssd/sssd.conf
      @sssd_ldap_schema = "rfc2307bis"

      # enumerate users/group
      @sssd_enumerate = false

      @ldap_error_hints = {
        # hint to error message
        -1  => _(
          "Verify that the LDAP Server is running and reachable."
        ),
        # hint to error message
        -11 => _(
          "Failed to establish TLS encryption.\nVerify that the correct CA Certificate is installed and the Server Certificate is valid."
        ),
        # hint to error message
        2   => _(
          "Failed to establish TLS encryption.\nVerify that the Server has StartTLS support enabled."
        )
      }
    end

    def use_secure_connection?
      @ldap_tls || @ldaps
    end

    alias_method :use_secure_connection, :use_secure_connection?

    #----------------------------------------------------------------

    # If the base DN has changed from a nonempty one, it may only be
    # changed at boot time. Use this to warn the user.
    # @return whether changed by SetBaseDN
    def BaseDNChanged
      @base_dn_changed
    end

    # obsolete, use BaseDNChanged
    def DomainChanged
      BaseDNChanged()
    end

    # Get the Base DN
    def GetBaseDN
      @base_dn
    end

    # obsolete, use GetBaseDN
    def GetDomain
      GetBaseDN()
    end

    # Set new LDAP base DN
    # @param [String] new_base_dn a new base DN
    def SetBaseDN(new_base_dn)
      @base_dn = new_base_dn
      @base_dn_changed = true if @base_dn != @old_base_dn && @old_base_dn != ""

      nil
    end

    # obsolete, use SetBaseDN
    def SetDomain(new_domain)
      SetBaseDN(new_domain)
    end

    # Set the defualt values, which should replace the ones from Read ()
    # Used during instalation, when we want to do a reasonable proposal
    def SetDefaults(settings)
      settings = deep_copy(settings)
      Builtins.y2milestone("using initial defaults: %1", settings)
      @initial_defaults = Builtins.eval(settings)
      true
    end

    # set the value of read_settings variable
    # which means, do not read some settings from system
    def SetReadSettings(read)
      @read_settings = read
      @read_settings
    end

    # Return needed packages and packages to be removed
    # during autoinstallation.
    # @return [Hash] of lists.
    def AutoPackages
      if @start
        @required_packages = Convert.convert(
          Builtins.union(
            @required_packages,
            @sssd ? @sssd_packages : @pam_nss_packages
          ),
          :from => "list",
          :to   => "list <string>"
        )
        if @sssd_with_krb
          @required_packages = Convert.convert(
            Builtins.union(@required_packages, @kerberos_packages),
            :from => "list",
            :to   => "list <string>"
          )
        end
      end
      { "install" => @required_packages, "remove" => [] }
    end


    # ------------- auto_yast functions --------------------------------

    # Only set variables, without checking anything
    # @return [void]
    def Set(settings)

      @start            = settings.fetch("start_ldap", false)
      @ldap_tls         = settings.fetch("ldap_tls", false)
      @ldaps            = settings.fetch("ldaps", false)
      @login_enabled    = settings.fetch("login_enabled", true)
      @_start_autofs    = settings.fetch("start_autofs", false)
      @file_server      = settings.fetch("file_server", false)
      @create_ldap      = settings.fetch("create_ldap", false)
      @mkhomedir        = settings.fetch("mkhomedir", @mkhomedir)
      @sssd             = settings.fetch("sssd", @sssd)
      @sssd_enumerate   = settings.fetch("sssd_enumerate", @sssd_enumerate)
      @sssd_cache_credentials = settings.fetch("sssd_cache_credentials", @sssd_cache_credentials)
      @sssd_with_krb    = settings.fetch("sssd_with_krb", @sssd_with_krb)

      @server           = settings["ldap_server"] || ""
      # leaving "ldap_domain" for backward compatibility
      @base_dn          = settings["ldap_domain"] || ""
      @pam_password     = settings["pam_password"] || "exop"
      @bind_dn          = settings["bind_dn"] || ""
      @base_config_dn   = settings["base_config_dn"] || ""
      @nss_base_passwd  = settings["nss_base_passwd"] || ""
      @nss_base_shadow  = settings["nss_base_shadow"] || ""
      @nss_base_group   = settings["nss_base_group"] || ""
      @nss_base_automount = settings["nss_base_automount"] || ""
      @member_attribute = settings["member_attribute"] || "member"
      @tls_cacertdir    = settings["tls_cacertdir"] || ""
      @tls_cacertfile   = settings["tls_cacertfile"] || ""
      @tls_checkpeer    = settings["tls_checkpeer"] || "yes"
      @sssd_ldap_schema = settings["sssd_ldap_schema"] || @sssd_ldap_schema
      @krb5_realm       = settings["krb5_realm"] || @krb5_realm

      # krb5_kdcip is obsoleted key - check for it if the profile is not new enough
      @krb5_server      = settings["krb5_server"] || settings["krb5_kdcip"] || @krb5_server

      @required_packages.push("autofs") if @_start_autofs

      @old_base_dn              = @base_dn
      @old_server               = @server
      @old_member_attribute     = @member_attribute
      @modified                 = true
      @openldap_modified        = true
      nil
    end

    # Get all the LDAP configuration from a map.
    # When called by ldap_auto (preparing autoinstallation data)
    # the map may be empty.
    # @param [Hash] settings	$["start": "domain": "servers":[...] ]
    # @return	success
    def Import(settings)
      settings = deep_copy(settings)
      Set(settings)
      true
    end

    # Dump the LDAP settings to a map, for autoinstallation use.
    # @return $["start":, "servers":[...], "domain":]
    def Export
      e = {
        "start_ldap"       => @start,
        "ldap_server"      => @server,
        "ldap_domain"      => @base_dn,
        "ldap_tls"         => @ldap_tls,
        "ldaps"            => @ldaps,
        "bind_dn"          => @bind_dn,
        "file_server"      => @file_server,
        "base_config_dn"   => @base_config_dn,
        "pam_password"     => @pam_password,
        "member_attribute" => @member_attribute,
        "create_ldap"      => @create_ldap,
        "login_enabled"    => @login_enabled,
        "mkhomedir"        => @mkhomedir,
        "sssd"             => @sssd,
        "sssd_with_krb"    => @sssd_with_krb
      }
      Ops.set(e, "tls_checkpeer", @tls_checkpeer) if @tls_checkpeer != "yes"
      Ops.set(e, "tls_cacertdir", @tls_cacertdir) if @tls_cacertdir != ""
      Ops.set(e, "tls_cacertfile", @tls_cacertfile) if @tls_cacertfile != ""
      if @nss_base_passwd != @base_dn
        Ops.set(e, "nss_base_passwd", @nss_base_passwd)
      end
      if @nss_base_shadow != @base_dn
        Ops.set(e, "nss_base_shadow", @nss_base_shadow)
      end
      if @nss_base_group != @base_dn
        Ops.set(e, "nss_base_group", @nss_base_group)
      end
      if @nss_base_automount != @base_dn
        Ops.set(e, "nss_base_automount", @nss_base_automount)
      end
      Ops.set(e, "start_autofs", @_start_autofs) if @_autofs_allowed
      Ops.set(e, "krb5_realm", @krb5_realm) if @krb5_realm != ""
      Ops.set(e, "krb5_server", @krb5_server) if @krb5_server != ""
      if @sssd_ldap_schema != "rfc2307bis"
        Ops.set(e, "sssd_ldap_schema", @sssd_ldap_schema)
      end
      Ops.set(e, "sssd_enumerate", @sssd_enumerate) if @sssd_enumerate
      if @sssd_cache_credentials
        Ops.set(e, "sssd_cache_credentials", @sssd_cache_credentials)
      end
      deep_copy(e)
    end

    # Summary()
    # returns html formated configuration summary
    # @return summary
    def Summary
      summary = ""
      # summary item
      summary = Summary.AddHeader(summary, _("LDAP Client Enabled"))
      # summary (is LDAP enabled?)
      summary = Summary.AddLine(
        summary,
        @start ? _("Yes") : Summary.NotConfigured
      )
      # summary item
      summary = Summary.AddHeader(summary, _("LDAP Domain"))
      summary = Summary.AddLine(
        summary,
        @base_dn != "" ? @base_dn : Summary.NotConfigured
      )
      # summary item
      summary = Summary.AddHeader(summary, _("LDAP Server"))
      summary = Summary.AddLine(
        summary,
        @server != "" ? @server : Summary.NotConfigured
      )
      # summary item
      summary = Summary.AddHeader(summary, _("LDAP TLS/SSL"))
      # summary (use TLS?)
      summary = Summary.AddLine(
        summary,
        @ldap_tls ? _("Yes") : Summary.NotConfigured
      )

      summary = Summary.AddHeader(summary, _("LDAPS"))
      summary = Summary.AddLine(
        summary,
        @ldaps ? _("Yes") : Summary.NotConfigured
      )

      # summary item
      summary = Summary.AddHeader(
        summary,
        _("System Security Services Daemon (SSSD) Set")
      )
      # summary (SSSD Set?)
      summary = Summary.AddLine(
        summary,
        @sssd && @start ? _("Yes") : Summary.NotConfigured
      )

      summary
    end

    # returns html formated configuration summary (shorter than Summary)
    # @return summary
    def ShortSummary
      nc = Summary.NotConfigured
      summary = ""
      # summary text
      summary = Ops.add(
        Ops.add(
          Builtins.sformat(
            _("<b>Servers</b>:%1<br>"),
            @server != "" ? @server : nc
          ),
          # summary text
          Builtins.sformat(
            _("<b>Base DN</b>:%1<br>"),
            @base_dn != "" ? @base_dn : nc
          )
        ),
        # summary text (yes/no follows)
        Builtins.sformat(
          _("<b>Client Enabled</b>:%1"),
          @start ?
            # summary (client enabled?)
            _("Yes") :
            # summary (client enabled?)
            _("No")
        )
      )
      if @_start_autofs
        # summary
        summary = Ops.add(Ops.add(summary, "<br>"), _("Automounter Configured"))
      end
      if @ldap_tls
        # summary
        summary = Ops.add(
          Ops.add(summary, "<br>"),
          _("LDAP TLS Configured")
        )
      end

      if @ldaps
        summary << "<br/>" << _("LDAPS Configured")
      end

      if @start && @sssd
        # summary
        summary = Ops.add(
          Ops.add(summary, "<br>"),
          _("System Security Services Daemon (SSSD) Set")
        )
      end
      summary
    end

    # ------------- read/write functions -------------------------------

    # For sssd, some kerberos values are needed
    def ReadKrb5Conf
      realm = Convert.convert(
        SCR.Read(path(".etc.krb5_conf.v.libdefaults.default_realm")),
        :from => "any",
        :to   => "list <string>"
      )
      realm = [] if realm == nil
      @krb5_realm = Ops.get(realm, 0, "")

      kdcs = Convert.convert(
        SCR.Read(
          Builtins.add(
            Builtins.add(path(".etc.krb5_conf.v"), @krb5_realm),
            "kdc"
          )
        ),
        :from => "any",
        :to   => "list <string>"
      )
      kdcs = [] if kdcs == nil
      @krb5_server = Builtins.mergestring(kdcs, ",")

      true
    end


    # Read single entry from /etc/ldap.conf file
    # @param [String] entry entry name
    # @param [String] defvalue default value if entry is not present
    # @return entry value
    def ReadLdapConfEntry(entry, defvalue)
      value = defvalue
      ret = SCR.Read(
        Builtins.add(path(".etc.ldap_conf.v.\"/etc/ldap.conf\""), entry)
      )
      if ret == nil
        value = defvalue
      elsif Ops.is_list?(ret)
        value = Ops.get_string(Convert.to_list(ret), 0, defvalue)
      else
        value = Builtins.sformat("%1", ret)
      end
      value
    end

    # Read multi-valued entry from /etc/ldap.conf file
    # @param [String] entry entry name
    # @return entry value
    def ReadLdapConfEntries(entry)
      ret = SCR.Read(
        Builtins.add(path(".etc.ldap_conf.v.\"/etc/ldap.conf\""), entry)
      )
      if ret == nil
        return []
      elsif Ops.is_list?(ret)
        return Convert.convert(ret, :from => "any", :to => "list <string>")
      else
        return [Builtins.sformat("%1", ret)]
      end
    end

    # Write (single valued) entry to /etc/ldap.conf
    # @param [String] entry name
    # @param [String] value; if value is nil, entry will be removed
    def WriteLdapConfEntry(entry, value)
      SCR.Write(
        Builtins.add(path(".etc.ldap_conf.v.\"/etc/ldap.conf\""), entry),
        value == nil ? nil : [value]
      )

      nil
    end

    # Write (possibly multi valued) entry to /etc/ldap.conf
    # @param [String] entry name
    # @param [Array<String>] value it is of type [attr1, attr2],
    # in /etc/ldap.conf should be written as "entry attr1 attr2"
    # @example to write "nss_map_attribute       uniquemember member", call
    # WriteLdapConfEntries ("nss_map_attribute", ["uniquemember", "member"])
    def WriteLdapConfEntries(entry, value)
      value = deep_copy(value)
      current = ReadLdapConfEntries(entry)
      values = []
      Builtins.foreach(current) do |val|
        lval = Builtins.splitstring(val, " \t")
        if Builtins.tolower(Ops.get_string(lval, 0, "")) !=
            Builtins.tolower(Ops.get(value, 0, ""))
          values = Builtins.add(values, val)
        else
          values = Builtins.add(values, Builtins.mergestring(value, " "))
        end
      end
      values = [Builtins.mergestring(value, " ")] if Builtins.size(current) == 0
      SCR.Write(
        Builtins.add(path(".etc.ldap_conf.v.\"/etc/ldap.conf\""), entry),
        values
      )

      nil
    end

    # Add a new value to the entry in /etc/ldap.conf
    # @param [String] entry name
    # @param [String] value
    def AddLdapConfEntry(entry, value)
      current = ReadLdapConfEntries(entry)
      current = Builtins.maplist(current) { |e| Builtins.tolower(e) }

      if !Builtins.contains(current, Builtins.tolower(value))
        SCR.Write(
          Builtins.add(path(".etc.ldap_conf.v.\"/etc/ldap.conf\""), entry),
          Builtins.union(current, [value])
        )
      end

      nil
    end

    # Check if current machine runs OES
    def CheckOES
      @oes = Package.Installed("NOVLam")
      @oes
    end

    # convert list of uri's to list of hosts
    def uri2servers(uri)
      Builtins.mergestring(
        Builtins.maplist(Builtins.splitstring(uri, " \t")) do |u|
          url = URL.Parse(u)
          h = Ops.get_string(url, "host", "")
          if Ops.get_string(url, "port", "") != ""
            h = Builtins.sformat("%1:%2", h, Ops.get_string(url, "port", ""))
          end
          h
        end,
        " "
      )
    end

    # Read values of LDAP hosts from ldap.conf
    # get them from 'uri' or 'host' values
    def ReadLdapHosts
      ret = ""
      uri = ReadLdapConfEntry("uri", "")
      if uri == ""
        ret = ReadLdapConfEntry("host", "")
      else
        detect_ldaps(uri)
        ret = uri2servers(uri)
      end
      ret
    end

    def detect_ldaps uri
      uri = URI.parse(uri)
      @ldaps = uri.scheme == 'ldaps'
      @request_server_certificate = read_openldap_config('TLS_REQCERT').first
    end

    def detect_uri_scheme
      @ldaps ? 'ldaps://' : 'ldap://'
    end

    # Reads LDAP settings from the SCR
    # @return success
    def Read
      @expert_ui = ProductFeatures.GetFeature("globals", "ui_mode") == "expert"

      CheckOES()

      Builtins.foreach(["passwd", "group", "passwd_compat", "group_compat"]) do |db|
        Ops.set(@nsswitch, db, Nsswitch.ReadDb(db))
      end

      # 'start' means that LDAP is present in nsswitch somehow... either as 'compat'/'ldap'...
      @start = Builtins.contains(Ops.get_list(@nsswitch, "passwd", []), "ldap") ||
        Builtins.contains(Ops.get_list(@nsswitch, "passwd", []), "compat") &&
          Builtins.contains(
            Ops.get_list(@nsswitch, "passwd_compat", []),
            "ldap"
          ) ||
        @oes && Builtins.contains(Ops.get_list(@nsswitch, "passwd", []), "nam")

      if @start
        # nss_ldap is used
        @sssd = false
      else
        # ... or as 'sssd'
        @start  = Builtins.contains(Ops.get_list(@nsswitch, "passwd", []), "sss")
      end

      # nothing is configured, but some packages are installed
      if !@start && Package.InstalledAll(@pam_nss_packages) &&
          !Package.InstalledAll(@sssd_packages)
        @sssd = false
      end

      @old_start = @start

      @nis_available = Builtins.contains(
        Ops.get_list(@nsswitch, "passwd", []),
        "nis"
      ) ||
        Builtins.contains(Ops.get_list(@nsswitch, "passwd", []), "compat") &&
          (Builtins.contains(
            Ops.get_list(@nsswitch, "passwd_compat", []),
            "nis"
          ) ||
            Builtins.size(Ops.get_list(@nsswitch, "passwd_compat", [])) == 0)
      @nis_available = @nis_available && Service.Status("ypbind") == 0

      @server = ReadLdapHosts()

      @base_dn = ReadLdapConfEntry("base", "")

      @old_base_dn = @base_dn
      @old_server = @server

      # ask DNS for LDAP server address if none is defined
      if (@server == "" ||
          @server == "127.0.0.1" && @base_dn == "dc=example,dc=com") &&
          FileUtils.Exists("/usr/bin/dig") &&
          !Mode.test
        domain = Hostname.CurrentDomain
        # workaround for bug#393951
        if domain == "" && Stage.cont
          out2 = Convert.to_map(
            SCR.Execute(path(".target.bash_output"), "domainname")
          )
          if Ops.get_integer(out2, "exit", 0) == 0
            domain = Builtins.deletechars(
              Ops.get_string(out2, "stdout", ""),
              "\n"
            )
          end
        end
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Builtins.sformat("dig SRV _ldap._tcp.%1 +short", domain)
          )
        )
        first = Ops.get(
          Builtins.splitstring(Ops.get_string(out, "stdout", ""), "\n"),
          0,
          ""
        )
        srv = Ops.get(Builtins.splitstring(first, " "), 3, "")
        if srv != ""
          # remove dot from the end of line
          @server = Builtins.substring(
            srv,
            0,
            Ops.subtract(Builtins.size(srv), 1)
          )
          Builtins.y2milestone("LDAP server address acquired from DNS...")
          # now, check if there is reasonable 'default' DN
          dn = ""
          Builtins.foreach(Builtins.splitstring(domain, ".")) do |part|
            dn = Ops.add(dn, ",") if dn != ""
            dn = Ops.add(Ops.add(dn, "dc="), part)
          end
          if 0 ==
              SCR.Execute(
                path(".target.bash"),
                Builtins.sformat(
                  "ldapsearch -x -h %1 -s base -b '' namingContexts | grep -i '^namingContexts: %2'",
                  @server,
                  dn
                )
              )
            Builtins.y2milestone("proposing DN %1 based on %2", dn, domain)
            @base_dn = dn
          end
        end
      end

      @ldap_tls = ReadLdapConfEntry("ssl", "no") == "start_tls"
      @tls_cacertdir = ReadLdapConfEntry("tls_cacertdir", "")
      @tls_cacertfile = ReadLdapConfEntry("tls_cacertfile", "")
      @tls_checkpeer = ReadLdapConfEntry("tls_checkpeer", "yes")

      @nss_base_passwd = ReadLdapConfEntry("nss_base_passwd", @base_dn)
      @nss_base_shadow = ReadLdapConfEntry("nss_base_shadow", @base_dn)
      @nss_base_group = ReadLdapConfEntry("nss_base_group", @base_dn)
      @nss_base_automount = ReadLdapConfEntry("nss_base_automount", @base_dn)

      @pam_password = ReadLdapConfEntry("pam_password", "exop")
      # check if Password Modify extenstion is supported (bnc#546398, c#6)
      if @pam_password == "exop"
        if 0 == SCR.Execute(path(".target.bash"), "ldapsearch -x -b '' -s base") &&
            0 !=
              SCR.Execute(
                path(".target.bash"),
                "ldapsearch -x -b '' -s base supportedExtension | grep -i '^supportedExtension:[[:space:]]*1.3.6.1.4.1.4203.1.11.1'"
              ) # LDAP server accessible
          Builtins.y2warning(
            "'exop' value not supported on server, using 'crypt'"
          )
          @pam_password = "crypt"
        end
      end

      # read sysconfig values
      @base_config_dn = Convert.to_string(
        SCR.Read(path(".sysconfig.ldap.BASE_CONFIG_DN"))
      )
      @base_config_dn = "" if @base_config_dn == nil

      @file_server = Convert.to_string(
        SCR.Read(path(".sysconfig.ldap.FILE_SERVER"))
      ) == "yes"

      if @read_settings || @bind_dn == ""
        @bind_dn = Convert.to_string(SCR.Read(path(".sysconfig.ldap.BIND_DN")))
      end
      if @bind_dn == nil || @bind_dn == ""
        @bind_dn = ReadLdapConfEntry("binddn", "")
      end

      if @read_settings || @member_attribute == ""
        map_attrs = ReadLdapConfEntries("nss_map_attribute")
        Builtins.foreach(map_attrs) do |map_attr|
          if Builtins.issubstring(Builtins.tolower(map_attr), "uniquemember")
            attr = Builtins.splitstring(map_attr, " \t")
            if Builtins.tolower(Ops.get(attr, 0, "")) == "uniquemember"
              @member_attribute = Ops.get(attr, 1, @member_attribute)
              # LDAP needs to know correct attribute name
              if @member_attribute == "uniquemember"
                @member_attribute = "uniqueMember"
              end
              @old_member_attribute = @member_attribute
            end
          end
        end
      end

      # install on demand
      @_autofs_allowed = true
      @_start_autofs = @_autofs_allowed && Service.Enabled("autofs")

      # read /etc/passwd to check + line:
      if !Convert.to_boolean(
          SCR.Execute(path(".passwd.init"), { "base_directory" => "/etc" })
        )
        error = Convert.to_string(SCR.Read(path(".passwd.error")))
        Builtins.y2error("error: %1", error)
      else
        @passwd_read = true
        @plus_lines_passwd = Convert.convert(
          SCR.Read(path(".passwd.passwd.pluslines")),
          :from => "any",
          :to   => "list <string>"
        )
        Builtins.foreach(@plus_lines_passwd) do |plus_line|
          plus = Builtins.splitstring(plus_line, ":")
          if Ops.get(plus, Ops.subtract(Builtins.size(plus), 1), "") == "/sbin/nologin"
            @login_enabled = false
          end
        end
      end

      @mkhomedir = Pam.Enabled("mkhomedir")

      Autologin.Read

      ReadKrb5Conf() if Pam.Enabled("krb5")
      if FileUtils.Exists("/etc/sssd/sssd.conf")
        # read realm and kdc from sssd.conf if available
        domain = Builtins.add(path(".etc.sssd_conf.v"), "domain/default")
        realm = Convert.to_string(SCR.Read(Builtins.add(domain, "krb5_realm")))
        @krb5_realm = realm if realm != nil
        kdc = Convert.to_string(SCR.Read(Builtins.add(domain, "krb5_server")))
        @krb5_server = kdc if kdc != nil
        schema = Convert.to_string(
          SCR.Read(Builtins.add(domain, "ldap_schema"))
        )
        @sssd_ldap_schema = schema if schema != nil

        cache_credentials = Convert.to_string(
          SCR.Read(Builtins.add(domain, "cache_credentials"))
        )
        @sssd_cache_credentials = cache_credentials != nil &&
          Builtins.tolower(cache_credentials) == "true"
        enumerate = Convert.to_string(
          SCR.Read(Builtins.add(domain, "enumerate"))
        )
        @sssd_enumerate = enumerate != nil &&
          Builtins.tolower(enumerate) == "true"

        id_start_tls = Convert.to_string(
          SCR.Read(Builtins.add(domain, "ldap_id_use_start_tls"))
        )
        if id_start_tls != nil
          @ldap_tls = Builtins.tolower(id_start_tls) == "true"
        else
          # true for SSSD by default, if not overriden by ldap_id_use_start_tls
          @ldap_tls = true
        end

        # replace nss_base_passwd with ldap_user_search_base (if it is set)
        user_base = Convert.to_string(
          SCR.Read(Builtins.add(domain, "ldap_user_search_base"))
        )
        @nss_base_passwd = user_base if user_base != nil
        group_base = Convert.to_string(
          SCR.Read(Builtins.add(domain, "ldap_group_search_base"))
        )
        @nss_base_group = group_base if group_base != nil
        autofs_base = Convert.to_string(
          SCR.Read(Builtins.add(domain, "ldap_autofs_search_base"))
        )
        @nss_base_automount = autofs_base if autofs_base != nil
      end
      @sssd_with_krb = true if @krb5_realm != "" && @krb5_server != ""

      # Now check if previous configuration of LDAP server didn't proposed
      # some better values:
      if Stage.cont
        if Ops.greater_than(Builtins.size(@initial_defaults), 0)
          Builtins.y2milestone("using values defined externaly")
          old_s = @old_server
          old_d = @old_base_dn
          old_m = @old_member_attribute
          Set(@initial_defaults)
          @old_server = old_s
          @old_base_dn = old_d
          @old_member_attribute = old_m
        end
      end

      if @member_attribute == ""
        @member_attribute = "member"
        @modified = true
      end

      true
    end

    # ------------- functions for work with LDAP tree contents ------------

    # Error popup for errors detected during LDAP operation
    # @param [String] type error type: binding/reading/writing
    # @param detailed error message (from agent-ldap)
    def LDAPErrorMessage(type, error)
      ldap_error = {
        # error message:
        "initialize"   => _(
          "\nThe server could be down or unreachable.\n"
        ),
        # error message:
        "missing_dn"   => _(
          "\nThe value of DN is missing or invalid.\n"
        ),
        # error message:
        "at_not_found" => _("\nAttribute type not found.\n"),
        # error message:
        "oc_not_found" => _("\nObject class not found.\n")
      }

      error_type = {
        # error message, more specific description follows
        "init"   => _(
          "Connection to the LDAP server cannot be established."
        ),
        # error message, more specific description follows
        "bind"   => _(
          "A problem occurred while connecting to the LDAP server."
        ),
        # error message, more specific description follows
        "read"   => _(
          "A problem occurred while reading data from the LDAP server."
        ),
        # error message, more specific description follows
        "users"  => _(
          "A problem occurred while writing LDAP users."
        ),
        # error message, more specific description follows
        "groups" => _(
          "A problem occurred while writing LDAP groups."
        ),
        # error message, more specific description follows
        "write"  => _(
          "A problem occurred while writing data to the LDAP server."
        ),
        # error message, more specific description follows
        "schema" => _(
          "A problem occurred while reading schema from the LDAP server."
        )
      }

      if !@use_gui || Mode.commandline
        Builtins.y2error(Ops.get_string(error_type, type, "Unknown LDAP error"))
        Builtins.y2error(Ops.get_string(ldap_error, error, error))
        return
      end

      error = "YaST error?" if error == nil

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # default error message
            Label(
              Ops.get_locale(
                error_type,
                type,
                _("An unknown LDAP error occurred.")
              )
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.5),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            PushButton(Id(:ok), Opt(:key_F10, :default), Label.OKButton)
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      UI.ChangeWidget(Id(:details), :Enabled, false) if error == ""
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(
              Id(:rp),
              VBox(Label(Ops.get_string(ldap_error, error, error)))
            )
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :ok && ret != :cancel
      UI.CloseDialog

      nil
    end

    # Reads and returns error map (=message + code) from agent
    def LDAPErrorMap
      ret = Convert.to_map(SCR.Read(path(".ldap.error")))
      if Ops.get_string(@ldap_error_hints, Ops.get_integer(ret, "code", 0), "") != ""
        Ops.set(
          ret,
          "hint",
          Ops.get_string(@ldap_error_hints, Ops.get_integer(ret, "code", 0), "")
        )
      end
      deep_copy(ret)
    end

    # Reads and returns error message from agent
    def LDAPError
      err_map = LDAPErrorMap()
      error = Ops.get_string(err_map, "msg", "")
      if Ops.get_string(err_map, "server_msg", "") != ""
        error = Builtins.sformat(
          "%1\n(%2)",
          error,
          Ops.get_string(err_map, "server_msg", "")
        )
      end
      error
    end


    # return administrator's DN
    # if it was not read yet, read it now
    def GetBindDN
      if @bind_pass == nil && Builtins.size(@bind_dn) == 0
        Builtins.y2milestone("--- bind dn not read yet or empty, reading now")
        @bind_dn = Convert.to_string(SCR.Read(path(".sysconfig.ldap.BIND_DN")))
        if @bind_dn == nil || @bind_dn == ""
          @bind_dn = ReadLdapConfEntry("binddn", "")
        end
      end
      @bind_dn
    end


    # this is a hack
    def GetFirstServer(servers)
      if @bind_pass == nil && servers == ""
        Builtins.y2milestone("--- server not read yet or empty, reading now")
        servers = ReadLdapHosts()
      end

      l_servers = Builtins.splitstring(servers, " \t")
      srv = Ops.get_string(l_servers, 0, "")
      Ops.get(Builtins.splitstring(srv, ":"), 0, "")
    end

    # this is a hack
    def GetFirstPort(servers)
      if @bind_pass == nil && servers == ""
        Builtins.y2milestone("--- server not read yet or empty, reading now")
        servers = ReadLdapHosts()
      end

      l_servers = Builtins.splitstring(servers, " \t")
      srv = Ops.get_string(l_servers, 0, "")
      return @default_port if !Builtins.issubstring(srv, ":")
      s_port = Builtins.substring(srv, Ops.add(Builtins.search(srv, ":"), 1))
      if s_port == "" || Builtins.tointeger(s_port) == nil
        return @default_port
      else
        return Builtins.tointeger(s_port)
      end
    end

    # Shut down existing LDAP connection
    def LDAPClose
      @ldap_initialized = false
      Convert.to_boolean(SCR.Execute(path(".ldap.close")))
    end

    # Initializes LDAP agent
    def LDAPInit
      # FIXME what if we have more servers? -> choose dialog?
      ret = ""
      args = {
        "hostname"   => GetFirstServer(@server),
        "port"       => GetFirstPort(@server),
        "use_tls"    => @ldap_tls ? "yes" : "no",
        "cacertdir"  => @tls_cacertdir,
        "cacertfile" => @tls_cacertfile
      }
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      if init == nil
        # error message
        ret = _("Unknown error. Perhaps 'yast2-ldap' is not available.")
      else
        @ldap_initialized = init
        @tls_when_initialized = @ldap_tls
        ret = LDAPError() if !init
      end
      ret
    end

    # Initializes LDAP agent; use the data passed as argument instead global values
    # Returns whole error map, not just message
    def LDAPInitArgs(args)
      args = deep_copy(args)
      ret = {}
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      if init == nil
        # error message
        Ops.set(
          ret,
          "msg",
          _("Unknown error. Perhaps 'yast2-ldap' is not available.")
        )
      else
        @ldap_initialized = init
        if !init
          ret = LDAPErrorMap()
        else
          @tls_when_initialized = Ops.get_string(args, "use_tls", "") == "yes"
        end
      end
      deep_copy(ret)
    end

    # Check if LDAP connection can be established with given values.
    def CheckLDAPConnection(args)
      args = deep_copy(args)
      LDAPClose()
      errmap = LDAPInitArgs(args)

      return true if errmap == {}

      details = Ops.get_string(errmap, "msg", "")
      if Ops.get_string(errmap, "server_msg", "") != ""
        details = Builtins.sformat(
          "%1\n%2",
          details,
          Ops.get_string(errmap, "server_msg", "")
        )
      end
      hint = Ops.get_string(errmap, "hint", "")

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # error message
            Left(
              Label(_("Connection to the LDAP server cannot be established."))
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.2),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            VSpacing(),
            hint != "" ? VBox(Left(Label(hint)), VSpacing()) : VBox(),
            Left(
              Label(
                # question following error message (yes/no buttons follow)
                _("Really keep this configuration?")
              )
            ),
            HBox(
              PushButton(Id(:yes), Opt(:key_F10, :default), Label.YesButton),
              PushButton(Id(:no), Opt(:key_F9), Label.NoButton)
            )
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(Id(:rp), VBox(Label(details)))
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :yes && ret != :no
      UI.CloseDialog
      ret == :yes
    end

    # popup shown after failed connection: ask for retry withou TLS (see bug 246397)
    # @return true if user wants to retry without TLS
    def ConnectWithoutTLS(errmap)
      errmap = deep_copy(errmap)
      details = Ops.get_string(errmap, "msg", "")
      if Ops.get_string(errmap, "server_msg", "") != ""
        details = Builtins.sformat(
          "%1\n%2",
          details,
          Ops.get_string(errmap, "server_msg", "")
        )
      end

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # error message
            Left(
              Label(_("Connection to the LDAP server cannot be established."))
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.2),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            VSpacing(),
            Left(
              Label(
                # question following error message (yes/no buttons follow)
                _(
                  "A possible reason for the failed connection may be that your client is\n" +
                    "configured for TLS/SSL but the server does not support it.\n" +
                    "\n" +
                    "Retry connection without TLS/SSL?\n"
                )
              )
            ),
            ButtonBox(
              PushButton(Id(:yes), Opt(:key_F10, :default), Label.YesButton),
              PushButton(Id(:no), Opt(:key_F9), Label.NoButton)
            )
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(Id(:rp), VBox(Label(details)))
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :yes && ret != :no
      UI.CloseDialog
      ret == :yes
    end

    # Initializes LDAP agent, offers to turn off TLS if it failed
    # @args arguments to use for initializaton (if empty, uses the current values)
    def LDAPInitWithTLSCheck(args)
      args = deep_copy(args)
      ret = ""
      if args == {}
        args = {
          "hostname"   => GetFirstServer(@server),
          "port"       => GetFirstPort(@server),
          "use_tls"    => @ldap_tls ? "yes" : "no",
          "cacertdir"  => @tls_cacertdir,
          "cacertfile" => @tls_cacertfile
        }
      end
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      # error message
      unknown = _("Unknown error. Perhaps 'yast2-ldap' is not available.")
      if init == nil
        ret = unknown
      else
        if !init
          errmap = LDAPErrorMap()
          if Ops.get_string(args, "use_tls", "") == "yes" &&
              Ops.get_boolean(errmap, "tls_error", false) &&
              ConnectWithoutTLS(errmap)
            Ops.set(args, "use_tls", "no")
            init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
            if init == nil
              ret = unknown
            elsif !init
              ret = LDAPError()
            else
              Builtins.y2milestone("switching TLS off...")
              @tls_switched_off = true
            end
          else
            ret = Ops.get_string(errmap, "msg", "")
            if Ops.get_string(errmap, "server_msg", "") != ""
              ret = Builtins.sformat(
                "%1\n%2",
                ret,
                Ops.get_string(errmap, "server_msg", "")
              )
            end
          end
        end
        @ldap_initialized = init
        @tls_when_initialized = Ops.get_string(args, "use_tls", "no") == "yes"
      end
      ret
    end

    # Binds to LDAP server
    # @param [String] pass password
    def LDAPBind(pass)
      ret = ""
      if pass != nil
        args = {}
        args = { "bind_dn" => @bind_dn, "bind_pw" => pass } if !@anonymous
        if !Convert.to_boolean(SCR.Execute(path(".ldap.bind"), args))
          ret = LDAPError()
        else
          @bound = true
        end
      end
      ret
    end

    # Asks user for bind password to LDAP server
    # @param anonymous if anonymous access could be allowed
    # @return password
    def GetLDAPPassword(enable_anonymous)
      UI.OpenDialog(
        Opt(:decorated),
        VBox(
          HSpacing(40),
          # password entering label
          Password(Id(:pw), Opt(:hstretch), _("&LDAP Server Password")),
          # label
          Label(
            Builtins.sformat(
              _("Server: %1:%2"),
              GetFirstServer(@server),
              GetFirstPort(@server)
            )
          ),
          # label (%1 is admin DN - string)
          Label(Builtins.sformat(_("Administrator: %1"), GetBindDN())),
          ButtonBox(
            PushButton(Id(:ok), Opt(:key_F10, :default), Label.OKButton),
            # button label
            PushButton(Id(:anon), Opt(:key_F6), _("&Anonymous Access")),
            PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton)
          )
        )
      )
      UI.ChangeWidget(Id(:anon), :Enabled, false) if !enable_anonymous
      UI.SetFocus(Id(:pw))
      ret = UI.UserInput
      pw = ""
      if ret == :ok
        pw = Convert.to_string(UI.QueryWidget(Id(:pw), :Value))
        @anonymous = false
      elsif ret == :cancel
        pw = nil
      else
        @anonymous = true
      end
      UI.CloseDialog
      pw
    end

    # Asks for LDAP password and tries to bind with it
    # @return password entered, nil on cancel
    def LDAPAskAndBind(enable_anonymous)
      return nil if Mode.commandline
      pw = GetLDAPPassword(enable_anonymous)
      if pw != nil
        ldap_msg = LDAPBind(pw)
        while pw != nil && ldap_msg != ""
          LDAPErrorMessage("bind", ldap_msg)
          pw = GetLDAPPassword(enable_anonymous)
          ldap_msg = LDAPBind(pw)
        end
      end
      pw
    end

    # Check if attribute allowes only single or multiple value
    # @param [String] attr attribute name
    # @return answer
    def SingleValued(attr)
      attr = Builtins.tolower(attr)
      if !Builtins.haskey(@attr_types, attr)
        attr_type = Convert.to_map(
          SCR.Read(path(".ldap.schema.at"), { "name" => attr })
        )
        attr_type = {} if attr_type == nil
        Ops.set(@attr_types, attr, attr_type)
      end
      Ops.get_boolean(@attr_types, [attr, "single"], false)
    end

    # Gets the description of attribute (from schema)
    # @param [String] attr attribute name
    # @return description
    def AttributeDescription(attr)
      if !Builtins.haskey(@attr_types, attr)
        attr_type = Convert.to_map(
          SCR.Read(path(".ldap.schema.at"), { "name" => attr })
        )
        attr_type = {} if attr_type == nil
        Ops.set(@attr_types, attr, attr_type)
      end
      Ops.get_string(@attr_types, [attr, "desc"], "")
    end

    # Returns true if given object class exists in schema
    # @param [String] class ObjectClass name
    def ObjectClassExists(_class)
      Convert.to_boolean(
        SCR.Read(path(".ldap.schema.oc.check"), { "name" => _class })
      )
    end

    # Returns true if given object class is of 'structural' type
    # @param [String] class ObjectClass name
    def ObjectClassStructural(_class)
      object_class = Convert.to_map(
        SCR.Read(path(".ldap.schema.oc"), { "name" => _class })
      )
      Ops.get_integer(object_class, "kind", 0) == 1
    end


    # Returns allowed and required attributes of given object class
    # Read it from LDAP if it was not done yet.
    # @param [String] class name of object class
    # @return attribute names (list of strings)
    def GetAllAttributes(_class)
      _class = Builtins.tolower(_class)
      if !Builtins.haskey(@object_classes, _class)
        object_class = Convert.to_map(
          SCR.Read(path(".ldap.schema.oc"), { "name" => _class })
        )
        object_class = {} if object_class == nil #TODO return from function?
        Ops.set(
          object_class,
          "all",
          Builtins.union(
            Ops.get_list(object_class, "may", []),
            Ops.get_list(object_class, "must", [])
          )
        )
        # read attributes of superior classes
        Builtins.foreach(Ops.get_list(object_class, "sup", [])) do |sup_oc|
          sup_all = GetAllAttributes(sup_oc)
          Ops.set(
            object_class,
            "all",
            Builtins.union(Ops.get_list(object_class, "all", []), sup_all)
          )
          Ops.set(
            object_class,
            "must",
            Builtins.union(
              Ops.get_list(object_class, "must", []),
              Ops.get_list(@object_classes, [sup_oc, "must"], [])
            )
          )
        end
        Ops.set(@object_classes, _class, object_class)
      end
      Ops.get_list(@object_classes, [_class, "all"], [])
    end

    # Returns required attributes of given object class
    # Read it from LDAP if it was not done yet.
    # @param [String] class name of object class
    # @return attribute names (list of strings)
    def GetRequiredAttributes(_class)
      _class = Builtins.tolower(_class)
      GetAllAttributes(_class) if !Builtins.haskey(@object_classes, _class)
      Ops.get_list(@object_classes, [_class, "must"], [])
    end

    def GetOptionalAttributes(_class)
      _class = Builtins.tolower(_class)
      GetAllAttributes(_class) if !Builtins.haskey(@object_classes, _class)
      Ops.get_list(@object_classes, [_class, "may"], [])
    end

    # Returns the list of all allowed and required attributes for each
    # object class, given in the list of object classes
    # @param [Array] classes list of object classes whose attributes we want
    # @return attribute names (list of strings)
    def GetObjectAttributes(classes)
      classes = deep_copy(classes)
      ret = []
      Builtins.foreach(
        Convert.convert(classes, :from => "list", :to => "list <string>")
      ) { |_class| ret = Builtins.union(ret, GetAllAttributes(_class)) }
      deep_copy(ret)
    end

    # For a given object, add all atributes this object is allowed to have
    # according to its "objectClass" value. Added attributes have empty values.
    # @param [Hash] object map describing LDAP entry
    # @return updated map
    def AddMissingAttributes(object)
      object = deep_copy(object)
      Builtins.foreach(Ops.get_list(object, "objectClass", [])) do |_class|
        Builtins.foreach(
          Convert.convert(
            GetAllAttributes(_class),
            :from => "list",
            :to   => "list <string>"
          )
        ) do |attr|
          if !Builtins.haskey(object, attr) &&
              !Builtins.haskey(object, Builtins.tolower(attr))
            object = Builtins.add(object, attr, [])
          end
        end
      end
      deep_copy(object)
    end

    # Prepare agent for later schema queries
    # (agent reads schema to its internal structures)
    # @return error message
    def InitSchema
      schemas = Convert.to_list(
        SCR.Read(
          path(".ldap.search"), #0:base
          { "base_dn" => "", "attrs" => ["subschemaSubentry"], "scope" => 0 }
        )
      )
      schema_dn = Ops.get_string(schemas, [0, "subschemaSubentry", 0], "")
      return LDAPError() if schemas == nil || schema_dn == ""

      if !Convert.to_boolean(
          SCR.Execute(path(".ldap.schema"), { "schema_dn" => schema_dn })
        )
        return LDAPError()
      end

      @schema_initialized = true
      ""
    end

    # In template object, convert the list of values
    # (which is in the form [ "a1=v1", "a2=v2"])
    # to map (in the form $[ "a1":"v1", "a2":"v2"]
    # @param [Hash] templ original template map
    # @return updated template map
    def ConvertDefaultValues(templ)
      templ = deep_copy(templ)
      template = Builtins.add(templ, "default_values", {})
      Builtins.foreach(Ops.get_list(templ, "suseDefaultValue", [])) do |value|
        lvalue = Builtins.splitstring(value, "=")
        at = Ops.get(lvalue, 0, "")
        v = Ops.greater_than(Builtins.size(lvalue), 1) ?
          # '=' could be part of value, so we cannot use lvalue[1]
          Builtins.substring(value, Ops.add(Builtins.search(value, "="), 1)) :
          ""
        Ops.set(template, ["default_values", at], v)
      end
      deep_copy(template)
    end

    # Read object templates from LDAP server
    # @return [String] error message
    def ReadTemplates
      @templates = {}
      all = Convert.to_map(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => @base_config_dn,
            "filter"       => "objectClass=suseObjectTemplate",
            "attrs"        => [],
            "scope"        => 2, # sub: all templates under config DN
            "map"          => true,
            "not_found_ok" => true
          }
        )
      )
      return LDAPError() if all == nil
      # create a helper map of default values inside ...
      @templates = Builtins.mapmap(
        Convert.convert(
          all,
          :from => "map",
          :to   => "map <string, map <string, any>>"
        )
      ) do |dn, templ|
        template = ConvertDefaultValues(templ)
        template = AddMissingAttributes(template)
        { dn => template }
      end
      ""
    end

    # Read configuration moduels from LDAP server
    # @return [String] error message
    def ReadConfigModules
      @config_modules = {}
      modules = Convert.to_map(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => @base_config_dn,
            "filter"       => "objectClass=suseModuleConfiguration",
            "attrs"        => [],
            "scope"        => 1, # one - deeper searches would have problems with
            # constructing the dn
            "map"          => true,
            "not_found_ok" => true
          }
        )
      )
      return LDAPError() if modules == nil
      @config_modules = Builtins.mapmap(
        Convert.convert(
          modules,
          :from => "map",
          :to   => "map <string, map <string, any>>"
        )
      ) { |dn, mod| { dn => AddMissingAttributes(mod) } }
      ""
    end

    # Search for one entry (=base scope) in LDAP directory
    # @param [String] dn DN of entry
    # @return [Hash] with entry values, empty map if nothing found, nil on error
    def GetLDAPEntry(dn)
      if !@ldap_initialized
        msg = LDAPInit()
        if msg != ""
          LDAPErrorMessage("init", msg)
          return nil
        end
      end
      if !@schema_initialized
        msg = InitSchema()
        if msg != ""
          LDAPErrorMessage("schema", msg)
          return nil
        end
      end
      if @bind_pass == nil && !@anonymous
        @bind_pass = LDAPAskAndBind(true)
        return nil if @bind_pass == nil
      end
      objects = Convert.to_list(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => dn,
            "attrs"        => [],
            "scope"        => 0, # only this one
            "not_found_ok" => true
          }
        )
      )
      if objects == nil
        LDAPErrorMessage("read", LDAPError())
        return nil
      end
      Ops.get_map(objects, 0, {})
    end

    # Check for existence of parent object of given DN in LDAP tree
    # return the answer
    def ParentExists(dn)
      return false if !Builtins.issubstring(dn, ",")

      parent = Builtins.substring(dn, Ops.add(Builtins.search(dn, ","), 1))
      object = GetLDAPEntry(parent)
      return false if object == nil
      if object == {}
        if !@use_gui
          Builtins.y2error(
            "A direct parent for DN %1 does not exist in the LDAP directory. The object with the selected DN cannot be created.",
            dn
          )
          return false
        end
        # error message, %1 is DN
        Popup.Error(
          Builtins.sformat(
            _(
              "A direct parent for DN '%1' \n" +
                "does not exist in the LDAP directory.\n" +
                "The object with the selected DN cannot be created.\n"
            ),
            dn
          )
        )
        return false
      end
      true
    end

    # Return main configuration object DN
    def GetMainConfigDN
      @base_config_dn
    end

    # Return the map of configuration modules (new copy)
    # (in the form $[ DN: $[ map_of_one_module] ])
    def GetConfigModules
      Builtins.eval(@config_modules)
    end

    # Return the map of templates (new copy)
    def GetTemplates
      Builtins.eval(@templates)
    end

    # Return list of default object classes for user or group
    # There is fixed list here, it is not saved anywhere (only in default
    # users plugin for LDAP objects)
    # @param [Hash] template used for differ if we need user or group list
    def GetDefaultObjectClasses(template)
      template = deep_copy(template)
      ocs = Builtins.maplist(Ops.get_list(template, "objectClass", [])) do |c|
        Builtins.tolower(c)
      end

      if Builtins.contains(ocs, "susegrouptemplate")
        return ["top", "posixGroup", "groupOfNames"]
        # TODO sometimes there is groupofuniquenames...
      elsif Builtins.contains(ocs, "suseusertemplate")
        return ["top", "posixAccount", "shadowAccount", "InetOrgPerson"]
      end
      []
    end

    # Creates default new map for a new object template
    # @param [String] cn cn of new template
    # @param [Array<String>] classes object classes of the object the template will belong to
    # @return template map
    def CreateTemplate(cn, classes)
      classes = deep_copy(classes)
      obj = { "cn" => [cn], "modified" => "added" }
      classes = Builtins.maplist(classes) { |c| Builtins.tolower(c) }
      if Builtins.contains(classes, "suseuserconfiguration")
        obj = Builtins.union(
          obj,
          Ops.get_map(@new_objects, "suseUserTemplate", {})
        )
      elsif Builtins.contains(classes, "susegroupconfiguration")
        obj = Builtins.union(
          obj,
          Ops.get_map(@new_objects, "suseGroupTemplate", {})
        )
      else
        Ops.set(obj, "objectClass", ["top", "suseObjectTemplate"])
      end

      obj = ConvertDefaultValues(obj)
      AddMissingAttributes(obj)
    end

    # Creates default new map for new configuration object
    # @param [String] class additional objectClass of new module (e.g.userConfiguration)
    # @return new module map
    def CreateModule(cn, _class)
      obj = {
        "cn"          => [cn],
        "objectClass" => Builtins.add(
          ["top", "suseModuleConfiguration"],
          _class
        ),
        "modified"    => "added"
      }
      # create some good defaults
      obj = Builtins.union(obj, Ops.get_map(@new_objects, _class, {}))
      templs = []
      templ_cn = ""
      default_base = ""
      if Builtins.tolower(_class) == "suseuserconfiguration"
        Builtins.foreach(
          Convert.convert(
            @templates,
            :from => "map",
            :to   => "map <string, map <string, any>>"
          )
        ) do |dn, t|
          cls = Builtins.maplist(Ops.get_list(t, "objectClass", [])) do |c|
            Builtins.tolower(c)
          end
          if Builtins.contains(cls, "suseusertemplate")
            templs = Builtins.add(templs, dn)
          end
        end
        templ_cn = "usertemplate" if templs == []
        default_base = Builtins.sformat("ou=people,%1", @base_dn)

        # for eDirectory, we have to use cleartext passwords!
        if @nds &&
            Builtins.tolower(Ops.get_string(obj, ["susePasswordHash", 0], "")) != "clear"
          Ops.set(obj, "susePasswordHash", ["clear"])
        end
      end
      if Builtins.tolower(_class) == "susegroupconfiguration"
        Builtins.foreach(
          Convert.convert(
            @templates,
            :from => "map",
            :to   => "map <string, map <string, any>>"
          )
        ) do |dn, t|
          cls = Builtins.maplist(Ops.get_list(t, "objectClass", [])) do |c|
            Builtins.tolower(c)
          end
          if Builtins.contains(cls, "susegrouptemplate")
            templs = Builtins.add(templs, dn)
          end
        end
        templ_cn = "grouptemplate" if templs == []
        default_base = Builtins.sformat("ou=group,%1", @base_dn)
      end
      # create proposal for defaultTemplate DN
      if templ_cn != ""
        tdn = Builtins.sformat("cn=%1,%2", templ_cn, @base_config_dn)
        i = 0
        while Ops.greater_than(Builtins.size(GetLDAPEntry(tdn)), 0)
          tdn = Builtins.sformat("cn=%1%2,%3", templ_cn, i, @base_config_dn)
          i = Ops.add(i, 1)
        end
        templs = [tdn]
      end
      Ops.set(obj, "suseDefaultTemplate", templs)
      Ops.set(obj, "suseDefaultBase", [default_base])
      Convert.convert(
        AddMissingAttributes(obj),
        :from => "map",
        :to   => "map <string, any>"
      )
    end

    # Searches for DN's of all objects defined by filter in given base ("sub")
    # @param [String] base search base
    # @param [String] search_filter if filter is empty, "objectClass=*" is used
    # @return [Array] of DN's (list of strings)
    def ReadDN(base, search_filter)
      all = Convert.convert(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"   => base,
            "filter"    => search_filter,
            "attrs"     => ["cn"], # not necessary, just not read all values
            "attrsOnly" => true,
            "scope"     => 2,
            "dn_only"   => true
          }
        ),
        :from => "any",
        :to   => "list <string>"
      )
      if all == nil
        LDAPErrorMessage("read", LDAPError())
        return []
      end
      deep_copy(all)
    end

    # Returns DN's of groups (objectClass=posixGroup) in given base
    # @param [String] base LDAP search base
    # @return groups (list of strings)
    def GetGroupsDN(base)
      @groups_dn = ReadDN(base, "objectClass=posixGroup") if @groups_dn == []
      deep_copy(@groups_dn)
    end

    # Check if given DN exist and if it points to some template
    # @param [String] dn
    # @return empty map if DN don't exist, template map if DN points
    #  to template object, nil if object with given DN is not template
    def CheckTemplateDN(dn)
      object = GetLDAPEntry(dn)
      return nil if object == nil
      if object == {}
        # OK, does not exist
        return {}
      end
      cls = Builtins.maplist(Ops.get_list(object, "objectClass", [])) do |c|
        Builtins.tolower(c)
      end
      if Builtins.contains(cls, "suseobjecttemplate")
        # exists as a template -> return object
        object = ConvertDefaultValues(object)
        Ops.set(object, "modified", "edited")
        return AddMissingAttributes(object)
      else
        # error message
        Popup.Error(
          _(
            "An object with the selected DN exists, but it is not a template object.\nSelect another one.\n"
          )
        )
        return nil
      end
    end

    # Save the edited map of configuration modules to global map
    def CommitConfigModules(modules)
      modules = deep_copy(modules)
      Builtins.foreach(
        Convert.convert(modules, :from => "map", :to => "map <string, map>")
      ) do |dn, modmap|
        if !Builtins.haskey(@config_modules, dn)
          Ops.set(@config_modules, dn, Builtins.eval(modmap))
          @ldap_modified = true
          next
        end
        # 'val' can be list (most time), map (default_values), string
        Builtins.foreach(
          Convert.convert(modmap, :from => "map", :to => "map <string, any>")
        ) do |attr, val|
          if Ops.get(@config_modules, [dn, attr]) != val
            Ops.set(@config_modules, [dn, attr], val)
            if !Builtins.haskey(modmap, "modified")
              Ops.set(@config_modules, [dn, "modified"], "edited")
            end
            @ldap_modified = true
            Builtins.y2debug("modified value: %1", val)
          end
        end
      end
      true
    end

    # Save the edited map of templates to global map
    def CommitTemplates(templs)
      templs = deep_copy(templs)
      Builtins.foreach(
        Convert.convert(templs, :from => "map", :to => "map <string, map>")
      ) do |dn, template|
        if !Builtins.haskey(@templates, dn)
          # dn changed
          Ops.set(@templates, dn, Builtins.eval(template))
          @ldap_modified = true
          next
        end
        # 'val' can be list (most time), map (default_values), string
        Builtins.foreach(
          Convert.convert(template, :from => "map", :to => "map <string, any>")
        ) do |attr, val|
          if Ops.get(@templates, [dn, attr]) != val
            Ops.set(@templates, [dn, attr], val)
            if !Builtins.haskey(template, "modified")
              Ops.set(@templates, [dn, "modified"], "edited")
            end
            @ldap_modified = true
            Builtins.y2debug("modified value: %1", val)
          end
        end
      end
      true
    end

    # Writes map of objects to LDAP
    # @param [Hash] objects map of objects to write. It is in the form:
    # $[ DN: (map) attribute_values]
    # @example TODO
    # @return error map (empty on success)
    def WriteToLDAP(objects)
      objects = deep_copy(objects)
      ret = {}
      Builtins.foreach(
        Convert.convert(objects, :from => "map", :to => "map <string, map>")
      ) do |dn, object|
        next if ret != {}
        action = Ops.get_string(object, "modified", "")
        if action != ""
          object = Builtins.remove(object, "modified")
        else
          next
        end
        # convert the default values back to the LDAP format
        if Builtins.haskey(object, "default_values")
          Ops.set(
            object,
            "suseDefaultValue",
            Builtins.maplist(Ops.get_map(object, "default_values", {})) do |key, val|
              Builtins.sformat("%1=%2", key, val)
            end
          )
          object = Builtins.remove(object, "default_values")
        end
        if action == "added"
          if !SCR.Write(path(".ldap.add"), { "dn" => dn }, object)
            ret = LDAPErrorMap()
          end
        end
        if action == "edited"
          if !SCR.Write(
              path(".ldap.modify"),
              { "dn" => dn, "check_attrs" => true },
              object
            )
            ret = LDAPErrorMap()
          end
        end
        if action == "renamed"
          arg_map = {
            "dn"          => Ops.get_string(object, "old_dn", dn),
            "check_attrs" => true
          }
          if Builtins.tolower(dn) !=
              Builtins.tolower(Ops.get_string(object, "old_dn", dn))
            Ops.set(arg_map, "new_dn", dn)
            Ops.set(arg_map, "deleteOldRDN", true)
            Ops.set(arg_map, "subtree", true)
          end
          if Builtins.haskey(object, "old_dn")
            object = Builtins.remove(object, "old_dn")
          end
          if !SCR.Write(path(".ldap.modify"), arg_map, object)
            ret = LDAPErrorMap()
          end
        end
        if action == "deleted"
          if Ops.get_string(object, "old_dn", dn) != dn
            dn = Ops.get_string(object, "old_dn", dn)
          end
          if !SCR.Write(path(".ldap.delete"), { "dn" => dn })
            ret = LDAPErrorMap()
          end
        end
      end
      deep_copy(ret)
    end

    # Writes map of objects to LDAP. Ask for password, when needed and
    # shows the error message when necessary.
    # @return success
    def WriteLDAP(objects)
      objects = deep_copy(objects)
      error = {}
      @bind_pass = LDAPAskAndBind(false) if @anonymous || @bind_pass == nil
      # nil means "canceled"
      if @bind_pass != nil
        error = WriteToLDAP(objects)
        if error != {}
          msg = Ops.get_string(error, "msg", "")
          if Ops.get_string(error, "server_msg", "") != ""
            msg = Ops.add(
              Ops.add(msg, "\n"),
              Ops.get_string(error, "server_msg", "")
            )
          end
          LDAPErrorMessage("write", msg)
        end
      end
      error == {} && @bind_pass != nil
    end

    # Modify also /etc/openldap/ldap.conf for the use of
    # ldap client utilities (like ldapsearch)
    # @return modified?
    def WriteOpenLdapConf
      return false if !Package.Installed("openldap2-client")
      uris = @server.split.map {|u| detect_uri_scheme + u }.join(' ')
      set_openldap('URI', uris)
      set_openldap('HOST', nil)
      set_openldap('BASE', @base_dn)

      if @ldaps || @ldap_tls
        set_openldap('TLS_REQCERT', @request_server_certificate)
        set_openldap('TLS_CACERTDIR', @tls_cacertdir.empty? ? nil : @tls_cacertdir)
        set_openldap('TLS_CACERT', @tls_cacertfile.empty? ? nil : @tls_cacertfile)
      else
        set_openldap('TLS_REQCERT', nil)
        set_openldap('TLS_CACERTDIR', nil)
        set_openldap('TLS_CACERT', nil)
      end

      Builtins.y2milestone("file /etc/openldap/ldap.conf was modified")
    end

    def set_openldap key, value
      SCR.Write(
        path(".etc.ldap_conf.v.\"/etc/openldap/ldap.conf\".#{key}"),
        value.nil? ? nil : [value]
      )
    end

    def read_openldap_config entry
      SCR.Read(path(".etc.ldap_conf.v.\"/etc/openldap/ldap.conf\".#{entry}"))
    end

    # Write updated /etc/sssd/sssd.conf file
    def WriteSSSDConfig
      if !FileUtils.Exists("/etc/sssd/sssd.conf")
        Builtins.y2warning(
          "file /etc/sssd/sssd.conf does not exists: not writing"
        )
        return false
      end

      sections = SCR.Dir(path(".etc.sssd_conf.section"))

      SCR.Write(path(".etc.sssd_conf.v.sssd.domains"), "default")

      # Create autofs section if autofs is enabled
      if @_start_autofs
        SCR.Write(
          Builtins.add(path(".etc.sssd_conf.section_comment"), "autofs"),
          "\n# Section created by YaST\n"
        )
      end

      # "The "services" setting should have the value "nss, pam" and "autofs" if autofs is enabled
      SCR.Write(path(".etc.sssd_conf.v.sssd.services"), @_start_autofs ? "nss,pam,autofs" : "nss,pam")

      # " Make sure that "filter_groups" and "filter_users" in the "[nss]" section contains "root".
      f_g = Convert.to_string(
        SCR.Read(path(".etc.sssd_conf.v.nss.filter_groups"))
      )
      f_g = "" if f_g == nil
      l = Convert.convert(
        Builtins.union(Builtins.splitstring(f_g, ","), ["root"]),
        :from => "list",
        :to   => "list <string>"
      )
      SCR.Write(
        path(".etc.sssd_conf.v.nss.filter_groups"),
        Builtins.mergestring(l, ",")
      )

      f_u = Convert.to_string(
        SCR.Read(path(".etc.sssd_conf.v.nss.filter_users"))
      )
      f_u = "" if f_u == nil
      l = Convert.convert(
        Builtins.union(Builtins.splitstring(f_u, ","), ["root"]),
        :from => "list",
        :to   => "list <string>"
      )
      SCR.Write(
        path(".etc.sssd_conf.v.nss.filter_users"),
        Builtins.mergestring(l, ",")
      )

      domain = Builtins.add(path(".etc.sssd_conf.v"), "domain/default")

      uri = Builtins.mergestring(
        Builtins.maplist(Builtins.splitstring(@server, " \t")) do |s|
          detect_uri_scheme + s
        end,
        ","
      )
      SCR.Write(Builtins.add(domain, "ldap_uri"), uri)
      SCR.Write(Builtins.add(domain, "ldap_search_base"), @base_dn)
      SCR.Write(Builtins.add(domain, "ldap_schema"), @sssd_ldap_schema)
      SCR.Write(Builtins.add(domain, "id_provider"), "ldap")
      SCR.Write(Builtins.add(domain, "ldap_user_uuid"), "entryuuid")
      SCR.Write(Builtins.add(domain, "ldap_group_uuid"), "entryuuid")

      SCR.Write(
        Builtins.add(domain, "ldap_id_use_start_tls"),
        @ldap_tls ? "True" : "False"
      )
      SCR.Write(
        Builtins.add(domain, "enumerate"),
        @sssd_enumerate ? "True" : "False"
      )
      SCR.Write(
        Builtins.add(domain, "cache_credentials"),
        @sssd_cache_credentials ? "True" : "False"
      )
      SCR.Write(
        Builtins.add(domain, "ldap_tls_cacertdir"),
        @tls_cacertdir == "" ? nil : @tls_cacertdir
      )
      SCR.Write(
        Builtins.add(domain, "ldap_tls_cacert"),
        @tls_cacertfile == "" ? nil : @tls_cacertfile
      )

      # remove the keys if their value is same as default (base_dn)
      SCR.Write(
        Builtins.add(domain, "ldap_user_search_base"),
        @nss_base_passwd != @base_dn && @nss_base_passwd != "" ? @nss_base_passwd : nil
      )
      SCR.Write(
        Builtins.add(domain, "ldap_group_search_base"),
        @nss_base_group != @base_dn && @nss_base_group != "" ? @nss_base_group : nil
      )
      SCR.Write(
        Builtins.add(domain, "ldap_autofs_search_base"),
        @nss_base_automount != @base_dn && @nss_base_automount != "" ? @nss_base_automount : nil
      )

      if !Builtins.contains(sections, "domain/default")
        SCR.Write(
          Builtins.add(path(".etc.sssd_conf.section_comment"), "domain/default"),
          "\n# Section created by YaST\n"
        )
      end

      # In a mixed Kerberos/LDAP setup the following changes are needed in the [domain/default] section:
      if @sssd_with_krb
        SCR.Write(Builtins.add(domain, "auth_provider"), "krb5")
        SCR.Write(Builtins.add(domain, "chpass_provider"), "krb5")

        SCR.Write(Builtins.add(domain, "krb5_realm"), @krb5_realm)
        SCR.Write(Builtins.add(domain, "krb5_server"), @krb5_server)
      else
        SCR.Write(Builtins.add(domain, "chpass_provider"), "ldap")
        SCR.Write(Builtins.add(domain, "auth_provider"), "ldap")
        SCR.Write(Builtins.add(domain, "krb5_realm"), nil)
        SCR.Write(Builtins.add(domain, "krb5_server"), nil)
      end

      if !SCR.Write(path(".etc.sssd_conf"), nil)
        Builtins.y2error("error writing sssd.conf file")
      end
      true
    end

    # If a file does not + entry, add it.
    # @param	is login allowed?
    # @return	success?
    def WritePlusLine(login)
      file = "/etc/passwd"
      what = "+::::::"
      what = "+::::::/sbin/nologin" if !login

      if !@passwd_read
        if !Convert.to_boolean(
            SCR.Execute(path(".passwd.init"), { "base_directory" => "/etc" })
          )
          Builtins.y2error("error: %1", SCR.Read(path(".passwd.error")))
          return false
        else
          @passwd_read = true
          @plus_lines_passwd = Convert.convert(
            SCR.Read(path(".passwd.passwd.pluslines")),
            :from => "any",
            :to   => "list <string>"
          )
        end
      end

      plus_lines = deep_copy(@plus_lines_passwd)

      if !Builtins.contains(plus_lines, what)
        plus_lines = Builtins.maplist(plus_lines) do |plus_line|
          next what if !login && plus_line == "+::::::"
          if login && Builtins.issubstring(plus_line, ":/sbin/nologin")
            next what
          end
          plus_line
        end
        if !Builtins.contains(plus_lines, what)
          plus_lines = Builtins.add(plus_lines, what)
        end

        if SCR.Write(path(".passwd.passwd.pluslines"), plus_lines)
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("/bin/cp %1 %1.YaST2save", file)
          )
          # empty map as a parameter means "use data you have read"
          if !SCR.Write(path(".passwd.users"), {})
            Report.Error(Message.ErrorWritingFile(file))
            return false
          end
        end
      end

      file = "/etc/shadow"
      what = "+"
      plus_lines = Convert.convert(
        SCR.Read(path(".passwd.shadow.pluslines")),
        :from => "any",
        :to   => "list <string>"
      )

      if !Builtins.contains(plus_lines, what) &&
          !Builtins.contains(plus_lines, "+::::::::")
        plus_lines = Builtins.add(plus_lines, what)

        if SCR.Write(path(".passwd.shadow.pluslines"), plus_lines)
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("/bin/cp %1 %1.YaST2save", file)
          )
          # empty map as a parameter means "use data you have read"
          if !SCR.Write(path(".passwd.shadow"), {})
            Report.Error(Message.ErrorWritingFile(file))
            return false
          end
        end
      end

      nil
    end

    # Check if references to other objects are correct;
    # create these objects if possible
    def CheckOrderOfCreation
      Builtins.foreach(
        Convert.convert(
          @config_modules,
          :from => "map",
          :to   => "map <string, map>"
        )
      ) do |dn, m|
        # 1. create suseDefaultBase object if not present
        base_dn = Ops.get_string(m, ["suseDefaultBase", 0], "")
        if base_dn != ""
          object = GetLDAPEntry(base_dn)
          if object == nil
            Builtins.y2warning("reference to nothing? (%1)", base_dn)
            Ops.set(@config_modules, dn, Builtins.remove(m, "suseDefaultBase"))
          elsif object == {}
            default_base = {
              "objectClass" => ["top", "organizationalUnit"],
              "modified"    => "added",
              "ou"          => get_cn(base_dn)
            }
            if @nds
              Ops.set(
                default_base,
                "acl",
                [
                  "3#subtree#[Public]#[All Attributes Rights]",
                  "1#subtree#[Public]#[Entry Rights]"
                ]
              )
            end
            if !ParentExists(base_dn) || !WriteLDAP({ base_dn => default_base })
              Builtins.y2error("%1 cannot be created", base_dn)
              Ops.set(
                @config_modules,
                dn,
                Builtins.remove(m, "suseDefaultBase")
              )
            end
          end
        end
        # 2. empty template must be created when there is a reference
        template_dn = Ops.get_string(m, ["suseDefaultTemplate", 0], "")
        if template_dn != "" && !Builtins.haskey(@templates, template_dn)
          object = GetLDAPEntry(template_dn)
          if Builtins.size(object) == 0
            Builtins.y2milestone("template does not exist, creating default...")
            t_class = Builtins.contains(
              Ops.get_list(m, "objectClass", []),
              "suseGroupConfiguration"
            ) ?
              "suseGroupTemplate" :
              "suseUserTemplate"
            template = { "modified" => "added", "cn" => get_cn(template_dn) }
            template = Builtins.union(
              template,
              Ops.get_map(@new_objects, t_class, {})
            )
            if !ParentExists(template_dn) ||
                !WriteLDAP({ template_dn => template })
              Builtins.y2error("%1 cannot be created", template_dn)
              Ops.set(
                @config_modules,
                dn,
                Builtins.remove(m, "suseDefaultTemplate")
              )
            end
          end
        end
      end

      # 3. check references to secondary groups in templates
      Builtins.foreach(
        Convert.convert(@templates, :from => "map", :to => "map <string, map>")
      ) do |dn, m|
        groups = Ops.get_list(m, "suseSecondaryGroup", [])
        if Ops.greater_than(Builtins.size(groups), 0)
          new_groups = []
          Builtins.foreach(
            Convert.convert(groups, :from => "list", :to => "list <string>")
          ) do |group|
            object = GetLDAPEntry(group)
            if object == nil || object == {}
              Builtins.y2warning("no such group %1;removing reference", group)
            else
              new_groups = Builtins.add(new_groups, group)
            end
          end
          Ops.set(m, "suseSecondaryGroup", new_groups)
        end
      end
      true
    end

    # create the default objects for users and groups
    def CreateDefaultLDAPConfiguration
      msg = ""
      if !@ldap_initialized
        msg = LDAPInit()
        if msg != ""
          LDAPErrorMessage("init", msg)
          return false
        end
      end
      if !@schema_initialized
        msg = InitSchema()
        LDAPErrorMessage("schema", msg) if msg != ""
      end
      if @bind_pass != nil && !@bound
        msg = LDAPBind(@bind_pass)
        if msg != ""
          LDAPErrorMessage("bind", msg)
          @bind_pass = nil
        end
      end
      # create base configuration object
      object = GetLDAPEntry(@base_config_dn)
      return false if object == nil
      if object == {}
        if ParentExists(@base_config_dn)
          config_object = {
            "objectClass" => ["top", "organizationalUnit"],
            "modified"    => "added",
            "ou"          => get_cn(@base_config_dn)
          }
          if @nds
            Ops.set(
              config_object,
              "acl",
              [
                "3#subtree#[Public]#[All Attributes Rights]",
                "1#subtree#[Public]#[Entry Rights]"
              ]
            )
          end
          if !WriteLDAP({ @base_config_dn => config_object })
            Builtins.y2error("%1 cannot be created", @base_config_dn)
          end
        end
        #TODO fail?
      end

      modules = {}
      templs = {}
      user_dn = get_dn("userconfiguration")
      group_dn = get_dn("groupconfiguration")

      ReadConfigModules() if @config_modules == {}

      # check which objects already exist...
      Builtins.foreach(
        Convert.convert(
          @config_modules,
          :from => "map",
          :to   => "map <string, map>"
        )
      ) do |dn, m|
        cl = Builtins.maplist(Ops.get_list(m, "objectClass", [])) do |c|
          Builtins.tolower(c)
        end
        user_dn = dn if Builtins.contains(cl, "suseuserconfiguration")
        group_dn = dn if Builtins.contains(cl, "susegroupconfiguration")
      end

      # create user configuration object
      if Ops.get_map(@config_modules, user_dn, {}) == {} &&
          GetLDAPEntry(user_dn) == {}
        Ops.set(
          modules,
          user_dn,
          CreateModule(get_cn(user_dn), "suseUserConfiguration")
        )
      end

      # create group configuration object
      if Ops.get_map(@config_modules, group_dn, {}) == {} &&
          GetLDAPEntry(group_dn) == {}
        Ops.set(
          modules,
          group_dn,
          CreateModule(get_cn(group_dn), "suseGroupConfiguration")
        )
      end

      CommitConfigModules(modules)
      modules = GetConfigModules()
      update_modules = false

      # create user template...
      template_dn = get_string(
        Ops.get_map(modules, user_dn, {}),
        "suseDefaultTemplate"
      )
      if Ops.get_list(modules, [user_dn, "suseDefaultTemplate"], []) == []
        template_dn = Ops.add("cn=usertemplate,", @base_config_dn)
        Ops.set(modules, [user_dn, "suseDefaultTemplate"], [template_dn])
        update_modules = true
      end

      if Ops.get_map(@templates, template_dn, {}) == {} &&
          GetLDAPEntry(template_dn) == {}
        Ops.set(
          templs,
          template_dn,
          CreateTemplate(get_cn(template_dn), ["suseUserConfiguration"])
        )
      end

      # group template...
      template_dn = get_string(
        Ops.get_map(modules, group_dn, {}),
        "suseDefaultTemplate"
      )
      if Ops.get_list(modules, [group_dn, "suseDefaultTemplate"], []) == []
        template_dn = Ops.add("cn=grouptemplate,", @base_config_dn)
        Ops.set(modules, [group_dn, "suseDefaultTemplate"], [template_dn])
        update_modules = true
      end

      if Ops.get_map(@templates, template_dn, {}) == {} &&
          GetLDAPEntry(template_dn) == {}
        Ops.set(
          templs,
          template_dn,
          CreateTemplate(get_cn(template_dn), ["suseGroupConfiguration"])
        )
      end

      CommitConfigModules(modules) if update_modules
      CommitTemplates(templs)
      true
    end

    # Check the server if it is NDS (novell directory service)
    def CheckNDS
      if !@ldap_initialized
        msg = LDAPInit()
        if msg != ""
          # no popup: see bug #132909
          return false
        end
      end

      vendor = Convert.to_list(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn" => "",
            "scope"   => 0,
            "attrs"   => ["vendorVersion", "vendorName"]
          }
        )
      )

      Builtins.y2debug("vendor: %1", vendor)
      output = Ops.get_map(vendor, 0, {})
      Builtins.foreach(output) do |attr, value|
        if Builtins.issubstring(Ops.get_string(value, 0, ""), "Novell")
          Builtins.y2debug("value: %1", Ops.get_string(value, 0, ""))
          @nds = true
        end
      end

      @nds_checked = true
      @nds
    end

    # Adpat passwd and group cache in /etc/nscd.conf
    # Caching should be disabled with sssd on
    # @param [Boolean] start_sssd if sssd will be started
    def WriteNscdCache(start_sssd)
      enable_cache = Convert.convert(
        SCR.Read(path(".etc.nscd_conf.v.enable-cache")),
        :from => "any",
        :to   => "list <string>"
      )
      enable_cache = Builtins.maplist(enable_cache) do |sect|
        l = Builtins.filter(Builtins.splitstring(sect, " \t")) do |part|
          part != ""
        end
        if Ops.get(l, 0, "") == "passwd" || Ops.get(l, 0, "") == "group"
          next Builtins.sformat(
            "%1\t\t%2",
            Ops.get(l, 0, ""),
            start_sssd ? "no" : "yes"
          )
        end
        sect
      end
      return false if enable_cache == [] || enable_cache == nil
      ret = SCR.Write(path(".etc.nscd_conf.v.enable-cache"), enable_cache)
      # ensure the changes are written
      ret = ret && SCR.Write(path(".etc.nscd_conf"), nil)
      ret
    end

    # Saves LDAP configuration.
    # @param [Proc] abort block for abort
    # @return [Symbol]
    def Write(abort)
      abort = deep_copy(abort)
      # progress caption
      caption = _("Writing LDAP Configuration...")
      no_of_steps = 4

      Progress.New(
        caption,
        " ",
        no_of_steps,
        [
          # progress stage label
          _("Stop services"),
          # progress stage label
          _("Update configuration files"),
          # progress stage label
          _("Start services"),
          # progress stage label
          _("Update configuration in LDAP directory")
        ],
        [
          # progress step label
          _("Stopping services..."),
          # progress step label
          _("Updating configuration files..."),
          # progress step label
          _("Starting services..."),
          # progress step label
          _("Updating configuration in LDAP directory..."),
          # final progress step label
          _("Finished")
        ],
        ""
      )

      # -------------------- stop services
      Progress.NextStage
      return :abort if Builtins.eval(abort)


      # initialize 'oes' value when Read was not called (bnc#670288)
      CheckOES() if Mode.autoinst

      ypbind_running = false

      if !@write_only
        ypbind_running = Service.Status("ypbind") == 0
        Service.Stop("ypbind")
      elsif @write_only && Mode.autoinst
        # Read existing nsswitch in autoinstallation mode
        Builtins.foreach(["passwd", "group", "passwd_compat", "group_compat"]) do |db|
          Ops.set(@nsswitch, db, Nsswitch.ReadDb(db))
        end
      end

      # -------------------- update config files
      Progress.NextStage
      return :abort if Builtins.eval(abort)

      if @modified
        # update ldap.conf
        WriteLdapConfEntry("host", nil)
        uri = Builtins.mergestring(
          Builtins.maplist(Builtins.splitstring(@server, " \t")) do |u|
            detect_uri_scheme + u
          end,
          " "
        )
        WriteLdapConfEntry("uri", uri)
        WriteLdapConfEntry("base", @base_dn)

        if @member_attribute != @old_member_attribute
          WriteLdapConfEntries(
            "nss_map_attribute",
            ["uniqueMember", @member_attribute]
          )
        end

        WriteOpenLdapConf()

        if @ldap_tls
          WriteLdapConfEntry("ssl", "start_tls")
        elsif @ldaps
          WriteLdapConfEntry("ssl", nil)
        else
          WriteLdapConfEntry("ssl", "no")
        end

        WriteLdapConfEntry(
          "tls_cacertdir",
          @tls_cacertdir == "" ? nil : @tls_cacertdir
        )
        WriteLdapConfEntry(
          "tls_cacertfile",
          @tls_cacertfile == "" ? nil : @tls_cacertfile
        )

        Pam.Set("mkhomedir", @mkhomedir)

        WriteLdapConfEntry("pam_password", @pam_password)

        # see bugs #suse37665 (pam_filter necessary), #118779 (not always)
        if ReadLdapConfEntry("pam_filter", "") == ""
          AddLdapConfEntry("pam_filter", "objectClass=posixAccount")
        end

        if @sssd
          WriteSSSDConfig()
        else
          # save the user and group bases
          @user_base = @base_dn
          @group_base = @base_dn

          WriteLdapConfEntry(
            "nss_base_passwd",
            @nss_base_passwd != @base_dn && @nss_base_passwd != "" ? @nss_base_passwd : nil
          )
          WriteLdapConfEntry(
            "nss_base_shadow",
            @nss_base_shadow != @base_dn && @nss_base_shadow != "" ? @nss_base_shadow : nil
          )
          WriteLdapConfEntry(
            "nss_base_group",
            @nss_base_group != @base_dn && @nss_base_group != "" ? @nss_base_group : nil
          )
        end

        # default value is 'yes'
        WriteLdapConfEntry(
          "tls_checkpeer",
          @tls_checkpeer == "yes" ? nil : @tls_checkpeer
        )
        WriteNscdCache(@start && @sssd) unless @oes
      end
      if @start # ldap used for authentication
        # ---------- correct pam_password value for Novell eDirectory
        if @pam_password != "nds" && @expert_ui
          CheckNDS() if !@nds_checked && !Mode.autoinst
          @pam_password = "nds" if @nds
          WriteLdapConfEntry("pam_password", @pam_password)
        end


        if !@oes
          if @sssd
            Pam.Add("sss")
            # Add "sss" to the passwd and group databases in nsswitch.conf

            Builtins.foreach(["passwd", "group"]) do |db|
              # replace 'ldap' with sss
              Ops.set(
                @nsswitch,
                db,
                Builtins.filter(Ops.get_list(@nsswitch, db, [])) do |v|
                  v != "ldap"
                end
              )
              Ops.set(
                @nsswitch,
                db,
                Builtins.union(Ops.get_list(@nsswitch, db, []), ["sss"])
              )
              Nsswitch.WriteDb(
                db,
                Convert.convert(
                  Ops.get(@nsswitch, db) { ["sss"] },
                  :from => "any",
                  :to   => "list <string>"
                )
              )
              # remove 'ldap' from _compat entries
              new_db = Ops.add(db, "_compat")
              Ops.set(
                @nsswitch,
                new_db,
                Builtins.filter(Ops.get_list(@nsswitch, new_db, [])) do |v|
                  v != "ldap"
                end
              )
              Nsswitch.WriteDb(new_db, Ops.get_list(@nsswitch, new_db, []))
            end
            # remove ldap entries from ldap-only db's
            Builtins.foreach(["services", "netgroup", "aliases"]) do |db|
              db_l = Builtins.filter(Nsswitch.ReadDb(db)) { |v| v != "ldap" }
              db_l = ["files"] if db_l == []
              Nsswitch.WriteDb(db, db_l)
            end

            if Pam.Enabled("krb5")
              Builtins.y2milestone(
                "configuring 'sss', so 'krb5' will be removed"
              )
              Pam.Remove("ldap-account_only")
              Pam.Remove("krb5")
            end
            Pam.Remove("ldap")
          else
            # pam settigs
            if Pam.Enabled("krb5")
              # If kerberos is used for authentication we configure
              # pam_ldap in a way that we use only the account checking.
              # Other configuration would mess up password changing
              Pam.Add("ldap-account_only")
            else
              Pam.Add("ldap")
            end
            # sss was removed, using pam_ldap (bnc#680184)
            Pam.Remove("sss") if Pam.Enabled("sss")

            # modify sources in /etc/nsswitch.conf
            Nsswitch.WriteDb("passwd", ["compat"])
            Nsswitch.WriteDb(
              "passwd_compat",
              Convert.convert(
                Builtins.union(
                  Ops.get_list(@nsswitch, "passwd_compat", []),
                  ["ldap"]
                ),
                :from => "list",
                :to   => "list <string>"
              )
            )

            Builtins.foreach(["services", "netgroup", "aliases"]) do |db|
              Nsswitch.WriteDb(db, ["files", "ldap"])
            end

            if Builtins.contains(Ops.get_list(@nsswitch, "group", []), "compat") &&
                Builtins.contains(
                  Ops.get_list(@nsswitch, "group_compat", []),
                  "ldap"
                )
              Builtins.y2milestone("group_compat present, not changing")
            else
              Nsswitch.WriteDb("group", ["files", "ldap"])
            end
          end

          Nsswitch.Write
        end
        Autologin.Write(@write_only)
      elsif !@oes # ldap is not used
        Builtins.foreach(["passwd", "group"]) do |db|
          new_db = Ops.add(db, "_compat")
          Ops.set(
            @nsswitch,
            db,
            Builtins.filter(Ops.get_list(@nsswitch, db, [])) do |v|
              v != "ldap" && v != "sss"
            end
          )
          if Ops.get_list(@nsswitch, db, []) == [] ||
              Ops.get_list(@nsswitch, db, []) == ["files"]
            Ops.set(@nsswitch, db, ["compat"])
          end
          Ops.set(
            @nsswitch,
            new_db,
            Builtins.filter(Ops.get_list(@nsswitch, new_db, [])) do |v|
              v != "ldap" && v != "sss"
            end
          )
          Nsswitch.WriteDb(
            db,
            Convert.convert(
              Ops.get(@nsswitch, db) { ["compat"] },
              :from => "any",
              :to   => "list <string>"
            )
          )
          Nsswitch.WriteDb(new_db, Ops.get_list(@nsswitch, new_db, []))
        end
        Builtins.foreach(["services", "netgroup", "aliases"]) do |db|
          db_l = Builtins.filter(Nsswitch.ReadDb(db)) do |v|
            v != "ldap" && v != "sss"
          end
          db_l = ["files"] if db_l == []
          Nsswitch.WriteDb(db, db_l)
        end

        Nsswitch.Write

        if Pam.Enabled("ldap")
          Pam.Remove("ldap")
        elsif Pam.Enabled("ldap-account_only")
          Pam.Remove("ldap-account_only")
        end
        Pam.Remove("sss") if Pam.Enabled("sss")
      end


      # write the changes in /etc/ldap.conf and /etc/openldap/ldap.conf now
      if !SCR.Write(path(".etc.ldap_conf"), nil)
        Builtins.y2error("error writing ldap.conf file")
      end
      SCR.UnmountAgent(path(".etc.ldap_conf")) if Stage.cont

      # write sysconfig values
      SCR.Write(
        path(".sysconfig.ldap.FILE_SERVER"),
        @file_server ? "yes" : "no"
      )

      SCR.Write(path(".sysconfig.ldap.BASE_CONFIG_DN"), @base_config_dn)

      SCR.Write(path(".sysconfig.ldap.BIND_DN"), @bind_dn)

      # write the changes in /etc/sysconfig/ldap now
      if !SCR.Write(path(".sysconfig.ldap"), nil)
        Builtins.y2error("error writing /etc/sysconfig/ldap")
      end

      if @_autofs_allowed
        if Nsswitch.WriteAutofs(@start && @_start_autofs, @sssd ? "sss" : "ldap")
          if @_start_autofs
            Service.Adjust("autofs", "enable")
          else
            Service.Adjust("autofs", "disable")
          end
        end
      end

      WritePlusLine(@login_enabled) if @start && !@sssd

      # -------------------- start services
      Progress.NextStage
      return :abort if Builtins.eval(abort)

      if !@write_only
        if @sssd && @start
          # enable the sssd daemon to be started at bootup
          Service.Adjust("sssd", "enable")
          if Service.Status("sssd") == 0
            Service.Restart("sssd")
          else
            Service.Start("sssd")
          end
        else
          Service.Stop("sssd")
          Service.Adjust("sssd", "disable")
        end

        if Package.Installed("nscd") && @modified
          SCR.Execute(path(".target.bash"), "/usr/sbin/nscd -i passwd")
          SCR.Execute(path(".target.bash"), "/usr/sbin/nscd -i group")
          Service.RunInitScript("nscd", "try-restart")
        end

        if Package.Installed("zmd") && Service.Status("novell-zmd") == 0
          Service.RunInitScript("novell-zmd", "try-restart")
        end

        Service.Restart("ypbind") if ypbind_running

        Service.Restart("sshd") if @restart_sshd

        if @_autofs_allowed
          Service.Stop("autofs")

          Service.Start("autofs") if @_start_autofs
        end
        # after finish of 2nd stage, restart running services (bnc#395402)
        if @start && Stage.cont
          services = []
          Builtins.foreach(["dbus", "haldaemon"]) do |service|
            if Service.Status(service) == 0
              services = Builtins.add(services, service)
            end
          end
          if Ops.greater_than(Builtins.size(services), 0)
            Builtins.y2milestone("services %1 will be restarted", services)
            SCR.Write(
              path(".target.string"),
              Ops.add(Directory.vardir, "/restart_services"),
              Ops.add(Builtins.mergestring(services, "\n"), "\n")
            )
          end
        end
      elsif @sssd
        # enable the sssd daemon to be started at bootup
        Service.Adjust("sssd", @start ? "enable" : "disable")
      end

      # -------------------- write settings to LDAP
      Progress.NextStage
      return :abort if Builtins.eval(abort)

      # ------------------------------ create the LDAP configuration (#40484)
      ldap_ok = true
      if @create_ldap && !Mode.autoinst
        ldap_ok = CreateDefaultLDAPConfiguration()
      end

      if @ldap_modified && ldap_ok
        CheckOrderOfCreation()

        if WriteLDAP(@templates) && WriteLDAP(@config_modules)
          @ldap_modified = false
        end
      end

      # final stage
      Progress.NextStage

      # unbind is done in agent destructor
      # ldap-client can be called more times from users module so we
      # will have to know it is necessary to bind again
      @bound = false
      if @modified
        @ldap_initialized = false
        @old_server = @server
        @old_base_dn = @base_dn
      end
      if @ldap_modified
        @config_modules = {}
        @templates = {}
      end

      # now clear the initial default values, so next time Read will read
      # real values
      if Stage.cont && Ops.greater_than(Builtins.size(@initial_defaults), 0)
        first_s = GetFirstServer(@server)
        if @start && ldap_ok &&
            @base_dn == Ops.get_string(@initial_defaults, "ldap_domain", "") &&
            (first_s == Ops.get_string(@initial_defaults, "ldap_server", "") ||
              DNS.IsHostLocal(first_s))
          @initial_defaults_used = true
          Builtins.y2milestone("initial defaults were used")
        end
        @initial_defaults = {}
      end

      :next
    end

    # wrapper for Write, without abort block
    def WriteNow
      abort = lambda { false }

      needed_packages = @sssd ? @sssd_packages : @pam_nss_packages
      if @sssd_with_krb
        needed_packages = Convert.convert(
          Builtins.union(needed_packages, @kerberos_packages),
          :from => "list",
          :to   => "list <string>"
        )
      end

      if @_start_autofs && !Package.Installed("autofs")
        needed_packages = Builtins.add(needed_packages, "autofs")
      end

      if @start && !Package.InstalledAll(needed_packages)
        if !Package.InstallAll(needed_packages)
          Report.Error(Message.FailedToInstallPackages)
        end
        @start = false
        @_start_autofs = false
      end
      # during CLI call nss_base_* are not edited: adapt them to new base DN
      if @old_base_dn != @base_dn && @nss_base_passwd == @old_base_dn
        @nss_base_passwd = @base_dn
        @nss_base_shadow = @base_dn
        @nss_base_group = @base_dn
        @nss_base_automount = @base_dn
      end

      Write(abort) == :next
    end


    # Check if base config DN belongs to some existing object and offer
    # creating it if necessary
    def CheckBaseConfig(dn)
      object = GetLDAPEntry(dn)
      return false if object == nil
      if object == {}
        # yes/no popup, %1 is value of DN
        if !@use_gui ||
            Popup.YesNo(
              Builtins.sformat(
                _(
                  "No entry with DN '%1'\nexists on the LDAP server. Create it now?\n"
                ),
                dn
              )
            )
          return false if !ParentExists(dn)
          config_object = {
            "objectClass" => ["top", "organizationalUnit"],
            "modified"    => "added",
            "ou"          => get_cn(dn)
          }
          if @nds
            Ops.set(
              config_object,
              "acl",
              [
                "3#subtree#[Public]#[All Attributes Rights]",
                "1#subtree#[Public]#[Entry Rights]"
              ]
            )
          end
          return WriteLDAP({ dn => config_object })
        end
        return false
      end
      true
    end

    # Set the value of bind_pass variable
    # @param [String] pass new password valure
    def SetBindPassword(pass)
      @bind_pass = pass

      nil
    end

    # Set the value of 'anonymous' variable (= bind without password)
    # @param [Boolean] anon new value
    def SetAnonymous(anon)
      @anonymous = anon

      nil
    end

    # Set the value of 'use_gui' variable (= show error popups)
    # @param [Boolean] gui new value
    def SetGUI(gui)
      @use_gui = gui

      nil
    end

    # Set the value of restart_sshd (= restart sshd during write)
    def RestartSSHD(restart)
      @restart_sshd = restart

      nil
    end

    publish :variable => :use_gui, :type => "boolean"
    publish :variable => :base_config_dn, :type => "string"
    publish :function => :get_rdn, :type => "string (string)", :private => true
    publish :function => :get_cn, :type => "string (string)", :private => true
    publish :function => :get_dn, :type => "string (string)", :private => true
    publish :function => :get_new_dn, :type => "string (string, string)", :private => true
    publish :function => :get_string, :type => "string (map, string)", :private => true
    publish :variable => :required_packages, :type => "list <string>"
    publish :variable => :write_only, :type => "boolean"
    publish :variable => :start, :type => "boolean"
    publish :variable => :old_start, :type => "boolean"
    publish :variable => :nis_available, :type => "boolean"
    publish :variable => :_autofs_allowed, :type => "boolean"
    publish :variable => :_start_autofs, :type => "boolean"
    publish :variable => :login_enabled, :type => "boolean"
    publish :variable => :member_attribute, :type => "string"
    publish :variable => :old_member_attribute, :type => "string"
    publish :variable => :server, :type => "string"
    publish :variable => :old_server, :type => "string"
    publish :variable => :modified, :type => "boolean"
    publish :variable => :openldap_modified, :type => "boolean"
    publish :variable => :base_dn, :type => "string", :private => true
    publish :variable => :old_base_dn, :type => "string", :private => true
    publish :variable => :base_dn_changed, :type => "boolean", :private => true
    publish :variable => :ldap_tls, :type => "boolean"
    publish :variable => :ldaps, :type => "boolean"
    publish :variable => :request_server_certificate, :type => "string"
    publish :variable => :tls_cacertdir, :type => "string"
    publish :variable => :tls_cacertfile, :type => "string"
    publish :variable => :tls_checkpeer, :type => "string"
    publish :variable => :pam_password, :type => "string"
    publish :variable => :plus_lines_passwd, :type => "list <string>"
    publish :variable => :default_port, :type => "integer"
    publish :variable => :file_server, :type => "boolean"
    publish :variable => :nss_base_passwd, :type => "string"
    publish :variable => :nss_base_shadow, :type => "string"
    publish :variable => :nss_base_group, :type => "string"
    publish :variable => :nss_base_automount, :type => "string"
    publish :variable => :user_base, :type => "string"
    publish :variable => :group_base, :type => "string"
    publish :variable => :autofs_base, :type => "string"
    publish :variable => :nsswitch, :type => "map", :private => true
    publish :variable => :anonymous, :type => "boolean"
    publish :variable => :bind_pass, :type => "string"
    publish :variable => :bind_dn, :type => "string"
    publish :variable => :current_module_dn, :type => "string"
    publish :variable => :current_template_dn, :type => "string"
    publish :variable => :create_ldap, :type => "boolean"
    publish :variable => :nds, :type => "boolean"
    publish :variable => :tls_switched_off, :type => "boolean"
    publish :variable => :nds_checked, :type => "boolean", :private => true
    publish :variable => :oes, :type => "boolean", :private => true
    publish :variable => :expert_ui, :type => "boolean", :private => true
    publish :variable => :new_objects, :type => "map"
    publish :variable => :base_template_dn, :type => "string"
    publish :variable => :ldap_modified, :type => "boolean"
    publish :variable => :config_modules, :type => "map"
    publish :variable => :templates, :type => "map"
    publish :variable => :bound, :type => "boolean"
    publish :variable => :groups_dn, :type => "list"
    publish :variable => :object_classes, :type => "map"
    publish :variable => :attr_types, :type => "map"
    publish :variable => :hash_schemas, :type => "list"
    publish :variable => :available_config_modules, :type => "list <string>"
    publish :variable => :initial_defaults, :type => "map"
    publish :variable => :initial_defaults_used, :type => "boolean"
    publish :variable => :schema_initialized, :type => "boolean"
    publish :variable => :ldap_initialized, :type => "boolean"
    publish :variable => :tls_when_initialized, :type => "boolean"
    publish :variable => :read_settings, :type => "boolean"
    publish :variable => :restart_sshd, :type => "boolean"
    publish :variable => :passwd_read, :type => "boolean", :private => true
    publish :variable => :mkhomedir, :type => "boolean"
    publish :variable => :pam_nss_packages, :type => "list <string>"
    publish :variable => :sssd_packages, :type => "list <string>"
    publish :variable => :kerberos_packages, :type => "list <string>"
    publish :variable => :sssd, :type => "boolean"
    publish :variable => :sssd_cache_credentials, :type => "boolean"
    publish :variable => :sssd_with_krb, :type => "boolean"
    publish :variable => :krb5_realm, :type => "string"
    publish :variable => :krb5_server, :type => "string"
    publish :variable => :sssd_ldap_schema, :type => "string"
    publish :variable => :sssd_enumerate, :type => "boolean"
    publish :variable => :ldap_error_hints, :type => "map"
    publish :function => :BaseDNChanged, :type => "boolean ()"
    publish :function => :DomainChanged, :type => "boolean ()"
    publish :function => :GetBaseDN, :type => "string ()"
    publish :function => :GetDomain, :type => "string ()"
    publish :function => :SetBaseDN, :type => "void (string)"
    publish :function => :SetDomain, :type => "void (string)"
    publish :function => :SetDefaults, :type => "boolean (map)"
    publish :function => :SetReadSettings, :type => "boolean (boolean)"
    publish :function => :AutoPackages, :type => "map ()"
    publish :function => :Set, :type => "void (map)"
    publish :function => :Import, :type => "boolean (map)"
    publish :function => :Export, :type => "map ()"
    publish :function => :Summary, :type => "string ()"
    publish :function => :ShortSummary, :type => "string ()"
    publish :function => :ReadKrb5Conf, :type => "boolean ()"
    publish :function => :ReadLdapConfEntry, :type => "string (string, string)", :private => true
    publish :function => :ReadLdapConfEntries, :type => "list <string> (string)", :private => true
    publish :function => :WriteLdapConfEntry, :type => "void (string, string)", :private => true
    publish :function => :WriteLdapConfEntries, :type => "void (string, list <string>)", :private => true
    publish :function => :AddLdapConfEntry, :type => "void (string, string)", :private => true
    publish :function => :CheckOES, :type => "boolean ()"
    publish :function => :uri2servers, :type => "string (string)", :private => true
    publish :function => :ReadLdapHosts, :type => "string ()"
    publish :function => :Read, :type => "boolean ()"
    publish :function => :LDAPErrorMessage, :type => "void (string, string)"
    publish :function => :LDAPErrorMap, :type => "map ()"
    publish :function => :LDAPError, :type => "string ()"
    publish :function => :GetBindDN, :type => "string ()"
    publish :function => :GetFirstServer, :type => "string (string)"
    publish :function => :GetFirstPort, :type => "integer (string)"
    publish :function => :LDAPClose, :type => "boolean ()"
    publish :function => :LDAPInit, :type => "string ()"
    publish :function => :LDAPInitArgs, :type => "map (map)"
    publish :function => :CheckLDAPConnection, :type => "boolean (map)"
    publish :function => :ConnectWithoutTLS, :type => "boolean (map)"
    publish :function => :LDAPInitWithTLSCheck, :type => "string (map)"
    publish :function => :LDAPBind, :type => "string (string)"
    publish :function => :GetLDAPPassword, :type => "string (boolean)"
    publish :function => :LDAPAskAndBind, :type => "string (boolean)"
    publish :function => :SingleValued, :type => "boolean (string)"
    publish :function => :AttributeDescription, :type => "string (string)"
    publish :function => :ObjectClassExists, :type => "boolean (string)"
    publish :function => :ObjectClassStructural, :type => "boolean (string)"
    publish :function => :GetAllAttributes, :type => "list (string)"
    publish :function => :GetRequiredAttributes, :type => "list <string> (string)"
    publish :function => :GetOptionalAttributes, :type => "list <string> (string)"
    publish :function => :GetObjectAttributes, :type => "list (list)"
    publish :function => :AddMissingAttributes, :type => "map (map)"
    publish :function => :InitSchema, :type => "string ()"
    publish :function => :ConvertDefaultValues, :type => "map (map)"
    publish :function => :ReadTemplates, :type => "string ()"
    publish :function => :ReadConfigModules, :type => "string ()"
    publish :function => :GetLDAPEntry, :type => "map (string)"
    publish :function => :ParentExists, :type => "boolean (string)"
    publish :function => :GetMainConfigDN, :type => "string ()"
    publish :function => :GetConfigModules, :type => "map ()"
    publish :function => :GetTemplates, :type => "map ()"
    publish :function => :GetDefaultObjectClasses, :type => "list (map)"
    publish :function => :CreateTemplate, :type => "map (string, list <string>)"
    publish :function => :CreateModule, :type => "map <string, any> (string, string)"
    publish :function => :ReadDN, :type => "list <string> (string, string)"
    publish :function => :GetGroupsDN, :type => "list (string)"
    publish :function => :CheckTemplateDN, :type => "map (string)"
    publish :function => :CommitConfigModules, :type => "boolean (map)"
    publish :function => :CommitTemplates, :type => "boolean (map)"
    publish :function => :WriteToLDAP, :type => "map (map)"
    publish :function => :WriteLDAP, :type => "boolean (map)"
    publish :function => :WriteOpenLdapConf, :type => "void ()"
    publish :function => :WriteSSSDConfig, :type => "boolean ()"
    publish :function => :WritePlusLine, :type => "boolean (boolean)"
    publish :function => :CheckOrderOfCreation, :type => "boolean ()"
    publish :function => :CreateDefaultLDAPConfiguration, :type => "boolean ()", :private => true
    publish :function => :CheckNDS, :type => "boolean ()"
    publish :function => :WriteNscdCache, :type => "boolean (boolean)", :private => true
    publish :function => :Write, :type => "symbol (block <boolean>)"
    publish :function => :WriteNow, :type => "boolean ()"
    publish :function => :CheckBaseConfig, :type => "boolean (string)"
    publish :function => :SetBindPassword, :type => "void (string)"
    publish :function => :SetAnonymous, :type => "void (boolean)"
    publish :function => :SetGUI, :type => "void (boolean)"
    publish :function => :RestartSSHD, :type => "void (boolean)"
    publish :function => :use_secure_connection, :type => "boolean ()"
  end

  Ldap = LdapClass.new
  Ldap.main
end
