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
require 'ui/dialog'
require 'authserver/dir/ds389'
require 'authserver/dir/client'
require 'authserver/krb/mit'
Yast.import 'UI'
Yast.import 'Icon'
Yast.import 'Label'
Yast.import 'Popup'

# NewKrbInst dialog collects setup details as input and eventually creates/replaces a new Kerberos server instance.
class NewKrbInst < UI::Dialog
  include Yast
  include UIShortcuts
  include I18n
  include Logger

  def initialize
    super
    textdomain 'authserver'
  end

  def dialog_options
    Opt(:decorated)
  end

  def finish_handler
    finish_dialog(:next)
  end

  def dialog_content
    VBox(
        Left(Heading(_('Create New Kerberos Instance'))),
        HBox(
            VBox(
                Frame(_('General options (mandatory)'),
                      VBox(
                          InputField(Id(:fqdn), Opt(:hstretch), _('Fully qualified domain name (e.g. krb.example.net)'), ''),
                          InputField(Id(:realm), Opt(:hstretch), _('Realm name (e.g. EXAMPLE.NET)'), ''),
                      ),
                ),
                Frame(_('389 directory server connectivity (mandatory)'),
                      VBox(
                          InputField(Id(:dir_addr), Opt(:hstretch), _('Directory server address (e.g. dir.example.net)'), ''),
                          InputField(Id(:dir_inst), Opt(:hstretch), _('Directory instance name'), ''),
                          InputField(Id(:dir_suffix), Opt(:hstretch), _('Directory suffix (e.g. dc=example,dc=net)'), ''),
                          InputField(Id(:container_dn), Opt(:hstretch), _('Container DN of existing users (e.g. ou=users,dc=example,dc=net)'), ''),
                          InputField(Id(:dm_dn), Opt(:hstretch), _('Directory manager DN (e.g. cn=root)'), ''),
                          Password(Id(:dm_pass), Opt(:hstretch), _('Directory manager password'), ''),
                      ),
                ),
            ),
            Frame(_('Security options (mandatory)'),
                  VBox(
                      Password(Id(:master_pass), Opt(:hstretch), _('Kerberos database master password'), ''),
                      Password(Id(:master_pass_repeat), Opt(:hstretch), _('Repeat master password'), ''),
                      InputField(Id(:kdc_dn), Opt(:hstretch), _('KDC account to create (e.g. cn=krbkdc)'), ''),
                      Password(Id(:kdc_pass), Opt(:hstretch), _('Password of KDC account'), ''),
                      Password(Id(:kdc_pass_repeat), Opt(:hstretch), _('Repeat password of KDC account'), ''),
                      InputField(Id(:admin_dn), Opt(:hstretch), _('Admin account to create (e.g. cn=krbadm)'), ''),
                      Password(Id(:admin_pass), Opt(:hstretch), _('Password of admin account'), ''),
                      Password(Id(:admin_pass_repeat), Opt(:hstretch), _('Repeat password of admin account'), ''),
                  ),
            ),
        ),
        HBox(
            PushButton(Id(:help), Label.HelpButton),
            PushButton(Id(:ok), Label.OKButton),
            PushButton(Id(:finish), Label.CancelButton),
        ),
        ReplacePoint(Id(:busy), Empty()),
    )
  end

  def help_handler
    Popup.LongMessage(_('Kerberos is a popular technology for providing authentication services to internal network.
Before setting up Kerberos, please make sure that you have administration rights in a 389 directory server.
You may set one up using "New Directory Instance" program.'))
  end

  def ok_handler
    fqdn = UI.QueryWidget(Id(:fqdn), :Value)
    realm = UI.QueryWidget(Id(:realm), :Value)

    dir_addr = UI.QueryWidget(Id(:dir_addr), :Value)
    dir_inst = UI.QueryWidget(Id(:dir_inst), :Value)
    dir_suffix = UI.QueryWidget(Id(:dir_suffix), :Value)
    container_dn = UI.QueryWidget(Id(:container_dn), :Value)
    dm_dn = UI.QueryWidget(Id(:dm_dn), :Value)
    dm_pass = UI.QueryWidget(Id(:dm_pass), :Value)

    master_pass = UI.QueryWidget(Id(:master_pass), :Value)
    master_pass_repeat = UI.QueryWidget(Id(:master_pass_repeat), :Value)
    kdc_dn_prefix = UI.QueryWidget(Id(:kdc_dn), :Value)
    kdc_pass = UI.QueryWidget(Id(:kdc_pass), :Value)
    kdc_pass_repeat = UI.QueryWidget(Id(:kdc_pass_repeat), :Value)
    admin_dn_prefix = UI.QueryWidget(Id(:admin_dn), :Value)
    admin_pass = UI.QueryWidget(Id(:admin_pass), :Value)
    admin_pass_repeat = UI.QueryWidget(Id(:admin_pass_repeat), :Value)

    # Validate input
    if fqdn == '' || realm == '' ||
        dir_addr == '' || dir_inst == '' || dir_suffix == '' || container_dn == '' ||
        master_pass == '' || master_pass_repeat == '' ||
        dm_dn == '' || dm_pass == '' ||
        kdc_dn_prefix == '' || kdc_pass == '' || kdc_pass_repeat == '' ||
        admin_dn_prefix == '' || admin_pass == '' || admin_pass_repeat == ''
      Popup.Error(_('Please complete setup details. All input fields are mandatory.'))
      return
    end
    if kdc_pass != kdc_pass_repeat
      Popup.Error(_('Two KDC password entries do not match.'))
      return
    end
    if admin_pass != admin_pass_repeat
      Popup.Error(_('Two admin password entries do not match.'))
      return
    end
    if master_pass != master_pass_repeat
      Popup.Error(_('Two master password entries do not match.'))
      return
    end
    if MITKerberos.is_configured
      if !Popup.YesNo(_('You appear to have altered Kerberos configuration.
Continue to use this software will completely overwrite your configuration.
Do you still wish to continue?'))
        return
      end
    end

    UI.ReplaceWidget(Id(:busy), Label(_('Installing new instance, this may take a minute or two.')))

    begin
      MITKerberos.install_pkgs
      # Enable kerberos schema on 389
      if !DS389.enable_krb_schema(dir_inst)
        Popup.Error(_('Failed to enable Kerberos schema.'))
        raise
      end

      # Create kerberos users and give them password in LDAP
      kdc_dn = kdc_dn_prefix+','+dir_suffix
      admin_dn = admin_dn_prefix+','+dir_suffix
      ldap = LDAPClient.new('ldaps://'+fqdn, dm_dn, dm_pass)
      out, ok = ldap.create_person(kdc_dn_prefix, 'Kerberos KDC Connection', dir_suffix)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create Kerberos KDC connection user! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end
      out, ok = ldap.change_password(kdc_dn,kdc_pass)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create Kerberos KDC connection user! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end
      out, ok = ldap.create_person(admin_dn_prefix, 'Kerberos Administration Connection', dir_suffix)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create Kerberos administration user! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end
      out, ok = ldap.change_password(admin_dn,admin_pass)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create Kerberos KDC administration user! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end

      # Create password file for KDC
      pass_file_path = '/etc/dirsrv/kdc'
      out, ok = MITKerberos.save_password_into_file(kdc_dn, kdc_pass, pass_file_path)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create password file! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end
      out, ok = MITKerberos.save_password_into_file(admin_dn, admin_pass, pass_file_path)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to create password file! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end

      # Make common and KDC configuration files
      open('/etc/krb5.conf', 'w') {|fh|
        fh.puts(MITKerberos.gen_common_conf(realm, fqdn))
      }
      open('/var/lib/kerberos/krb5kdc/kdc.conf', 'w') {|fh|
        fh.puts(MITKerberos.gen_kdc_conf(realm, kdc_dn, admin_dn, container_dn, pass_file_path, dir_addr))
      }

      # Give kerberos rights to modify directory
      out, ok = ldap.aci_allow_modify(container_dn, 'kerberos-admin', admin_dn)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to modify directory permission! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end
      out, ok = ldap.aci_allow_modify(container_dn, 'kerberos-kdc', kdc_dn)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to modify directory permission! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end

      # Let kerberos do its initialisation sequence
      out, ok = MITKerberos.init_dir(dir_addr, dm_dn, dm_pass, realm, container_dn, master_pass)
      MITKerberos.append_to_log(out)
      if !ok
        Popup.Error(_('Kerberos initialisation failure! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
        raise
      end

      # Kerberos may finally start
      if !MITKerberos.restart_kdc
        Popup.Error(_('Failed to start KDC, please inspect the journal of krb5kdc.service'))
        raise
      end
      if !MITKerberos.restart_kadmind
        Popup.Error(_('Failed to start kadmind, please inspect the journal of kadmind.service'))
        raise
      end

      UI.ReplaceWidget(Id(:busy), Empty())
      Popup.Message(_('New instance has been set up! Log output may be found in %s') % [KDC_SETUP_LOG_PATH])
      finish_dialog(:next)
    rescue Exception => e
      Popup.Error('There was an error ' + e.message)
      # Give user an opportunity to correct mistake
      UI.ReplaceWidget(Id(:busy), Empty())
    end
  end
end