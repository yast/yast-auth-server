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
#               William Brown <wbrown@suse.de>

require 'yast'
require 'ui/dialog'
require 'authserver/dir/ds389'
require 'authserver/dir/client'
Yast.import 'UI'
Yast.import 'Icon'
Yast.import 'Label'
Yast.import 'Popup'

def y2log
  "/var/log/YaST2/y2log"
end

# NewDirInst dialog collects setup details as input and eventually creates a new directory server instance.
class NewDirInst < UI::Dialog
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
        Left(Heading(_('Create New Directory Instance'))),
        HBox(
            Frame(_('General options (mandatory)'),
                VBox(
                    InputField(Id(:fqdn), Opt(:hstretch), _('Fully qualified domain name (e.g. dir.example.net)'), ''),
                    InputField(Id(:instance_name), Opt(:hstretch), _('Directory server instance name (e.g. localhost)'), ''),
                    InputField(Id(:suffix), Opt(:hstretch), _('Directory suffix (e.g. dc=example,dc=net)'), ''),
                ),
            ),
            VBox(
                Frame(_('Security options (mandatory)'),
                    VBox(
                        Password(Id(:dm_pass), Opt(:hstretch), _('"cn=Directory Manager" password'), ''),
                        Password(Id(:dm_pass_repeat), Opt(:hstretch), _('Repeat "cn=Directory Manager" password'), ''),
                    ),
                ),
                Frame(_('Security options (optional)'),
                    VBox(
                        InputField(Id(:tls_ca), Opt(:hstretch), _('Server TLS certificate authority in PEM format'), ''),
                        InputField(Id(:tls_p12), Opt(:hstretch), _('Server TLS certificate and key in PKCS12 format with friendly name "Server-Cert"'), ''),
                    ),
                ),
            ),
        ),
        HBox(
            PushButton(Id(:ok), Label.OKButton),
            PushButton(Id(:finish), Label.CancelButton),
        ),
        ReplacePoint(Id(:busy), Empty()),
    )
  end

  def ok_handler
    fqdn = UI.QueryWidget(Id(:fqdn), :Value)
    instance_name = UI.QueryWidget(Id(:instance_name), :Value)
    suffix = UI.QueryWidget(Id(:suffix), :Value)
    dm_pass = UI.QueryWidget(Id(:dm_pass), :Value)
    dm_pass_repeat = UI.QueryWidget(Id(:dm_pass_repeat), :Value)
    tls_ca = UI.QueryWidget(Id(:tls_ca), :Value)
    tls_p12 = UI.QueryWidget(Id(:tls_p12), :Value)

    UI.ReplaceWidget(Id(:busy), Empty())

    # Validate input
    if fqdn == '' || instance_name == ''|| suffix == '' || dm_pass == '' 
      Popup.Error(_('Please complete mandatory setup fields.'))
      return
    end
    if dm_pass_repeat != dm_pass
      Popup.Error(_('Two password entries do not match.'))
      return
    end
    if ! ((tls_ca == '' && tls_p12 == '') || (tls_ca != '' && tls_p12 != ''))
      Popup.Error(_('Both TLS Certificate authority and PKCS12 must be provided, or none provided.'))
      return
    end
    if (tls_ca != '' && tls_p12 != '') && (!File.exists?(tls_ca) || !File.exists?(tls_p12))
      Popup.Error(_('TLS certificate authority PEM OR certificate/key PKCS12 file does not exist.'))
      return
    end
    # The dscreate tool has an instance name checker that is much more aware of instance
    # rules than this ruby tool can be.
    UI.ReplaceWidget(Id(:busy), Label(_('Preparing to install new instance, this may take a minute ...')))

    if !DS389.install_pkgs
      Popup.Error(_('Error during package installation.'))
      return
    end

    # Collect setup parameters into an INI file and feed it into 389 setup script
    ini_content = DS389.gen_setup_ini(fqdn, instance_name, suffix, dm_pass)
    ini_safe_content = DS389.gen_setup_ini(fqdn, instance_name, suffix, "********")
    log.info(ini_safe_content)
    UI.ReplaceWidget(Id(:busy), Label(_('Installing new instance, this may take a minute ...')))
    ok = DS389.exec_setup(ini_content)
    # Always remove the ini file
    DS389.remove_setup_ini
    if !ok
      Popup.Error(_('Failed to set up new instance! Log output may be found in %{y2log}'), y2log: y2log)
      UI.ReplaceWidget(Id(:busy), Empty())
      return
    end

    if (tls_ca != '' && tls_p12 != '')
      UI.ReplaceWidget(Id(:busy), Label(_('Configuring instance TLS ...')))
      # Turn on TLS
      if !DS389.install_tls_in_nss(instance_name, tls_ca, tls_p12)
        Popup.Error(_('Failed to set up new instance! Log output may be found in %{y2log}'), y2log: y2log)
        UI.ReplaceWidget(Id(:busy), Empty())
        return
      end

      if !DS389.restart(instance_name)
        Popup.Error(_('Failed to restart directory instance, please inspect the journal of dirsrv@%s.service and /var/log/dirsrv/slapd-%s') % [instance_name, instance_name])
        UI.ReplaceWidget(Id(:busy), Empty())
        return
      end
    end

    UI.ReplaceWidget(Id(:busy), Empty())
    Popup.Message(_('New instance has been set up! Log output may be found in %{y2log}'), y2log: y2log)
    finish_dialog(:next)
    UI.ReplaceWidget(Id(:busy), Empty())
  end
end
