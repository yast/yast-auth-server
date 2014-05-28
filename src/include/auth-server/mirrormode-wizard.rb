# encoding: utf-8

# File:	include/ldap-server/mirrormode-wizard.ycp
# Package:	Configuration of ldap-server
# Summary:	Wizards definitions
# Authors:	Andreas Bauer <abauer@suse.de>
#              Ralf Haferkamp <rhafer@suse.de>
#
# $Id$
module Yast
  module AuthServerMirrormodeWizardInclude
    def initialize_auth_server_mirrormode_wizard(include_target)
      Yast.import "UI"

      textdomain "auth-server"

      Yast.import "Sequencer"
      Yast.import "Wizard"
      Yast.import "URL"

      Yast.include include_target, "auth-server/complex.rb"
      Yast.include include_target, "auth-server/dialogs.rb"
      Yast.include include_target, "auth-server/wizards.rb"

      @caption = _("OpenLDAP MirrorMode Configuration")
      @dlg_mm_overview = HSquash(
        VBox(
          Heading(_("MirrorMode Node List")),
          VSpacing(),
          VBox(
            VBox(
              MinSize(
                60,
                7,
                Table(
                  Id(:serverid_tab),
                  Opt(:keepSorting),
                  Header(_("Server ID"), _("Server URI"))
                )
              ),
              Left(HBox(PushButton(Id(:pb_del), Label.DeleteButton)))
            )
          )
        )
      )

      @dlg_nomm_message = HSquash(
        VBox(
          Label(
            _(
              "This server is not setup as a MirrorMode Node. Click \"Next\" to launch the standard OpenLDAP configuration wizard."
            )
          )
        )
      )
    end

    def MirrorModeOverview
      ret = nil
      event = {}
      if !AuthServer.HasMirrorMode
        Wizard.SetContentsButtons(
          caption,
          @dlg_nomm_message,
          Ops.get_string(@HELPS, "service_dialog", "help not found"),
          Label.BackButton,
          Label.NextButton
        )
        Wizard.HideBackButton
        Wizard.SetAbortButton(:abort, Label.CancelButton)

        while true
          event = UI.WaitForEvent

          ret = Ops.get(event, "ID")
          if ret == :abort || ret == :cancel
            break
          elsif ret == :next
            ret = :nomirror
            break
          end
        end
        return deep_copy(ret)
      end
      caption = _("OpenLDAP MirrorMode Overview")
      Wizard.SetContentsButtons(
        caption,
        @dlg_mm_overview,
        Ops.get_string(@HELPS, "service_dialog", "help not found"),
        Label.BackButton,
        Label.OKButton
      )
      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      serverids = AuthServer.ReadServerIds
      pos = -1
      itemlist = Builtins.maplist(serverids) do |v|
        pos = Ops.add(pos, 1)
        Item(
          Id(pos),
          Ops.get_integer(v, "id", -1),
          Ops.get_string(v, "uri", "")
        )
      end

      UI.ChangeWidget(:serverid_tab, :Items, itemlist)
      while true
        event = UI.WaitForEvent
        ret = Ops.get(event, "ID")

        if ret == :back || ret == :abort || ret == :cancel || ret == :next ||
            ret == :finish
          break
        elsif ret == :pb_del
          selected = Convert.to_integer(
            UI.QueryWidget(:serverid_tab, :CurrentItem)
          )
          if selected != nil
            Builtins.y2milestone(
              "Delete Server: %1",
              Ops.get(serverids, selected, {})
            )
            url = URL.Parse(Ops.get_string(serverids, [selected, "uri"], ""))
            if Ops.get_string(url, "host", "") == AuthServer.ReadHostnameFQ
              Popup.Error(
                _(
                  "Deleting the host on which you started this YaST Module is not possible.\n"
                ) +
                  _(
                    "Start yast2 openldap-mirrormode on a different MirrorMode server."
                  )
              )
              next
            end

            if Popup.YesNo(
                Ops.add(
                  Builtins.sformat(
                    _(
                      "Do you really want to remove \"%1\" from the MirrorMode setup?\n"
                    ),
                    Ops.get_string(serverids, [selected, "uri"], "")
                  ),
                  _(
                    "Changes will take effect immediately after clicking \"Yes\""
                  )
                )
              )
              AuthServer.RemoveMMSyncrepl(
                Ops.get_string(serverids, [selected, "uri"], "")
              )
              serverids = Builtins.remove(serverids, selected)
              AuthServer.WriteServerIds(serverids)
              itemlist = Builtins.maplist(serverids) do |v|
                pos = Ops.add(pos, 1)
                Item(
                  Id(pos),
                  Ops.get_integer(v, "id", -1),
                  Ops.get_string(v, "uri", "")
                )
              end
              UI.ChangeWidget(:serverid_tab, :Items, itemlist)
              Wizard.HideAbortButton
            end
          end
        end
      end

      deep_copy(ret)
    end

    def MirrorModeSequence
      # Initialization dialog contents
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetDesktopIcon("ldap-server")
      Wizard.SetContentsButtons(
        @caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      AuthServer.WriteSetupSlave(true)
      AuthServer.WriteSetupMirrorMode(true)
      aliases = {
        "read"               => lambda { ReadDialog() },
        "newnode"            => lambda { EnableServiceDialog() },
        "slavesetup"         => lambda { SlaveSetupDialog() },
        "replicationsummary" => lambda { ReplicatonSetupSummaryDialog() },
        "main"               => lambda { MirrorModeOverview() },
        "write"              => lambda { WriteDialog() }
      }

      sequence = {
        "ws_start"           => "read",
        "read"               => {
          :abort   => :abort,
          :initial => "newnode",
          :next    => "main"
        },
        "newnode"            => {
          :next   => "slavesetup",
          :abort  => :abort,
          :finish => :disable
        },
        "slavesetup"         => { :next => "replicationsummary" },
        "replicationsummary" => { :next => "write" },
        "main"               => {
          :abort    => :abort,
          :next     => "write",
          :nomirror => :nomirror,
          :reread   => "read"
        },
        "write"              => { :abort => :abort, :next => :next }
      }

      Builtins.y2milestone("--> starting MirrorModeSequence")

      ret = Sequencer.Run(aliases, sequence)

      Builtins.y2milestone("<-- MirrorModeSequence finished ")

      UI.CloseDialog

      ret = LdapServerSequence() if ret == :nomirror
      deep_copy(ret)
    end
  end
end
