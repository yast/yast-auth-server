# encoding: utf-8

# File:	include/ldap-server/tree_structure.ycp
# Package:	Configuration of ldap-server
# Summary:	Widget Tree structure
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
module Yast
  module AuthServerWidgetsInclude
    def initialize_auth_server_widgets(include_target)
      textdomain "auth-server"
      Yast.import "CWMFirewallInterfaces"
      Yast.import "Label"
      Yast.import "Ldap"
      Yast.import "Popup"
      Yast.import "Wizard"

      @firewall_settings = {
        "services"        => ["service:openldap"],
        "display_details" => true
      }

      # list of valid encoding methods for password inputs, used by add database and edit database
      # dialogs
      @enc_types = [
        Item(Id("CRYPT"), "CRYPT"),
        Item(Id("SMD5"), "SMD5"),
        Item(Id("SHA"), "SHA"),
        Item(Id("SSHA"), "SSHA", true),
        Item(Id("PLAIN"), "PLAIN")
      ]

      @fw_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        @firewall_settings
      )
      @dlg_service = Top(
        VBox(
          VBox(
            Frame(
              _("&Start LDAP Server"),
              VBox(
                RadioButtonGroup(
                  Id(:rb_service_enable),
                  VBox(
                    Left(RadioButton(Id(:rb_no), Opt(:notify), Label.NoButton)),
                    Left(
                      RadioButton(
                        Id(:rb_yes),
                        Opt(:notify),
                        Label.YesButton,
                        true
                      )
                    )
                  )
                ),
                Left(
                  CheckBox(
                    Id(:cb_register_slp),
                    _("Register at an &SLP Daemon"),
                    AuthServer.ReadSLPEnabled
                  )
                ),
                HStretch()
              )
            )
          ),
          VSpacing(),
          VBox(
            Frame(
              Id(:fr_listener),
              _("Protocol Listeners"),
              VBox(
                Left(
                  HBox(
                    HWeight(
                      1,
                      CheckBox(Id(:cb_interface_ldap), _("LDAP"), false)
                    ),
                    #`HWeight(1, `PushButton( `id( `pb_interface_ldap), "Interfaces ...")),
                    HWeight(1, HStretch())
                  )
                ),
                Left(
                  HBox(
                    HWeight(
                      1,
                      CheckBox(
                        Id(:cb_interface_ldaps),
                        _("LDAP over SSL (ldaps)"),
                        false
                      )
                    ),
                    #`HWeight(1, `PushButton( `id( `pb_interface_ldaps), "Interfaces ...")),
                    HWeight(1, HStretch())
                  )
                )
              )
            )
          ),
          VSpacing(),
          VBox(
            Frame(
              Id(:fr_firewall),
              _("Firewall Settings"),
              VBox(
                Ops.get_term(@fw_widget, "custom_widget", Empty()),
                HStretch()
              )
            )
          )
        )
      )

      @schemaWidget = VBox(
        SelectionBox(
          Id(:sb_schemalist),
          Opt(:notify),
          _("Included &Schema Files"),
          []
        ),
        HBox(
          PushButton(Id(:pb_add), Label.AddButton),
          PushButton(Id(:pb_del), Label.DeleteButton)
        )
      )

      @loglevelWidget = MultiSelectionBox(
        Id(:msb_loglevel),
        _("Select &Log Level Flags:"),
        [
          Item(Id("trace"), _("Trace Function Calls")),
          Item(Id("packets"), _("Debug Packet Handling")),
          Item(Id("args"), _("Heavy Trace Debugging (function args)")),
          Item(Id("conns"), _("Connection Management")),
          Item(Id("BER"), _("Print Packets Sent and Received")),
          Item(Id("filter"), _("Search Filter Processing")),
          Item(Id("config"), _("Configuration File Processing")),
          Item(Id("ACL"), _("Access Control List Processing")),
          Item(Id("stats"), _("Log Connections, Operations, and Result")),
          Item(Id("stats2"), _("Log Entries Sent")),
          Item(Id("shell"), _("Print Communication with Shell Back-Ends")),
          Item(Id("parse"), _("Entry Parsing")),
          Item(Id("sync"), _("LDAPSync Replication")),
          Item(Id("none"), _("None"))
        ]
      )

      @allowWidget = VBox(
        MultiSelectionBox(
          Id(:msb_allow),
          _("Select &Allow Flags:"),
          [
            Item(Id("bind_v2"), _("LDAPv2 Bind Requests")),
            Item(
              Id("bind_anon_cred"),
              _("Anonymous Bind when Credentials Not Empty")
            ),
            Item(
              Id("bind_anon_dn"),
              _("Unauthenticated Bind when DN Not Empty")
            ),
            Item(
              Id("update_anon"),
              _("Unauthenticated Update Operations to Process")
            )
          ]
        ),
        MultiSelectionBox(
          Id(:msb_disallow),
          _("Select &Disallow Flags:"),
          [
            Item(
              Id("bind_anon"),
              _(
                "Disable acceptance of anonymous Bind Requests (does not prohibit anonymous directory access)"
              )
            ),
            Item(Id("bind_simple"), _("Disable Simple Bind authentication")),
            Item(
              Id("tls_2_anon"),
              _(
                "Disable forcing session to anonymous status upon StartTLS operation receipt"
              )
            ),
            Item(
              Id("tls_authc"),
              _("Disallow the StartTLS operation if authenticated")
            )
          ]
        )
      )

      @tlsWidget = HSquash(
        VBox(
          Heading(_("TLS Settings")),
          VBox(
            Frame(
              _("Basic Settings"),
              VBox(
                Left(
                  CheckBox(
                    Id(:cb_tls_enabled),
                    Opt(:notify),
                    _("Enable TLS"),
                    false
                  )
                ),
                Left(
                  CheckBox(
                    Id(:cb_ssl_listener_enabled),
                    _("Enable LDAP over SSL (ldaps) interface"),
                    false
                  )
                ),
                Left(
                  CheckBox(
                    Id(:cb_use_common_cert),
                    Opt(:notify),
                    _("Use common Server Certificate"),
                    false
                  )
                ),
                HStretch()
              )
            )
          ),
          VSpacing(0.5),
          VBox(
            Frame(
              Id(:fr_import_cert),
              _("Import Certificate"),
              VBox(
                VSquash(
                  HBox(
                    InputField(
                      Id(:te_ca_file),
                      Opt(:hstretch),
                      _("C&A Certificate File (PEM Format)")
                    ),
                    HSpacing(0.5),
                    Bottom(PushButton(Id(:pb_ca_file), _("Bro&wse...")))
                  )
                ),
                VSpacing(0.5),
                VSquash(
                  HBox(
                    InputField(
                      Id(:te_cert_file),
                      Opt(:hstretch),
                      _("Certificate &File (PEM Format)")
                    ),
                    HSpacing(0.5),
                    Bottom(PushButton(Id(:pb_cert_file), _("&Browse...")))
                  )
                ),
                VSpacing(0.5),
                VSquash(
                  HBox(
                    InputField(
                      Id(:te_key_file),
                      Opt(:hstretch),
                      _("Certificate &Key File (PEM Format - Unencrypted)")
                    ),
                    HSpacing(0.5),
                    Bottom(PushButton(Id(:pb_key_file), _("B&rowse...")))
                  )
                )
              )
            )
          ),
          VSpacing(0.5),
          Left(PushButton(Id(:pb_launch_ca), _("Launch CA Management Module")))
        )
      )


      @generalDbWidget = VBox(
        InputField(Id(:te_basedn), Opt(:disabled, :hstretch), _("&Base DN")),
        VSpacing(0.5),
        VSquash(
          HBox(
            InputField(Id(:te_rootdn), Opt(:hstretch), _("Administrator DN")),
            HSpacing(0.5),
            Bottom(CheckBox(Id(:cb_append_basedn), _("&Append Base DN"))),
            HSpacing(0.5),
            Bottom(PushButton(Id(:pb_changepw), _("Change Password"))),
            VSpacing(0.3)
          )
        )
      )

      @editBdbDatabase = Top(
        VBox(
          Heading(_("Edit BDB Database")),
          VSpacing(1),
          @generalDbWidget,
          VSpacing(0.5),
          VBox(
            HBox(
              HSquash(
                IntField(Id(:if_entrycache), _("Entry Cache"), 0, 2000000000, 0)
              ),
              HSpacing(0.5),
              HSquash(
                IntField(
                  Id(:if_idlcache),
                  _("Index Cache (IDL cache)"),
                  0,
                  2000000000,
                  0
                )
              ),
              HStretch()
            )
          ),
          VSpacing(0.5),
          VBox(
            Left(Label(_("Checkpoint Settings"))),
            HBox(
              HSquash(IntField(Id(:if_checkpoint_kb), "", 0, 2000000000, 0)),
              Label(_("kilobytes")),
              HSquash(IntField(Id(:if_checkpoint_min), "", 0, 2000000000, 0)),
              Label(_("minutes")),
              HStretch()
            )
          )
        )
      )
      @editConfigDatabase = Top(
        VBox(
          Heading(_("Change Configuration Database Settings")),
          VSpacing(1),
          CheckBox(
            Id(:cb_conf_ldapsimplebind),
            Opt(:notify),
            _(
              "Allow Plaintext Authentication (Simple Bind) for this Database. "
            ) +
              _("(Remote Connection needs to be encrypted)"),
            false
          ),
          VSpacing(0.3),
          ReplacePoint(
            Id(:rp_confpw),
            PushButton(Id(:pb_changepw), _("Change Administration Password"))
          )
        )
      )
      @editGenericDatabase = Top(
        VBox(
          Heading(_("Edit Database")),
          VSpacing(1),
          Label(_("Database type not currently supported."))
        )
      )

      @editBdbIndexes = VBox(
        Heading(_("Indexing Configuration")),
        Table(
          Id(:tab_idx),
          Header(_("Attribute"), _("Presence"), _("Equality"), _("Substring")),
          []
        ),
        Left(
          HSquash(
            HBox(
              PushButton(Id(:pb_idx_add), Label.AddButton),
              PushButton(Id(:pb_idx_edit), Label.EditButton),
              PushButton(Id(:pb_idx_del), Label.DeleteButton)
            )
          )
        )
      )
    end

    def ChangeAdminPassword
      result = nil
      content = VBox(
        Heading(_("Change Administrator Password")),
        Password(Id(:te_rootpw), _("New Administrator &Password")),
        HSpacing(0.5),
        Password(Id(:te_valid_rootpw), _("&Validate Password")),
        HSpacing(0.5),
        ComboBox(Id(:cb_cryptmethod), _("Password &Encryption"), @enc_types),
        Wizard.CancelOKButtonBox
      )
      UI.OpenDialog(Opt(:decorated), content)
      while true
        ret = UI.UserInput
        if ret == :cancel
          break
        elsif ret == :ok
          pw = Convert.to_string(UI.QueryWidget(:te_rootpw, :Value))
          verifypw = Convert.to_string(UI.QueryWidget(:te_valid_rootpw, :Value))
          hashAlgo = Convert.to_string(UI.QueryWidget(:cb_cryptmethod, :Value))
          if Builtins.size(pw) == 0
            Popup.Error(_("Enter a password"))
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
          elsif pw == verifypw
            result = {}
            Ops.set(result, "password", pw)
            Ops.set(result, "hashAlgo", hashAlgo)
            break
          else
            Popup.Error(
              _("The passwords you have entered do not match. Try again.")
            )
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
          end
        end
      end
      UI.CloseDialog
      deep_copy(result)
    end


    def DatabaseIndexPopup(skipAttrs, editAttr, currentIdx)
      skipAttrs = deep_copy(skipAttrs)
      currentIdx = deep_copy(currentIdx)
      Builtins.y2milestone("AddIndexPopup skipAttrs: %1", skipAttrs)
      content = VBox(
        Heading(_("Add Index")),
        ReplacePoint(
          Id(:rp_attrs),
          ComboBox(Id(:cb_attrs), Opt(:hstretch, :notify), "Attributetypes")
        ),
        Left(CheckBox(Id(:cb_idx_pres), _("Presence"))),
        Left(CheckBox(Id(:cb_idx_eq), _("Equality"))),
        Left(CheckBox(Id(:cb_idx_substr), _("Substring"))),
        Wizard.CancelOKButtonBox
      )

      attrTypes = Convert.convert(
        SCR.Read(path(".ldapserver.schema.attributeTypes")),
        :from => "any",
        :to   => "map <string, map <string, boolean>>"
      )
      if editAttr == ""
        items = []
        Builtins.foreach(attrTypes) do |key, idx|
          items = Builtins.add(items, key) if nil == Builtins.find(skipAttrs) do |elem|
            Builtins.tolower(elem) == Builtins.tolower(key)
          end
        end
        items = Builtins.lsort(items)
        UI.OpenDialog(Opt(:decorated), content)
        UI.ChangeWidget(:cb_attrs, :Items, items)
      else
        UI.OpenDialog(Opt(:decorated), content)
        UI.ReplaceWidget(:rp_attrs, Label(Id(:attr), editAttr))
        Builtins.y2milestone("Current IDX: %1", currentIdx)
        if Ops.get(currentIdx, "eq", false)
          UI.ChangeWidget(:cb_idx_eq, :Value, true)
        end
        if Ops.get(currentIdx, "pres", false)
          UI.ChangeWidget(:cb_idx_pres, :Value, true)
        end
        if Ops.get(currentIdx, "sub", false)
          UI.ChangeWidget(:cb_idx_substr, :Value, true)
        end
      end

      selectedAttr = ""
      if editAttr == ""
        selectedAttr = Convert.to_string(UI.QueryWidget(:cb_attrs, :Value))
      else
        selectedAttr = editAttr
      end

      Builtins.y2milestone("selected Attribute \"%1\"", selectedAttr)
      idxOpt = Ops.get(attrTypes, selectedAttr)
      Builtins.y2milestone("index opts: %1", idxOpt)
      if Ops.get(idxOpt, "equality", false)
        UI.ChangeWidget(:cb_idx_eq, :Enabled, true)
      else
        UI.ChangeWidget(:cb_idx_eq, :Enabled, false)
      end
      if Ops.get(idxOpt, "substring", false)
        UI.ChangeWidget(:cb_idx_substr, :Enabled, true)
      else
        UI.ChangeWidget(:cb_idx_substr, :Enabled, false)
      end
      if Ops.get(idxOpt, "presence", false)
        UI.ChangeWidget(:cb_idx_pres, :Enabled, true)
      else
        UI.ChangeWidget(:cb_idx_pres, :Enabled, false)
      end

      retval = {}
      while true
        ret = UI.UserInput
        Builtins.y2milestone("ret = %1", ret)
        break if ret == :cancel
        if editAttr == ""
          selectedAttr = Convert.to_string(UI.QueryWidget(:cb_attrs, :Value))
          Builtins.y2milestone("selected Attribute \"%1\"", selectedAttr)
        end
        if ret == :cb_attrs # Attribute selected in the Combobox
          idxOpt2 = Ops.get(attrTypes, selectedAttr)
          Builtins.y2milestone("index opts: %1", idxOpt2)
          if Ops.get(idxOpt2, "equality", false)
            UI.ChangeWidget(:cb_idx_eq, :Enabled, true)
          else
            UI.ChangeWidget(:cb_idx_eq, :Enabled, false)
          end
          if Ops.get(idxOpt2, "substring", false)
            UI.ChangeWidget(:cb_idx_substr, :Enabled, true)
          else
            UI.ChangeWidget(:cb_idx_substr, :Enabled, false)
          end
          if Ops.get(idxOpt2, "presence", false)
            UI.ChangeWidget(:cb_idx_pres, :Enabled, true)
          else
            UI.ChangeWidget(:cb_idx_pres, :Enabled, false)
          end
        elsif ret == :ok
          Ops.set(retval, "name", selectedAttr)
          Ops.set(retval, "pres", UI.QueryWidget(:cb_idx_pres, :Value))
          Ops.set(retval, "eq", UI.QueryWidget(:cb_idx_eq, :Value))
          Ops.set(retval, "sub", UI.QueryWidget(:cb_idx_substr, :Value))
          Builtins.y2milestone("new index: %1", retval)
          break
        end
      end
      UI.CloseDialog
      deep_copy(retval)
    end
  end
end
