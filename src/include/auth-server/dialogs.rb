# encoding: utf-8

# File:	include/ldap-server/dialogs.ycp
# Package:	Configuration of ldap-server
# Summary:	Dialogs definitions
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
module Yast
  module AuthServerDialogsInclude
    def initialize_auth_server_dialogs(include_target)
      Yast.import "UI"

      textdomain "auth-server"

      Yast.import "CWMFirewallInterfaces"
      Yast.import "Label"
      Yast.import "Wizard"
      Yast.import "Ldap"
      Yast.import "LdapPopup"
      Yast.import "AuthServer"
      Yast.import "HTML"
      Yast.import "Report"

      Yast.include include_target, "auth-server/helps.rb"
      Yast.include include_target, "auth-server/kerberos_advanced.rb"
      Yast.include include_target, "auth-server/tree_structure.rb"

      @section_id = ""

      #heading for all dialogs
      @caption = _("Authentication Server Configuration")


      #*********************
      #* helper functions **
      #********************

      @error_str = ""


      #*********************
      #* dialog functions **
      #********************

      @dlg_service_initial = HSquash(
        VBox(
          Heading(_("General Settings")),
          VSpacing(),
          VBox(
            Frame(
              _("&Start LDAP Server"),
              VBox(
                RadioButtonGroup(
                  VBox(
                    Left(
                      RadioButton(
                        Id(:rb_yes),
                        Opt(:notify),
                        Label.YesButton,
                        false
                      )
                    ),
                    Left(
                      RadioButton(
                        Id(:rb_no),
                        Opt(:notify),
                        Label.NoButton,
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
              _("Firewall Settings"),
              VBox(ReplacePoint(Id(:rp_firewall), Empty()), HStretch())
            )
          )
        )
      )
    end

    def generateTreeRec(tree, parent, children)
      tree = deep_copy(tree)
      children = deep_copy(children)
      Builtins.y2milestone(
        "generating tree for item '%1', children are '%2'",
        parent,
        children
      )
      Builtins.foreach(children) do |item|
        item_map = Ops.get(@widget_map, item)
        if item_map == nil
          @error_str = Ops.add(
            Ops.add(
              Ops.add(
                Ops.add("item ", item),
                " does not exist but is referenced by '"
              ),
              parent
            ),
            "'!"
          )
          next nil
        end
        Builtins.y2milestone("adding tree item '%1' to parent %2", item, parent)
        tree = Wizard.AddTreeItem(
          tree,
          parent,
          Ops.get_string(item_map, "name", ""),
          item
        )
        Builtins.y2milestone("tree '%1'", tree)
        if Builtins.haskey(item_map, "children")
          childlist = Ops.get_list(item_map, "children", [])
          tree = generateTreeRec(tree, item, childlist)
          next nil if tree == nil
        end
      end
      deep_copy(tree)
    end

    def generateTree
      baselist = Ops.get_list(@widget_map, ["base", "children"], [])
      tree = []
      Builtins.y2debug(
        "generating tree for 'base', children are '%1'",
        baselist
      )
      Builtins.foreach(baselist) do |item|
        item_map = Ops.get(@widget_map, item)
        if item_map == nil
          @error_str = Ops.add(
            Ops.add("item ", item),
            " does not exist but is referenced by 'base'!"
          )
          next nil
        end
        Builtins.y2milestone("adding tree item '%1' to root", item)
        tree = Wizard.AddTreeItem(
          tree,
          "",
          Ops.get_string(item_map, "name", ""),
          item
        )
        if Builtins.haskey(item_map, "children")
          childlist = Ops.get_list(item_map, "children", [])
          tree = generateTreeRec(tree, item, childlist)
          next nil if tree == nil
        end
      end

      #create dynamic tree items (databases)
      deep_copy(tree)
    end

    def callHandler(item, handler)
      Builtins.y2milestone("callhandler %1 for item %2", handler, item)
      if Builtins.haskey(Ops.get(@widget_map, item, {}), handler)
        function = Ops.get(@widget_map, [item, handler])
        if function != nil
          if !Convert.to_boolean(Builtins.eval(function))
            Report.Error(@callback_error) if @callback_error != ""
            return false
          end
        else
          Builtins.y2error(
            Builtins.sformat(
              "AuthServer Module: illegal handler '%1' for item '%2'",
              handler,
              item
            )
          )
        end
      end
      true
    end

    def showTreeDialog(name, focus_tree)
      #create new item
      widget = nil
      if !AuthServer.ReadServiceRunning
        if name != "daemon"
          ret = Popup.AnyQuestion3(
            _("The LDAP Server is not running."),
            _(
              "Do you want to start it now to re-read its configuration data or do you want to create a new configuration from scratch?"
            ),
            _("Restart"),
            _("New Configuration"),
            Label.AbortButton,
            :focus_yes
          )
          name = "daemon"
          if ret == :yes
            return "__reread__"
          elsif ret == :no
            return "__empty__"
          elsif ret == :retry
            return name
          end
        end
      end
      widget = Ops.get_term(@widget_map, [name, "widget"]) do
        Label(Ops.add(Ops.add("Loading widget for item '", name), "' failed."))
      end

      #get helps page
      help_page = Ops.get_string(@widget_map, [name, "help_page"], name)
      help_string = Ops.get_string(
        @HELPS,
        help_page,
        Ops.add(
          Ops.add(_("help page for item <b>"), help_page),
          _("</b> not available")
        )
      )

      Wizard.SetAbortButton(:abort, Label.CancelButton)
      Wizard.SetContentsButtons(
        @caption,
        widget,
        help_string,
        Label.BackButton,
        Label.OKButton
      )
      Wizard.HideBackButton


      UI.SetFocus(Id(:wizardTree)) if focus_tree

      name
    end

    def EnableServiceDialog
      defaults = AuthServer.CreateInitialDefaults
      firewall_settings = {
        "services"        => ["service:openldap", "service:kdc", "service:kadmind"],
        "display_details" => true
      }
      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        firewall_settings
      )

      Wizard.SetContentsButtons(
        @caption,
        @dlg_service_initial,
        Ops.get_string(@HELPS, "service_dialog", "help not found"),
        Label.BackButton,
        Label.NextButton
      )
      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      UI.ReplaceWidget(
        :rp_firewall,
        Ops.get_term(firewall_widget, "custom_widget", Empty())
      )
      CWMFirewallInterfaces.OpenFirewallInit(firewall_widget, "")

      if Ops.get_boolean(defaults, "serviceEnabled", true)
        UI.ChangeWidget(:rb_yes, :Value, true)
        Wizard.SetNextButton(:next, Label.NextButton)
      else
        UI.ChangeWidget(:cb_register_slp, :Enabled, false)
        Wizard.SetNextButton(:finish, Label.FinishButton)
      end
      UI.ChangeWidget(
        :cb_register_slp,
        :Value,
        Ops.get_boolean(defaults, "slpRegister", false)
      )

      ret = nil
      event = {}

      while true
        event = UI.WaitForEvent
        ret = Ops.get(event, "ID")
        CWMFirewallInterfaces.OpenFirewallHandle(firewall_widget, "", event)
        Builtins.y2milestone(
          "EnableServiceDialog: seeing return value '%1'",
          ret
        )

        if ret == :back || ret == :abort || ret == :cancel
          break
        elsif ret == :next || ret == :finish
          CWMFirewallInterfaces.OpenFirewallStore(firewall_widget, "", event)
          if Convert.to_boolean(UI.QueryWidget(:cb_register_slp, :Value))
            Ops.set(defaults, "slpRegister", 1)
          else
            Ops.set(defaults, "slpRegister", 0)
          end
          AuthServer.SetInitialDefaults(defaults)
          break
        elsif ret == :rb_yes
          Ops.set(defaults, "serviceEnabled", true)
          UI.ChangeWidget(:cb_register_slp, :Enabled, true)
          Wizard.SetNextButton(:next, Label.NextButton)
        elsif ret == :rb_no
          Ops.set(defaults, "serviceEnabled", false)
          UI.ChangeWidget(:cb_register_slp, :Enabled, false)
          Wizard.SetNextButton(:finish, Label.FinishButton)
        end
      end

      deep_copy(ret)
    end

    def ServerTypeDialog
      serverTypeWidget = HSquash(
        VBox(
          Heading(_("Server Type")),
          Frame(
            "",
            VBox(
              VSpacing(),
              RadioButtonGroup(
                Id(:rbg_servertype),
                VBox(
                  Left(
                    RadioButton(
                      Id(:rb_standalone),
                      _("Stand-alone server"),
                      true
                    )
                  ),
                  VSpacing(),
                  Left(
                    RadioButton(
                      Id(:rb_master),
                      _("Master server in a replication setup"),
                      false
                    )
                  ),
                  VSpacing(),
                  Left(
                    RadioButton(
                      Id(:rb_slave),
                      _("Replica (slave) server.\n") +
                        _(
                          "All data, including configuration, is replicated from a remote server."
                        ),
                      false
                    )
                  )
                )
              )
            )
          )
        )
      )
      Wizard.SetContentsButtons(
        @caption,
        serverTypeWidget,
        Ops.get_string(@HELPS, "server_type", "help not found"),
        Label.BackButton,
        Label.NextButton
      )
      ret = nil
      while true
        ret = UI.UserInput
        Builtins.y2milestone("TlsConfigDialog: seeing return value '%1'", ret)
        if ret == :next
          if UI.QueryWidget(Id(:rbg_servertype), :CurrentButton) == :rb_slave
            ret = :slave_setup
            AuthServer.WriteSetupMaster(false)
            AuthServer.WriteSetupSlave(true)
          elsif UI.QueryWidget(Id(:rbg_servertype), :CurrentButton) == :rb_master
            if Builtins.size(AuthServer.ReadHostnameFQ) == 0
              Popup.Notify(
                _(
                  "YaST was not able to determine the fully qualified hostname of this\ncomputer. \n"
                ) +
                  _(
                    "Setting up a replication master is currently not possible."
                  )
              )
              UI.ChangeWidget(:rb_master, :Enabled, false)
              UI.ChangeWidget(:rbg_servertype, :CurrentButton, :rb_standalone)
              next
            else
              AuthServer.WriteSetupMaster(true)
              AuthServer.WriteSetupSlave(false)
            end
          else
            AuthServer.WriteSetupMaster(false)
            AuthServer.WriteSetupSlave(false)
          end
          SCR.Execute(path(".ldapserver.reset"))
        end
        return deep_copy(ret)
      end
      deep_copy(ret)
    end

    def TlsConfigDialog
      Wizard.SetContentsButtons(
        @caption,
        @tlsWidget,
        Ops.get_string(@HELPS, "tls_dialog", "help not found"),
        Label.BackButton,
        Label.NextButton
      )
      AuthServer.InitGlobals
      cb_read_tls
      ret = nil
      while true
        ret = UI.UserInput
        Builtins.y2milestone("TlsConfigDialog: seeing return value '%1'", ret)

        break if ret == :back
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :next || ret == :finish
          if !cb_write_tls
            Report.Error(@callback_error)
            next
          end
          break
        elsif Ops.is_symbol?(ret)
          @handler_cmd = Convert.to_symbol(ret)
          cb_input_tls
        end
      end

      deep_copy(ret)
    end

    def KerberosDialog()
      advButton = Empty()

      # Button text
      advButton = PushButton(Id(:advanced), _("&Advanced Configuration"))

      firewall_settings = {
        "services"        => ["service:kdc", "service:kadmind"],
        "display_details" => true
      }
      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        firewall_settings
      )

      kerberosServiceWidget = HSquash(
        VBox(
          Heading(_("Kerberos Authentication")),
          VSpacing(),
          Frame(
            _("&Enable Kerberos Authentication"),
            VBox(
              RadioButtonGroup(
                VBox(
                  Left(
                    RadioButton(
                      Id(:rb_yes),
                      Opt(:notify),
                      Label.YesButton,
                      false
                    )
                  ),
                  Left(
                    RadioButton(
                      Id(:rb_no),
                      Opt(:notify),
                      Label.NoButton,
                      true
                    )
                  )
                )
              )
            )
          ),
          VSpacing(0.5),
          Frame(
            Id(:fr_kerberos_settings),
            _("Basic Kerberos Settings"),
            VBox(
              # TextEntry label: "Realm" is a typical kerberos phrase.
              # 								Please think twice please before you translate this,
              # 								and check with kerberos.pot how it is translated there.
              InputField(
                Id(:realm),
                Opt(:hstretch),
                _("R&ealm"),
                AuthServer.ReadKerberosRealm
              ),
              Password(
                Id(:pw1),
                Opt(:hstretch),
                Label.Password,
                AuthServer.ReadKerberosPassword
              ),
              Password(
                Id(:pw2),
                Opt(:hstretch),
                Label.ConfirmPassword,
                AuthServer.ReadKerberosPassword
              )
            )
          ),
          advButton
        )
      )

      Wizard.SetContentsButtons(
        @caption,
        kerberosServiceWidget,
        Ops.get_string(@HELPS, "kerberos", ""),
        Label.BackButton,
        Label.NextButton
      )

      UI.ChangeWidget(:fr_kerberos_settings, :Enabled, false)
      if AuthServer.ReadKerberosEnabled
        UI.ChangeWidget(:rb_yes, :Value, true)
        UI.ChangeWidget(:fr_kerberos_settings, :Enabled, true)
      end

      ret = nil
      event = {}

      while true
        event = UI.WaitForEvent
        ret = Ops.get_symbol(event, "ID")

        # abort?
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == :advanced || ret == :next
          stash = AuthServer.ReadKerberosDBvalue("key_stash_file")
          oldrealm = AuthServer.ReadKerberosRealm
          realm = Convert.to_string(UI.QueryWidget(Id(:realm), :Value))

          newstash = Builtins.regexpsub(
            stash,
            Ops.add(Ops.add("^(.+)", oldrealm), "$"),
            Ops.add("\\1", realm)
          )
          if newstash != nil
            AuthServer.WriteKerberosDBvalue("key_stash_file", newstash)
          end

          # --------------------------------- password checks
          pw1 = Convert.to_string(UI.QueryWidget(Id(:pw1), :Value))
          pw2 = Convert.to_string(UI.QueryWidget(Id(:pw2), :Value))

          if pw1 != pw2
            # The two user password information do not match
            # error popup
            Report.Error(_("The passwords do not match.\nTry again."))
            UI.SetFocus(Id(:pw1))
            next
          end

          AuthServer.WriteKerberosRealm(realm)
          AuthServer.WriteKerberosPassword(pw1)

          if AuthServer.ReadKerberosEnabled
            if ret == :next && pw1 == ""
              # Error popup
              Report.Error(_("Empty password is not allowed."))
              UI.SetFocus(Id(:pw1))
              next
            end
          end

          break
        elsif ret == :rb_yes
          if !Package.Installed("krb5-plugin-kdb-ldap")
            if !Package.Install("krb5-plugin-kdb-ldap")
              Popup.Error(
                Builtins.sformat(
                  _(
                    "The package '%1' is not available.\n" +
                      "YaST2 cannot enable Kerberos\n" +
                      "without installing the package."
                  ),
                  "krb5-plugin-kdb-ldap"
                )
              )
              UI.ChangeWidget(:rb_yes, :Value, false)
              UI.ChangeWidget(:rb_no, :Value, true)
              next
            end
          end
	  AuthServer.WriteKerberosEnabled(true)
          UI.ChangeWidget(:fr_kerberos_settings, :Enabled, true)
        elsif ret == :rb_no
	  AuthServer.WriteKerberosEnabled(false)
          UI.ChangeWidget(:fr_kerberos_settings, :Enabled, false)
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      ret
    end

    def KerberosAdvancedConfiguration()
      itemList = get_adv_itemlist
      lastItem = nil

      # caption
      caption = _("Advanced Kerberos Configuration")

      # term content = `Label("Advanced Dialog");

      button = HBox(
        PushButton(Id(:back), Opt(:key_F8), Label.BackButton),
        HStretch(),
        PushButton(Id(:abort), Opt(:key_F9), Label.AbortButton),
        HStretch(),
        PushButton(Id(:next), Opt(:key_F10), Label.NextButton),
        Empty()
      )

      UI.OpenDialog(
        Opt(:defaultsize),
        VBox(
          VSpacing(3),
          HSpacing(85),
          HWeight(
            70,
            VBox(
              HBox(
                HWeight(
                  35,
                  # tree widget label
                  Tree(
                    Id(:tree),
                    Opt(:notify, :vstretch),
                    _("Advanced &Options"),
                    itemList
                  )
                ),
                HSpacing(1),
                HWeight(
                  65,
                  VBox(
                    HSpacing(60),
                    # label widget
                    Left(
                      Heading(
                        Id(:heading),
                        Opt(:hstretch),
                        _("Current Selection: ")
                      )
                    ),
                    VSpacing(0.5),
                    VBox(
                      ReplacePoint(
                        Id(:replace),
                        RichText(Id(:id_advanced_d), "")
                      )
                    )
                  )
                )
              ),
              button
            )
          )
        )
      )

      UI.ChangeWidget(Id(:tree), :CurrentItem, :advanced)
      lastItem = :advanced

      ret = :dummy

      while ret != :back && ret != :abort && ret != :next
        ret = Convert.to_symbol(UI.UserInput)

        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :back
          break
        end

        selected = Convert.to_symbol(UI.QueryWidget(Id(:tree), :CurrentItem))

        # saving settings for old selection
        item = Ops.get_map(@itemMap, lastItem, {})
        function = Ops.get(item, "setCallback")
        error = ""
        if function != nil
          ret2 = Builtins.eval(function)
          error = Convert.to_string(ret2) if Ops.is_string?(ret2)
        end

        if error != nil && Ops.greater_than(Builtins.size(error), 0)
          Popup.Error(error)
          # set selection back
          UI.ChangeWidget(Id(:tree), :CurrentItem, lastItem)
        else
          if ret == :add
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Add for: %1", selected2)

            # Calling Add callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "addCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          elsif ret == :modify
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Modify for: %1", selected2)

            # Calling Modify callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "modifyCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          elsif ret == :delete
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Delete for: %1", selected2)

            # Calling Delete callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "deleteCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          else
            # no error --> goto next selection
            lastItem = selected
            item = Ops.get_map(@itemMap, selected, {})
            # header label
            UI.ChangeWidget(
              Id(:heading),
              :Value,
              Ops.add(
                _("Current Selection: "),
                Ops.get_string(item, "name", "")
              )
            )
            # showing concerning input fields
            UI.ReplaceWidget(
              Id(:replace),
              Ops.get_term(item, "widget", Empty())
            )

            # getting values
            function = Ops.get(item, "getCallback")
            ret2 = Builtins.eval(function) if function != nil
          end
        end
      end

      UI.CloseDialog

      ret
    end

    def ProposalDialog
      ret = LdapDatabase.AddDbBasic(true)
      if ret == :next
        AuthServer.SetInitialDefaults(LdapDatabase.GetDatabase)
        AuthServer.WriteLdapConfBase(LdapDatabase.GetLdapConfBase)
        ret = :mastersetup if AuthServer.ReadSetupMaster
      end

      ret
    end

    def TreeDialog
      #close service dialog
      #    UI::CloseDialog();
      Wizard.CreateTreeDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      #item selected at start
      @current_tree_item = "daemon"

      #trigger initial build of widget tree
      @rebuild_widget_tree = true

      ret = nil
      while true
        if @rebuild_widget_tree
          #generate tree
          Wizard.DeleteTreeItems
          deleteDynamicTreeItems
          generateDynamicTreeItems if AuthServer.ReadServiceRunning
          @widget_tree = generateTree
          if @widget_tree == nil
            Builtins.y2error(
              "error when generating widget tree: %1",
              @error_str
            )
          end

          # tree widget headline
          Wizard.CreateTree(@widget_tree, _("Configuration:"))

          #select&show current item
          @current_tree_item = showTreeDialog(
            @current_tree_item,
            @widget_tree == [] ? false : true
          )
          Wizard.SelectTreeItem(@current_tree_item)
          #initialize current dialog
          callHandler(@current_tree_item, "cb_read")
          @rebuild_widget_tree = false
        end
        event = UI.WaitForEvent
        ret = Ops.get(event, "ID")
        Builtins.y2milestone("TreeDialog: seeing return value %1", ret)

        if Ops.is_string?(ret) || ret == :wizardTree
          new_item = Wizard.QueryTreeItem

          # workaround to catch changes in the firewall widget
          if Ops.is_string?(ret) &&
              Builtins.issubstring(Convert.to_string(ret), "firewall")
            CWMFirewallInterfaces.OpenFirewallHandle(@fw_widget, "", event)
            next
          end

          #check values of current tree item
          Builtins.y2milestone(
            "wizard-->current item is %1",
            @current_tree_item
          )

          if !callHandler(@current_tree_item, "cb_check")
            Wizard.SelectTreeItem(@current_tree_item)
            next
          end

          if !callHandler(@current_tree_item, "cb_write")
            Wizard.SelectTreeItem(@current_tree_item)
            next
          end

          @current_tree_item = showTreeDialog(
            new_item,
            ret == :wizardTree ? true : false
          )
          if @current_tree_item == "__reread__"
            ret = :reread
            break
          end
          if @current_tree_item == "__empty__"
            ret = :empty
            break
          end
          Wizard.SelectTreeItem(@current_tree_item)

          callHandler(@current_tree_item, "cb_read")
        elsif Ops.is_symbol?(ret)
          sym_ret = Convert.to_symbol(ret)
          if sym_ret == :abort || sym_ret == :cancel
            if Popup.ReallyAbort(true)
              break
            else
              next
            end
          elsif sym_ret == :back || sym_ret == :reread
            break
          elsif sym_ret == :next
            next if !callHandler(@current_tree_item, "cb_check")
            next if !callHandler(@current_tree_item, "cb_write")
            break
          elsif Builtins.haskey(
              Ops.get(@widget_map, @current_tree_item, {}),
              "cb_input"
            )
            #call input handler of current tree item
            function = Ops.get(@widget_map, [@current_tree_item, "cb_input"])
            if function != nil
              ############### input handler ################
              @handler_cmd = sym_ret
              if !Convert.to_boolean(Builtins.eval(function))
                Report.Error(@callback_error)
                next
              end
            else
              Report.Error(
                Ops.add(
                  Ops.add(
                    "AuthServer Module: illegal input handler for item '",
                    @current_tree_item
                  ),
                  "'"
                )
              )
            end
          end
        end
      end
      deep_copy(ret)
    end

    def VerifyAdminPasswordPopup(bindparm, suffix)
      bindparm = deep_copy(bindparm)
      authinfo = AuthServer.ReadAuthInfo(suffix)
      pw = nil
      if Ops.greater_than(Builtins.size(authinfo), 0)
        if Ops.get(authinfo, "bind_dn", "1") ==
            Ops.get_string(bindparm, "bind_dn", "2")
          pw = Ops.get(authinfo, "bind_pw", "")
        end
      end
      Ldap.Set(bindparm)
      Ldap.LDAPInitWithTLSCheck({})
      state = :cont
      while state == :cont
        pw = Ldap.GetLDAPPassword(false) if pw == nil
        if pw == nil
          state = :cancel
        else
          err = Ldap.LDAPBind(pw)
          if err != ""
            pw = nil
            if !Popup.YesNo(
                Ops.add(
                  _("LDAP Authentication failed. Try again?\n") +
                    _("Error message: "),
                  err
                )
              )
              state = :cancel
            end
          else
            state = :ok
            AuthServer.WriteAuthInfo(
              suffix,
              {
                "bind_dn" => Ops.get_string(bindparm, "bind_dn", ""),
                "bind_pw" => pw
              }
            )
          end
        end
      end
      pw
    end

    def SyncreplAccountConfig(syncrepl)
      syncrepl = deep_copy(syncrepl)
      widget = HSquash(
        VBox(
          RadioButtonGroup(
            Id(:rbg_syncaccount),
            VBox(
              Left(
                RadioButton(
                  Id(:rb_createaccount),
                  Opt(:notify),
                  _("Create new account in the first database"),
                  true
                )
              ),
              Left(
                HBox(
                  HSpacing(2),
                  VBox(
                    Id(:vb_account_param),
                    Left(
                      HBox(
                        InputField(
                          Id(:if_uid),
                          Opt(:hstretch),
                          _("User Id"),
                          ""
                        ),
                        HSpacing(0.5),
                        InputField(
                          Id(:if_basedn),
                          Opt(:hstretch),
                          _("Container Object"),
                          ""
                        ),
                        HSpacing(0.5),
                        VBox(
                          VSpacing(0.5),
                          PushButton(Id(:pb_select_parent), _("Browse"))
                        )
                      )
                    ),
                    Left(
                      CheckBox(
                        Id(:cb_random_pw),
                        _("Generate a Random Password"),
                        true
                      )
                    )
                  )
                )
              ),
              VSpacing(0.3),
              Left(
                RadioButton(
                  Id(:rb_useconfig),
                  Opt(:notify),
                  _("Use the \"cn=config\" Account for Replication")
                )
              )
            )
          )
        )
      )

      db = AuthServer.ReadDatabase(1)
      suffix = Ops.get_string(db, "suffix", "")
      rootdn = Ops.get_string(db, "rootdn", "")

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ldap-server")
      Wizard.SetContents(
        _("Configure Account for Replication"),
        widget,
        "",
        true,
        true
      )

      UI.ChangeWidget(:if_uid, :Value, "syncrepl")
      UI.ChangeWidget(:if_basedn, :Value, Ops.add("ou=system,", suffix))
      ret = nil
      while true
        ret = UI.UserInput
        if ret == :rb_useconfig
          UI.ChangeWidget(:vb_account_param, :Enabled, false)
        elsif ret == :rb_createaccount
          UI.ChangeWidget(:vb_account_param, :Enabled, true)
        elsif ret == :pb_select_parent
          client = {
            "bind_dn"     => rootdn,
            "ldap_server" => Ops.get_string(
              syncrepl,
              ["provider", "target"],
              ""
            ),
            "ldap_tls"    => Ops.get_boolean(syncrepl, "starttls", true)
          }
          pw = VerifyAdminPasswordPopup(client, suffix)
          if pw != nil
            dn = LdapPopup.BrowseTree(suffix)
            UI.ChangeWidget(:if_basedn, :Value, dn) if dn != ""
          end
        end
        if ret == :next
          binddn = ""
          bindpw = ""
          if Convert.to_boolean(UI.QueryWidget(:rb_createaccount, :Value))
            binddn = Ops.add(
              Ops.add(
                Ops.add(
                  "uid=",
                  Convert.to_string(UI.QueryWidget(:if_uid, :Value))
                ),
                ","
              ),
              Convert.to_string(UI.QueryWidget(:if_basedn, :Value))
            )
            if !AuthServer.ValidateDn(binddn)
              Popup.Error(
                Ops.add(
                  Ops.add(Ops.add("\"", binddn), "\""),
                  _("is not a valid LDAP DN")
                )
              )
              next
            end
            if Convert.to_boolean(UI.QueryWidget(:cb_random_pw, :Value))
              bindpw = AuthServer.GenerateRandPassword
            else
              askPwWidget = HSquash(
                VSquash(
                  VBox(
                    Password(Id(:te_pw), Opt(:hstretch), _("Password")),
                    HSpacing(0.5),
                    Password(
                      Id(:te_valid_pw),
                      Opt(:hstretch),
                      _("Validate Password")
                    ),
                    HSpacing(0.5),
                    Wizard.CancelOKButtonBox
                  )
                )
              )
              UI.OpenDialog(Opt(:decorated), askPwWidget)
              ret1 = nil
              while true
                ret1 = UI.UserInput
                if ret1 == :cancel
                  bindpw = ""
                  break
                elsif ret1 == :ok
                  pw = Convert.to_string(UI.QueryWidget(:te_pw, :Value))
                  verifypw = Convert.to_string(
                    UI.QueryWidget(:te_valid_pw, :Value)
                  )
                  if Builtins.size(pw) == 0
                    Popup.Error(_("Enter a password"))
                    UI.ChangeWidget(:te_pw, :Value, "")
                    UI.ChangeWidget(:te_valid_pw, :Value, "")
                  elsif pw == verifypw
                    bindpw = pw
                    break
                  else
                    Popup.Error(
                      _(
                        "The passwords you have entered do not match. Try again."
                      )
                    )
                    UI.ChangeWidget(:te_pw, :Value, "")
                    UI.ChangeWidget(:te_valid_pw, :Value, "")
                  end
                end
              end
              UI.CloseDialog
              next if ret1 != :ok
            end
            AuthServer.WriteSyncReplAccount(
              { "dn" => binddn, "pw" => bindpw, "dbsuffix" => suffix }
            )
            Ops.set(syncrepl, "binddn", binddn)
            Ops.set(syncrepl, "credentials", bindpw)
          else
            Ops.set(syncrepl, "binddn", "cn=config")
          end
          break
        end
      end
      Wizard.CloseDialog
      deep_copy(syncrepl)
    end

    def SlaveSetupDialog
      widget = HSquash(
        VBox(
          Heading(_("Provider Details")),
          VSpacing(0.3),
          VSpacing(),
          VSquash(
            HBox(
              ComboBox(
                Id(:cb_sync_prot),
                Opt(:notify),
                _("Protocol"),
                ["ldap", "ldaps"]
              ),
              HSpacing(),
              InputField(
                Id(:te_sync_target),
                Opt(:hstretch),
                _("Provider Hostname"),
                ""
              ),
              HSpacing(),
              HSquash(IntField(Id(:if_sync_port), "Port", 0, 65536, 389)),
              HSpacing(),
              VBox(
                Bottom(CheckBox(Id(:cb_start_tls), _("Use StartTLS"), true)),
                VSpacing(0.3)
              )
            )
          ),
          VSpacing(0.3),
          Password(
            Id(:te_config_cred),
            Opt(:hstretch),
            _("Administration Password for the \"cn=config\" Database"),
            ""
          ),
          VSpacing(0.3),
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
          )
        )
      )

      Wizard.SetContentsButtons(
        @caption,
        widget,
        Ops.get_string(@HELPS, "slave_dialog", "help not found"),
        Label.BackButton,
        Label.NextButton
      )
      ret = nil
      cacert = "/etc/ssl/certs/YaST-CA.pem"

      while true
        UI.ChangeWidget(:cb_start_tls, :Enabled, false)
        UI.ChangeWidget(:te_ca_file, :Value, cacert)
        synbase = AuthServer.ReadSyncreplBaseConfig
        if Ops.greater_than(Builtins.size(synbase), 0)
          UI.ChangeWidget(
            :cb_sync_prot,
            :Value,
            Ops.get_string(synbase, ["provider", "protocol"], "")
          )
          UI.ChangeWidget(
            :te_sync_target,
            :Value,
            Ops.get_string(synbase, ["provider", "target"], "")
          )
          UI.ChangeWidget(
            :if_sync_port,
            :Value,
            Ops.get_integer(synbase, ["provider", "port"], 389)
          )
          UI.ChangeWidget(
            :cb_start_tls,
            :Value,
            Ops.get_boolean(synbase, "start_tls", true)
          )
          UI.ChangeWidget(
            :te_config_cred,
            :Value,
            Ops.get_string(synbase, "credentials", "")
          )
          AuthServer.WriteSyncreplBaseConfig({})

          ret = :next
        else
          ret = UI.UserInput
        end
        Builtins.y2milestone("SlaveSetupDialog: seeing return value '%1'", ret)
        if ret == :pb_ca_file
          name = UI.AskForExistingFile(
            "/etc/ssl/certs",
            "*.pem *.crt *",
            _("Select CA Certificate File")
          )
          cacert = name if name != nil
          next
        elsif ret == :next
          if cacert == "" || cacert == nil
            Popup.Error(_("Select a Valid CA Certificate File"))
            next
          end

          # test connection
          provider = {
            "protocol" => Convert.to_string(
              UI.QueryWidget(:cb_sync_prot, :Value)
            ),
            "target"   => Convert.to_string(
              UI.QueryWidget(:te_sync_target, :Value)
            ),
            "port"     => Convert.to_integer(
              UI.QueryWidget(:if_sync_port, :Value)
            )
          }

          testparm = {}
          testparm = Builtins.add(testparm, "target", provider)
          if Ops.get_string(provider, "protocol", "ldap") == "ldap"
            testparm = Builtins.add(testparm, "starttls", true)
          else
            testparm = Builtins.add(testparm, "starttls", false)
          end
          testparm = Builtins.add(testparm, "basedn", "cn=config")
          testparm = Builtins.add(testparm, "binddn", "cn=config")
          testparm = Builtins.add(
            testparm,
            "credentials",
            Convert.to_string(UI.QueryWidget(:te_config_cred, :Value))
          )
          if cacert != "" && cacert != nil
            testparm = Builtins.add(testparm, "cacert", cacert)
          end

          if !AuthServer.ReadModeInstProposal # Doing these checks during installation will
            # most probably fail
            if !AuthServer.InitRemoteConnection(testparm)
              err = AuthServer.ReadError
              Popup.ErrorDetails(
                _(
                  "Failed to open connection to the \"cn=config\" database on the provider server.\n"
                ) +
                  _(
                    "Verify that the provider server allows remote connections to the \n\"cn=config\" database and that you entered the correct password.\n"
                  ),
                Ops.add(
                  Ops.add(
                    Ops.add(
                      Ops.add(
                        _("The following error messages were returned:") + "\n\n\"",
                        Ops.get_string(err, "msg", "")
                      ),
                      "\"\n\""
                    ),
                    Ops.get_string(err, "details", "")
                  ),
                  "\""
                )
              )
              next
            end
            if !AuthServer.VerifyTlsSetup(Ops.get_map(testparm, "target", {}))
              err = AuthServer.ReadError
              Popup.ErrorDetails(
                _(
                  "An error occurred while verifying the TLS/SSL configuration."
                ),
                Ops.add(
                  Ops.add(
                    Ops.add(Ops.get_string(err, "msg", ""), "\n"),
                    Ops.get_string(err, "details", "")
                  ),
                  "\n"
                )
              )
              if Popup.YesNo(
                  _("Do you want to import a different CA/Server Certificate?")
                )
                WFM.CallFunction("common_cert", [])
              end
              next
            end
            # Check if the syncrepl config of cn=config makes sense
            srl = AuthServer.ReadSyncRepl(0)
            syncrepl = Ops.get(srl, 0, {})
            if Builtins.size(syncrepl) == 0
              if Popup.ContinueCancel(
                  _(
                    "The replication configuration on the provider server is missing.\n"
                  ) +
                    _("Click Continue to create it now.")
                )
                syncrepl = {
                  "provider"    => Ops.get_map(testparm, "target", {}),
                  "starttls"    => Ops.get_boolean(testparm, "starttls", true),
                  "binddn"      => Ops.get_string(
                    testparm,
                    "binddn",
                    "cn=config"
                  ),
                  "credentials" => Ops.get_string(testparm, "credentials", ""),
                  "type"        => "refreshAndPersist"
                }
              else
                ret = :cancel
                break
              end
            else
              # 1. Verify that the provider uri points to the provider itself
              if Builtins.size(srl) == 1 # this test needs only be done in a non-MirrorMode setup
                provider2 = Ops.get_map(syncrepl, "provider", {})
                setupok = true
                if Ops.greater_than(Builtins.size(provider2), 0)
                  if Ops.get_string(provider2, "target", "") !=
                      Ops.get_string(testparm, ["target", "target"], "")
                    Builtins.y2error(
                      "Provider target names do not match: <%1> vs. <%2>",
                      Ops.get_string(provider2, "target", ""),
                      Ops.get_string(testparm, ["target", "target"], "")
                    )
                    setupok = false
                  end
                  if Ops.get_string(provider2, "protocol", "") !=
                      Ops.get_string(testparm, ["target", "protocol"], "")
                    Builtins.y2error(
                      "Provider protocols do not match: <%1> vs. <%2>",
                      Ops.get_string(provider2, "protocol", ""),
                      Ops.get_string(testparm, ["target", "protocol"], "")
                    )
                    setupok = false
                  end
                  if Ops.get_integer(provider2, "port", 0) !=
                      Ops.get_integer(testparm, ["target", "port"], 0)
                    Builtins.y2error(
                      "Provider ports do not match: <%1> vs. <%2>",
                      Ops.get_string(provider2, "port", ""),
                      Ops.get_string(testparm, ["target", "port"], "")
                    )
                    setupok = false
                  end
                  if !setupok
                    Popup.Error(
                      _(
                        "The replication configuration on the master server indicates that\nit is already acting as a replication consumer.\n"
                      ) +
                        _(
                          "Setting up cascaded replication of the cn=config is currently not supported."
                        )
                    )
                    ret = :cancel
                    break
                  end
                end
              end
              # 2. Verify that the binddn/credential combination acutally works
              bindtestparm = {
                "target"      => Ops.get_map(syncrepl, "provider", {}),
                "starttls"    => Ops.get_boolean(syncrepl, "starttls", true),
                "basedn"      => Ops.get_string(syncrepl, "basedn", ""),
                "binddn"      => Ops.get_string(syncrepl, "binddn", ""),
                "credentials" => Ops.get_string(syncrepl, "credentials", "")
              }
              if !Convert.to_boolean(
                  SCR.Execute(path(".ldapserver.remoteBindCheck"), bindtestparm)
                )
                err = SCR.Error(path(".ldapserver"))
                if Popup.ContinueCancel(
                    Ops.add(
                      Ops.add(
                        Ops.add(
                          Ops.add(
                            Ops.add(
                              _(
                                "Checking the authentication credentials defined in the replication configuration on the provider server failed.\n"
                              ) +
                                _(
                                  "The test returned the following error messages:"
                                ) + "\n\n\"",
                              Ops.get_string(err, "summary", "")
                            ),
                            "\"\n\""
                          ),
                          Ops.get_string(err, "description", "")
                        ),
                        "\"\n\n"
                      ),
                      _("Click \"Continue\" to correct this now.")
                    )
                  )
                  syncrepl = SyncreplAccountConfig(syncrepl)
                  if Ops.get_string(syncrepl, "binddn", "") == "cn=config"
                    Ops.set(
                      syncrepl,
                      "credentials",
                      Ops.get_string(testparm, "credentials", "")
                    ) # Get admin password if we don't have it already
                  else
                    db = AuthServer.ReadDatabase(1)
                    suffix = Ops.get_string(db, "suffix", "")
                    rootdn = Ops.get_string(db, "rootdn", "")
                    if Builtins.size(AuthServer.ReadAuthInfo(suffix)) == 0
                      authinfo_firstdb = {}
                      client = {
                        "bind_dn"     => rootdn,
                        "ldap_server" => Ops.get_string(
                          syncrepl,
                          ["provider", "target"],
                          ""
                        ),
                        "ldap_tls"    => Ops.get_boolean(
                          syncrepl,
                          "starttls",
                          true
                        )
                      }
                      VerifyAdminPasswordPopup(client, suffix)
                    end
                  end
                else
                  ret = :cancel
                  break
                end
              end
            end
            AuthServer.WriteSyncreplBaseConfig(syncrepl)
            AuthServer.WriteAuthInfo(
              "cn=config",
              {
                "bind_dn" => "cn=config",
                "bind_pw" => Ops.get_string(testparm, "credentials", "")
              }
            )
            break # we were called during the Installation Proposal
          else
            syncrepl = {
              "provider"    => Ops.get_map(testparm, "target", {}),
              "starttls"    => Ops.get_boolean(testparm, "starttls", true),
              "binddn"      => Ops.get_string(testparm, "binddn", "cn=config"),
              "credentials" => Ops.get_string(testparm, "credentials", ""),
              "type"        => "refreshAndPersist"
            }
            AuthServer.WriteSyncreplBaseConfig(syncrepl)
          end
        end
        if ret == :cb_sync_prot
          prot = Convert.to_string(UI.QueryWidget(:cb_sync_prot, :Value))
          port = Convert.to_integer(UI.QueryWidget(:if_sync_port, :Value))
          if prot == "ldaps"
            UI.ChangeWidget(:cb_start_tls, :Value, false)
            UI.ChangeWidget(:if_sync_port, :Value, 636) if port == 389
          else
            UI.ChangeWidget(:cb_start_tls, :Value, true)
            UI.ChangeWidget(:if_sync_port, :Value, 389) if port == 636
          end
          next
        end
        break
      end
      if ret != :next
        # reset remote connection
        SCR.Execute(path(".ldapserver.reset"))
      end

      deep_copy(ret)
    end

    # ReplicatonSummary dialog
    # @return dialog result
    def ReplicatonSetupSummaryDialog
      ret = nil

      AuthServer.SetupRemoteForReplication
      AuthServer.ReadFromDefaults
      ret = :next
      deep_copy(ret)
    end

    def MasterSetupDialog
      widget = HSquash(
        VSquash(
          VBox(
            Heading(_("Replication Master setup")),
            VSpacing(0.5),
            Label(
              _(
                "To act as a master server for replication, the configuration database needs\nto be remotely accessible. Set a password for the configuration database.\n"
              ) +
                _(
                  "\n" +
                    "(Remote access to the Configuration database will be restricted to encrypted\n" +
                    "LDAP Connections.)\n"
                )
            ),
            VSpacing(0.5),
            Password(Id(:te_rootpw), Opt(:hstretch), _("Enter new &Password")),
            VSpacing(0.5),
            Password(
              Id(:te_valid_rootpw),
              Opt(:hstretch),
              _("&Validate Password")
            ),
            VSpacing(0.5),
            Left(
              CheckBox(
                Id(:cb_mirror_mode),
                _(
                  "Prepare for MirrorMode replication (generates the serverId attribute)"
                )
              )
            )
          )
        )
      )
      Wizard.SetContentsButtons(
        @caption,
        widget,
        Ops.get_string(@HELPS, "master_setup_dialog", "help not found"),
        Label.BackButton,
        Label.NextButton
      )
      ret = nil
      while true
        ret = UI.UserInput
        if ret == :next
          pw = Convert.to_string(UI.QueryWidget(:te_rootpw, :Value))
          verifypw = Convert.to_string(UI.QueryWidget(:te_valid_rootpw, :Value))
          if Builtins.size(pw) == 0
            Popup.Error(_("Enter a password"))
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
          elsif pw != verifypw
            Popup.Error(
              _("The passwords you have entered do not match. Try again.")
            )
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
            pw = ""
            verifypw = ""
          else
            defaults = AuthServer.CreateInitialDefaults
            Ops.set(defaults, "configpw", pw)
            AuthServer.SetInitialDefaults(defaults)
            AuthServer.WriteSetupMirrorMode(
              Convert.to_boolean(UI.QueryWidget(:cb_mirror_mode, :Value))
            )
            break
          end
        else
          break
        end
      end
      deep_copy(ret)
    end
  end
end
