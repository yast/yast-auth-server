# encoding: utf-8

# File:	include/ldap-server/tree_structure.ycp
# Package:	Configuration of ldap-server
# Summary:	Widget Tree structure
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
module Yast
  module AuthServerTreeStructureInclude
    def initialize_auth_server_tree_structure(include_target)
      Yast.import "UI"
      textdomain "auth-server"

      Yast.import "AuthServer"
      Yast.import "LdapDatabase"
      Yast.import "Report"
      Yast.import "Label"
      Yast.import "HTML"
      Yast.import "String"

      Yast.include include_target, "auth-server/widgets.rb"

      # forward declaration of the widget tree
      @widget_map = nil

      # error string, all callbacks return false and set this to an error description
      @callback_error = ""

      @widget_tree = nil
      # this is set to true when the widget tree must be rebuilt, that is, when dynamic tree
      # items are added/removed
      @rebuild_widget_tree = true

      # command for input handlers, is set in the main UserInput loop in dialogs.ycp
      # --> pseudo function argument for input callbacks
      @handler_cmd = nil

      # current_tree_item, is set in main UserInput loop. The widget_map key of the currently
      # active tree item. Used by callbacks of dynamic items.
      # --> pseudo function argument for dynamic callbacks
      @current_tree_item = ""


      #****************************************
      #*     tree structure definition       **
      #***************************************
      @widget_map = {
        "base"       => {
          "children" => ["daemon", "global", "schema", "databases"]
        },
        "daemon"     => {
          "name"      => _("Startup Configuration"),
          "widget"    => @dlg_service,
          "cb_read"   => lambda { cb_read_daemon },
          "cb_write"  => lambda { cb_write_daemon },
          "help_page" => "startup_config"
        },
        "global"     => {
          "children" => ["g_loglevel", "g_allow", "g_tls"],
          # Tree item
          "name"     => _("Global Settings"),
          "widget"   => Empty()
        },
        "schema"     => {
          # Tree item
          "name"     => _("Schema Files"),
          "widget"   => @schemaWidget,
          "inclist"  => [],
          "cb_read"  => lambda { cb_read_schema },
          "cb_input" => lambda { cb_input_schema }
        },
        "g_loglevel" => {
          # Tree item
          "name"     => _("Log Level Settings"),
          "widget"   => @loglevelWidget,
          "cb_check" => lambda { cb_check_loglevel },
          "cb_read"  => lambda { cb_read_loglevel },
          "cb_write" => lambda { cb_write_loglevel }
        },
        "g_allow"    => {
          # Tree item
          "name"     => _("Allow/Disallow Features"),
          "widget"   => @allowWidget,
          "cb_check" => lambda { cb_check_allow },
          "cb_read"  => lambda { cb_read_allow },
          "cb_write" => lambda { cb_write_allow }
        },
        "g_tls"      => {
          # Tree item
          "name"      => _("TLS Settings"),
          "widget"    => @tlsWidget,
          "cb_read"   => lambda { cb_read_tls },
          "cb_write"  => lambda { cb_write_tls },
          "cb_input"  => lambda { cb_input_tls },
          "help_page" => "tls_dialog"
        },
        "databases"  => {
          # Tree item
          "name"     => _("Databases"),
          "widget"   => VBox(
            MinSize(
              60,
              7,
              Table(
                Id(:tab_db),
                Opt(:keepSorting),
                Header(_("Suffix DN"), _("Database Type"))
              )
            ),
            Left(
              HBox(
                PushButton(Id(:pb_add), Label.AddButton),
                PushButton(Id(:pb_del), Label.DeleteButton)
              )
            )
          ),
          "cb_read"  => lambda { cb_read_databases },
          "cb_write" => lambda { cb_write_databases },
          "cb_input" => lambda { cb_input_databases }
        }
      }
    end

    #********************************
    #*     callback handlers       **
    #*******************************

    #****************************
    #* default handlers
    #***************************

    def cb_check_default
      Builtins.y2milestone("calling default check handler")
      true
    end

    def cb_read_default
      Builtins.y2milestone("calling default read handler")
      true
    end

    def cb_write_default
      Builtins.y2milestone("calling default write handler")
      true
    end

    #****************************
    #* global schema handlers
    #***************************

    def update_schemalist(l)
      l = deep_copy(l)
      l = [] if l == nil
      #widget_map["g_schema","inclist"] = l;
      UI.ChangeWidget(:sb_schemalist, :Items, l)
      UI.ChangeWidget(:pb_del, :Enabled, false)

      nil
    end

    def cb_read_daemon
      Builtins.y2milestone("calling read handler for item \"daemon\"")
      enabled = AuthServer.ReadServiceEnabled
      CWMFirewallInterfaces.OpenFirewallInit(@fw_widget, "")
      if enabled
        UI.ChangeWidget(:rb_service_enable, :CurrentButton, :rb_yes)
      else
        UI.ChangeWidget(:rb_service_enable, :CurrentButton, :rb_no)
      end
      if AuthServer.ReadSLPEnabled
        UI.ChangeWidget(:cb_register_slp, :Value, true)
      else
        UI.ChangeWidget(:cb_register_slp, :Value, false)
      end
      if AuthServer.ReadProtocolListenerEnabled("ldap")
        UI.ChangeWidget(:cb_interface_ldap, :Value, true)
      else
        UI.ChangeWidget(:cb_interface_ldap, :Value, false)
      end
      if AuthServer.ReadProtocolListenerEnabled("ldaps")
        UI.ChangeWidget(:cb_interface_ldaps, :Value, true)
      else
        UI.ChangeWidget(:cb_interface_ldaps, :Value, false)
      end
      true
    end

    def cb_write_daemon
      Builtins.y2milestone("calling write handler for item \"daemon\"")

      serviceEnabled = Convert.to_symbol(
        UI.QueryWidget(Id(:rb_service_enable), :CurrentButton)
      )
      CWMFirewallInterfaces.OpenFirewallStore(@fw_widget, "", {})
      if serviceEnabled == :rb_yes
        AuthServer.WriteServiceEnabled(true)
      else
        AuthServer.WriteServiceEnabled(false)
      end

      AuthServer.WriteSLPEnabled(
        Convert.to_boolean(UI.QueryWidget(Id(:cb_register_slp), :Value))
      )
      AuthServer.WriteProtocolListenerEnabled(
        "ldap",
        Convert.to_boolean(UI.QueryWidget(Id(:cb_interface_ldap), :Value))
      )
      AuthServer.WriteProtocolListenerEnabled("ldapi", true)
      if Convert.to_boolean(UI.QueryWidget(Id(:cb_interface_ldaps), :Value))
        tls = AuthServer.ReadTlsConfig
        if Ops.get_string(tls, "caCertFile", "") != "" &&
            Ops.get_string(tls, "certFile", "") != "" &&
            Ops.get_string(tls, "certKeyFile", "") != ""
          AuthServer.WriteProtocolListenerEnabled("ldaps", true)
        else
          if Popup.YesNoHeadline(
              _("Your TLS/SSL Configuration seems to be incomplete."),
              _("Do you really want to enable the \"ldaps\" protocol listener?")
            )
            AuthServer.WriteProtocolListenerEnabled("ldaps", true)
          else
            AuthServer.WriteProtocolListenerEnabled("ldaps", false)
          end
        end
      else
        AuthServer.WriteProtocolListenerEnabled("ldaps", false)
      end
      true
    end

    def cb_read_schema
      Builtins.y2milestone("calling schema read handler")
      inclist = AuthServer.ReadSchemaList
      update_schemalist(inclist)
      true
    end

    def cb_input_schema
      Builtins.y2milestone("calling schema input handler")


      inclist = AuthServer.ReadSchemaList
      current_item = Convert.to_string(
        UI.QueryWidget(:sb_schemalist, :CurrentItem)
      )
      Builtins.y2milestone("current_item is '%1'", current_item)

      if @handler_cmd == :pb_add
        #add a new file to the list
        # file dialog heading
        new_item = UI.AskForExistingFile(
          "/etc/openldap/schema/",
          "*.ldif *",
          _("Select New Schema File")
        )

        return true if new_item == nil

        if Builtins.contains(inclist, new_item)
          # error popup
          @callback_error = _("The schema file is already in the list.")
          return false
        end
        if Builtins.regexpmatch(new_item, ".*.schema$")
          if !AuthServer.AddSchemaToSchemaList(new_item)
            err = AuthServer.ReadError
            @callback_error = Ops.add(
              Ops.add(Ops.get(err, "msg", ""), "\n"),
              Ops.get(err, "details", "")
            )
            return false
          end
          inclist2 = AuthServer.ReadSchemaList
          update_schemalist(inclist2)
        elsif !AuthServer.AddLdifToSchemaList(new_item)
          err = AuthServer.ReadError
          @callback_error = Ops.add(
            Ops.add(Ops.get(err, "msg", ""), "\n"),
            Ops.get(err, "details", "")
          )
          return false
        else
          inclist2 = AuthServer.ReadSchemaList
          update_schemalist(inclist2)
        end 
        # Deleteing Schema ist not supported on the server side yet
      elsif @handler_cmd == :pb_del
        return true if current_item == nil
        AuthServer.RemoveFromSchemaList(current_item)
        inclist2 = AuthServer.ReadSchemaList
        update_schemalist(inclist2)
      elsif @handler_cmd == :sb_schemalist
        if AuthServer.IsSchemaDeletable(current_item)
          UI.ChangeWidget(:pb_del, :Enabled, true)
        else
          UI.ChangeWidget(:pb_del, :Enabled, false)
        end
      end

      true
    end

    #****************************
    #* global loglevel handlers
    #***************************

    def cb_check_loglevel
      true
    end

    def cb_read_loglevel
      Builtins.y2milestone("calling loglevel read handler")
      lvls = AuthServer.ReadLogLevels

      UI.ChangeWidget(:msb_loglevel, :SelectedItems, lvls)
      true
    end

    def cb_write_loglevel
      Builtins.y2milestone("calling loglevel write handler")
      idlist = Convert.convert(
        UI.QueryWidget(:msb_loglevel, :SelectedItems),
        :from => "any",
        :to   => "list <string>"
      )

      Builtins.y2milestone("writing loglevel: '%1'", idlist)
      AuthServer.WriteLogLevels(idlist)
    end

    #****************************
    #* global allow handlers
    #***************************

    def cb_check_allow
      true
    end

    def cb_read_allow
      Builtins.y2milestone("calling allow read handler")
      allowlist = AuthServer.ReadAllowFeatures
      disallowlist = AuthServer.ReadDisallowFeatures
      UI.ChangeWidget(:msb_allow, :SelectedItems, allowlist)
      UI.ChangeWidget(:msb_disallow, :SelectedItems, disallowlist)
      true
    end

    def cb_write_allow
      Builtins.y2milestone("calling allow write handler")
      allowlist = []
      disallowlist = []
      allowlist = Convert.convert(
        UI.QueryWidget(:msb_allow, :SelectedItems),
        :from => "any",
        :to   => "list <string>"
      )
      disallowlist = Convert.convert(
        UI.QueryWidget(:msb_disallow, :SelectedItems),
        :from => "any",
        :to   => "list <string>"
      )

      Builtins.y2milestone("writing allowlist: '%1'", allowlist)
      AuthServer.WriteAllowFeatures(allowlist)
      AuthServer.WriteDisallowFeatures(disallowlist)
      true
    end

    #****************************
    #* tls handlers
    #***************************

    def cb_read_tls
      Builtins.y2milestone("calling tls read handler")
      tls = AuthServer.ReadTlsConfig
      Builtins.y2milestone("tls config %1", tls)
      if (Ops.get_string(tls, "caCertFile", "") != "" ||
          Ops.get_string(tls, "caCertDir", "") != "") &&
          Ops.get_string(tls, "certFile", "") != "" &&
          Ops.get_string(tls, "certKeyFile", "") != ""
        UI.ChangeWidget(:cb_tls_enabled, :Value, true)
        UI.ChangeWidget(:cb_ssl_listener_enabled, :Enabled, true)

        if Ops.get_string(tls, "caCertFile", "") == "/etc/ssl/certs/YaST-CA.pem" &&
            Ops.get_string(tls, "certFile", "") ==
              "/etc/ssl/servercerts/servercert.pem" &&
            Ops.get_string(tls, "certKeyFile", "") ==
              "/etc/ssl/servercerts/serverkey.pem"
          UI.ChangeWidget(:cb_use_common_cert, :Value, true)
          UI.ChangeWidget(:fr_import_cert, :Enabled, false)
        else
          UI.ChangeWidget(:cb_use_common_cert, :Value, false)
          UI.ChangeWidget(:fr_import_cert, :Enabled, true)
        end
      else
        UI.ChangeWidget(:cb_ssl_listener_enabled, :Enabled, false)
        UI.ChangeWidget(:cb_use_common_cert, :Enabled, false)
        UI.ChangeWidget(:fr_import_cert, :Enabled, false)
      end
      UI.ChangeWidget(
        :cb_ssl_listener_enabled,
        :Value,
        AuthServer.ReadProtocolListenerEnabled("ldaps")
      )
      UI.ChangeWidget(
        :te_ca_file,
        :Value,
        Ops.get_string(tls, "caCertFile", "")
      )
      UI.ChangeWidget(
        :te_cert_file,
        :Value,
        Ops.get_string(tls, "certFile", "")
      )
      UI.ChangeWidget(
        :te_key_file,
        :Value,
        Ops.get_string(tls, "certKeyFile", "")
      )

      true
    end

    def cb_write_tls
      Builtins.y2milestone("calling tls write handler")
      tls_active = Convert.to_boolean(UI.QueryWidget(:cb_tls_enabled, :Value))
      if tls_active == true
        cafile = Convert.to_string(UI.QueryWidget(:te_ca_file, :Value))

        tlsSettings = {
          "certKeyFile"  => Convert.to_string(
            UI.QueryWidget(:te_key_file, :Value)
          ),
          "certFile"     => Convert.to_string(
            UI.QueryWidget(:te_cert_file, :Value)
          ),
          "caCertFile"   => Convert.to_string(
            UI.QueryWidget(:te_ca_file, :Value)
          ),
          "caCertDir"    => "",
          "crlFile"      => "",
          "crlCheck"     => 0,
          "verifyClient" => 0,
          "tls_active"   => true
        }
        if Ops.get_string(tlsSettings, "caCertFile", "") == ""
          @callback_error = _("Select a Valid CA Certificate File")
          return false
        end
        if Ops.get_string(tlsSettings, "certFile", "") == ""
          @callback_error = _("Select a valid Certificate File")
          return false
        end
        if Ops.get_string(tlsSettings, "certKeyFile", "") == ""
          @callback_error = _("Select a valid Certificate Key File")
          return false
        end
        if !AuthServer.WriteTlsConfig(tlsSettings)
          err = AuthServer.ReadError
          @callback_error = Ops.add(
            Ops.get(err, "msg", ""),
            Ops.get(err, "details", "")
          )
          return false
        end
        AuthServer.WriteProtocolListenerEnabled(
          "ldaps",
          Convert.to_boolean(
            UI.QueryWidget(Id(:cb_ssl_listener_enabled), :Value)
          )
        )
      else
        tlsSettings = {
          "tls_active"   => false,
          "certKeyFile"  => "",
          "certFile"     => "",
          "caCertFile"   => "",
          "caCertDir"    => "",
          "crlFile"      => "",
          "crlCheck"     => 0,
          "verifyClient" => 0
        }

        AuthServer.WriteTlsConfig(tlsSettings)
        AuthServer.WriteProtocolListenerEnabled("ldaps", false)
      end
      true
    end

    def cb_input_tls
      Builtins.y2milestone("calling tls input handler")

      common_cert_available = AuthServer.HaveCommonServerCertificate

      if @handler_cmd == :cb_tls_enabled
        tls_enabled_cb = Convert.to_boolean(
          UI.QueryWidget(:cb_tls_enabled, :Value)
        )
        if tls_enabled_cb
          UI.ChangeWidget(:cb_ssl_listener_enabled, :Enabled, true)
          UI.ChangeWidget(:cb_ssl_listener_enabled, :Value, true)
          if common_cert_available
            UI.ChangeWidget(:cb_use_common_cert, :Enabled, true)
            UI.ChangeWidget(:cb_use_common_cert, :Value, true)
            UI.ChangeWidget(:te_ca_file, :Value, "/etc/ssl/certs/YaST-CA.pem")
            UI.ChangeWidget(
              :te_cert_file,
              :Value,
              "/etc/ssl/servercerts/servercert.pem"
            )
            UI.ChangeWidget(
              :te_key_file,
              :Value,
              "/etc/ssl/servercerts/serverkey.pem"
            )
            UI.ChangeWidget(:fr_import_cert, :Enabled, false)
          else
            UI.ChangeWidget(:fr_import_cert, :Enabled, true)
          end
        else
          UI.ChangeWidget(:cb_ssl_listener_enabled, :Enabled, false)
          UI.ChangeWidget(:cb_use_common_cert, :Enabled, false)
          UI.ChangeWidget(:fr_import_cert, :Enabled, false)
        end
      elsif @handler_cmd == :cb_use_common_cert
        use_common_cert = Convert.to_boolean(
          UI.QueryWidget(:cb_use_common_cert, :Value)
        )
        if use_common_cert
          if common_cert_available
            UI.ChangeWidget(:te_ca_file, :Value, "/etc/ssl/certs/YaST-CA.pem")
            UI.ChangeWidget(
              :te_cert_file,
              :Value,
              "/etc/ssl/servercerts/servercert.pem"
            )
            UI.ChangeWidget(
              :te_key_file,
              :Value,
              "/etc/ssl/servercerts/serverkey.pem"
            )
            UI.ChangeWidget(:fr_import_cert, :Enabled, false)
          else
            Popup.Error(_("A common server certificate is not available."))
            UI.ChangeWidget(:cb_use_common_cert, :Value, false)
            UI.ChangeWidget(:cb_use_common_cert, :Enabled, false)
          end
        else
          UI.ChangeWidget(:fr_import_cert, :Enabled, true)
        end
      elsif @handler_cmd == :pb_ca_file
        # file selection headline
        name = UI.AskForExistingFile(
          "/etc/ssl/certs",
          "*.pem *.crt *",
          _("Select CA Certificate File")
        )
        UI.ChangeWidget(:te_ca_file, :Value, name) if name != nil
      elsif @handler_cmd == :pb_cert_file
        # file selection headline
        name = UI.AskForExistingFile(
          "/var/lib/CAM",
          "*.pem *.crt *",
          _("Select Certificate File")
        )
        UI.ChangeWidget(:te_cert_file, :Value, name) if name != nil
      elsif @handler_cmd == :pb_key_file
        # file selection headline
        name = UI.AskForExistingFile(
          "/var/lib/CAM",
          "*.pem *.crt *",
          _("Select Certificate Key File")
        )
        UI.ChangeWidget(:te_key_file, :Value, name) if name != nil
      elsif @handler_cmd == :pb_launch_ca
        WFM.CallFunction("ca_mgm", [])
        cb_read_tls
      end
      #reread tls page
      true
    end

    #****************************************
    #* handlers for database parent widget
    #***************************************

    def cb_read_databases
      Builtins.y2milestone("calling databases read handler")
      dblist = AuthServer.ReadDatabaseList

      pos = -1
      itemlist = Builtins.maplist(dblist) do |v|
        pos = Ops.add(pos, 1)
        Item(
          Id(pos),
          Ops.get_string(v, "suffix", ""),
          Ops.get_string(v, "type", "")
        )
      end
      UI.ChangeWidget(:tab_db, :Items, itemlist)
      true
    end

    def cb_write_databases
      true
    end

    def cb_input_databases
      Builtins.y2milestone("calling databases input handler")
      if @handler_cmd == :pb_add
        ret = nil
        ret = LdapDatabase.AddDbWizard
        Builtins.y2milestone("Database wizard returned %1", ret)
        if ret == :next
          @rebuild_widget_tree = true
          newDb = LdapDatabase.GetDatabase
          if !AuthServer.AddDatabase(
              0,
              newDb,
              LdapDatabase.GetCreateDir,
              LdapDatabase.GetCreateBase
            )
            err = AuthServer.ReadError
            @callback_error = Ops.add(
              Ops.add(Ops.get(err, "msg", ""), "\n"),
              Ops.get(err, "details", "")
            )
            return false
          end
          LdapDatabase.ResetCreateBase
          syncrepl = LdapDatabase.GetSyncRepl
          if Ops.greater_than(Builtins.size(syncrepl), 0) &&
              Ops.greater_than(
                Builtins.size(Ops.get_map(syncrepl, "syncrepl", {})),
                0
              )
            dblist = AuthServer.ReadDatabaseList
            dbindex = 0
            Builtins.foreach(dblist) do |db|
              if Ops.get(db, "suffix", "") ==
                  Ops.get_string(newDb, "suffix", "")
                dbindex = Builtins.tointeger(Ops.get(db, "index", "0"))
                raise Break
              end
            end
            if Ops.greater_than(dbindex, 0)
              if !AuthServer.WriteSyncRepl(
                  dbindex,
                  Ops.get_map(syncrepl, "syncrepl", {})
                )
                err = AuthServer.ReadError
                @callback_error = Ops.add(
                  Ops.add(Ops.get(err, "msg", ""), "\n"),
                  Ops.get(err, "details", "")
                )
                return false
              end
              AuthServer.WriteUpdateRef(
                dbindex,
                Ops.get_map(syncrepl, "updateref", {})
              )
            end
          end
          ppolicy = LdapDatabase.GetPpolicy
          if Ops.greater_than(Builtins.size(ppolicy), 0)
            dblist = AuthServer.ReadDatabaseList
            dbindex = 0
            Builtins.foreach(dblist) do |db|
              if Ops.get(db, "suffix", "") ==
                  Ops.get_string(newDb, "suffix", "")
                dbindex = Builtins.tointeger(Ops.get(db, "index", "0"))
                raise Break
              end
            end
            if Ops.greater_than(dbindex, 0)
              if !AuthServer.AddPasswordPolicy(dbindex, ppolicy)
                err = AuthServer.ReadError
                @callback_error = Ops.add(
                  Ops.add(Ops.get(err, "msg", ""), "\n"),
                  Ops.get(err, "details", "")
                )
                return false
              end
            end
          end
          AuthServer.WriteLdapConfBase(LdapDatabase.GetLdapConfBase)
        else
          Builtins.y2milestone("Database creating aborted")
        end
      elsif @handler_cmd == :pb_del
        selected = Convert.to_integer(UI.QueryWidget(:tab_db, :CurrentItem))
        if selected != nil
          dblist = AuthServer.ReadDatabaseList
          db = Convert.convert(
            Ops.get(dblist, selected),
            :from => "map",
            :to   => "map <string, string>"
          )
          if db != nil
            Builtins.y2milestone(
              "Trying to delete datbase %1 %2",
              Ops.get(db, "suffix", ""),
              Ops.get(db, "type", "")
            )
            if Ops.get(db, "type", "") == "frontend"
              Popup.Error(_("Cannot delete Frontend database"))
            elsif Ops.get(db, "type", "") == "config"
              Popup.Error(_("Cannot delete Config database"))
            else
              if Popup.YesNo(_("Do you really want to delete the database?"))
                AuthServer.UpdateDatabase(
                  Builtins.tointeger(Ops.get(db, "index", "")),
                  {}
                )
                cb_read_databases
                @rebuild_widget_tree = true
              end
            end
          end
        end
      end

      true
    end

    #****************************
    #* database handlers
    #***************************

    def cb_write_db
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone(
        "calling db write handler for '%1'",
        @current_tree_item
      )

      if index == nil
        # Error Popup
        @callback_error = _(
          "Unable to write settings for the current database."
        )
        Builtins.y2error(
          "'name' entry for item '%1' is nil",
          @current_tree_item
        )
        return false
      end

      db = {}
      Ops.set(
        db,
        "rootdn",
        Convert.to_string(UI.QueryWidget(:te_rootdn, :Value))
      )

      if Ops.get_string(db, "rootdn", "") != "" &&
          Convert.to_boolean(UI.QueryWidget(:cb_append_basedn, :Value))
        olddb = AuthServer.ReadDatabase(index)
        suffix = Ops.get_string(olddb, "suffix", "")
        Ops.set(
          db,
          "rootdn",
          Ops.add(Ops.add(Ops.get_string(db, "rootdn", ""), ","), suffix)
        )
      end
      Ops.set(
        db,
        "entrycache",
        Convert.to_integer(UI.QueryWidget(:if_entrycache, :Value))
      )
      Ops.set(
        db,
        "idlcache",
        Convert.to_integer(UI.QueryWidget(:if_idlcache, :Value))
      )
      kbytes = Convert.to_integer(UI.QueryWidget(:if_checkpoint_kb, :Value))
      min = Convert.to_integer(UI.QueryWidget(:if_checkpoint_min, :Value))
      checkpoint = [kbytes, min]
      Ops.set(db, "checkpoint", checkpoint)
      Builtins.y2milestone("updated Database: %1", db)

      res = AuthServer.UpdateDatabase(index, db)


      true
    end

    def cb_read_db
      Builtins.y2milestone("cb_read_db current item: %1", @current_tree_item)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])

      if index == nil
        @callback_error = _("Unable to read settings for the current database.")
        Builtins.y2error(
          "'index' entry for item '%1' is nil",
          @current_tree_item
        )
        return false
      end

      db = AuthServer.ReadDatabase(index)

      UI.ChangeWidget(:te_basedn, :Value, Ops.get_string(db, "suffix", ""))

      rootdn = Ops.get_string(db, "rootdn", "")
      append_checked = false
      pos = Builtins.search(rootdn, Ops.get_string(db, "suffix", ""))
      if Ops.greater_than(pos, -1)
        chkSuffix = Builtins.substring(rootdn, pos)
        if chkSuffix == Ops.get_string(db, "suffix", "")
          rootdn = Builtins.substring(rootdn, 0, Ops.subtract(pos, 1))
          append_checked = true
        end
      end
      UI.ChangeWidget(:te_rootdn, :Value, rootdn)
      UI.ChangeWidget(:cb_append_basedn, :Value, append_checked)
      UI.ChangeWidget(
        :if_entrycache,
        :Value,
        Builtins.tointeger(Ops.get_string(db, "entrycache", ""))
      )
      UI.ChangeWidget(
        :if_idlcache,
        :Value,
        Builtins.tointeger(Ops.get_string(db, "idlcache", ""))
      )
      checkpoint = Ops.get_list(db, "checkpoint", [])
      UI.ChangeWidget(
        :if_checkpoint_kb,
        :Value,
        Builtins.tointeger(Ops.get_string(checkpoint, 0, ""))
      )
      UI.ChangeWidget(
        :if_checkpoint_min,
        :Value,
        Builtins.tointeger(Ops.get_string(checkpoint, 1, ""))
      )

      true
    end

    def cb_input_db
      treeItem = @current_tree_item
      Builtins.y2milestone("calling db input handler for item '%1'", treeItem)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      if @handler_cmd == :pb_changepw
        newpw = ChangeAdminPassword()
        if newpw != nil
          Builtins.y2milestone("set password")
          newhash = AuthServer.HashPassword(
            Ops.get(newpw, "hashAlgo", ""),
            Ops.get(newpw, "password", "")
          )
          Builtins.y2milestone("new hash: %1", newhash)
          AuthServer.UpdateDatabase(index, { "rootpw" => newhash })
        else
          Builtins.y2milestone("password change cancelled")
        end
      end

      true
    end

    def cb_write_confdb
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone(
        "calling confdb write handler for '%1'",
        @current_tree_item
      )

      if index == nil
        # Error Popup
        @callback_error = _(
          "Unable to write settings for the current database."
        )
        Builtins.y2error(
          "'name' entry for item '%1' is nil",
          @current_tree_item
        )
        return false
      end

      db = {}
      olddb = AuthServer.ReadDatabase(index)
      Ops.set(
        db,
        "secure_only",
        Convert.to_boolean(UI.QueryWidget(:cb_conf_ldapsimplebind, :Value))
      )
      if Ops.get_boolean(db, "secure_only", false)
        if Ops.get_string(olddb, "rootpw", "") == ""
          pw = Convert.to_string(UI.QueryWidget(:te_rootpw, :Value))
          verifypw = Convert.to_string(UI.QueryWidget(:te_valid_rootpw, :Value))
          hashAlgo = Convert.to_string(UI.QueryWidget(:cb_cryptmethod, :Value))
          if Builtins.size(pw) == 0
            Popup.Error(_("Enter a password"))
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
            return false
          elsif pw != verifypw
            Popup.Error(
              _("The passwords you have entered do not match. Try again.")
            )
            UI.ChangeWidget(:te_rootpw, :Value, "")
            UI.ChangeWidget(:te_valid_rootpw, :Value, "")
            pw = ""
            verifypw = ""
            return false
          end
          if pw != ""
            Builtins.y2milestone("set password")
            newhash = AuthServer.HashPassword(hashAlgo, pw)
            Builtins.y2milestone("new hash: %1", newhash)
            Ops.set(db, "rootpw", newhash)
          end
        end
      else
        Ops.set(db, "rootpw", "")
      end

      res = AuthServer.UpdateDatabase(index, db)
      true
    end

    def cb_read_confdb
      Builtins.y2milestone("cb_read_db current item: %1", @current_tree_item)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])

      if index == nil
        @callback_error = _("Unable to read settings for the current database.")
        Builtins.y2error(
          "'index' entry for item '%1' is nil",
          @current_tree_item
        )
        return false
      end
      db = AuthServer.ReadDatabase(index)
      UI.ChangeWidget(
        :cb_conf_ldapsimplebind,
        :Value,
        Ops.get_boolean(db, "secure_only", false)
      )
      if Ops.get_boolean(db, "secure_only", false)
        if Ops.get_string(db, "rootpw", "") == ""
          UI.ReplaceWidget(
            :rp_confpw,
            VBox(
              Password(Id(:te_rootpw), _("New Administrator &Password")),
              HSpacing(0.5),
              Password(Id(:te_valid_rootpw), _("&Validate Password")),
              HSpacing(0.5),
              ComboBox(
                Id(:cb_cryptmethod),
                _("Password &Encryption"),
                @enc_types
              )
            )
          )
        end
      else
        UI.ChangeWidget(:rp_confpw, :Enabled, false)
      end
      true
    end

    def cb_input_confdb
      treeItem = @current_tree_item
      Builtins.y2milestone("calling db input handler for item '%1'", treeItem)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      if @handler_cmd == :pb_changepw
        newpw = ChangeAdminPassword()
        if newpw != nil
          Builtins.y2milestone("set password")
          newhash = AuthServer.HashPassword(
            Ops.get(newpw, "hashAlgo", ""),
            Ops.get(newpw, "password", "")
          )
          Builtins.y2milestone("new hash: %1", newhash)
          AuthServer.UpdateDatabase(index, { "rootpw" => newhash })
        else
          Builtins.y2milestone("password change cancelled")
        end
      elsif @handler_cmd == :cb_conf_ldapsimplebind
        db = AuthServer.ReadDatabase(index)
        if Convert.to_boolean(UI.QueryWidget(:cb_conf_ldapsimplebind, :Value))
          if Ops.get_string(db, "rootpw", "") == ""
            UI.ReplaceWidget(
              :rp_confpw,
              VBox(
                Password(Id(:te_rootpw), _("New Administrator &Password")),
                HSpacing(0.5),
                Password(Id(:te_valid_rootpw), _("&Validate Password")),
                HSpacing(0.5),
                ComboBox(
                  Id(:cb_cryptmethod),
                  _("Password &Encryption"),
                  @enc_types
                )
              )
            )
          else
            UI.ReplaceWidget(
              :rp_confpw,
              PushButton(Id(:pb_changepw), _("Change Administration Password"))
            )
          end
          UI.ChangeWidget(:rp_confpw, :Enabled, true)
        else
          UI.ChangeWidget(:rp_confpw, :Enabled, false)
        end
      end

      true
    end

    def cb_read_bdb_index
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone(
        "cb_read_bdb_index current item: %1, index %2",
        @current_tree_item,
        index
      )
      idxMap = AuthServer.ReadDatabaseIndexes(index)
      i = 0
      newItems = []
      Builtins.foreach(idxMap) do |attr, idx|
        eqIdx = _("No")
        presIdx = _("No")
        substrIdx = _("No")
        approxIdx = _("No")
        Builtins.y2milestone("index attr: %1", attr)
        eqIdx = _("Yes") if Ops.get(idx, "eq", false)
        presIdx = _("Yes") if Ops.get(idx, "pres", false)
        substrIdx = _("Yes") if Ops.get(idx, "sub", false)
        newItems = Builtins.add(
          newItems,
          Item(Id(i), attr, presIdx, eqIdx, substrIdx, approxIdx)
        )
        i = Ops.add(i, 1)
      end
      UI.ChangeWidget(:tab_idx, :Items, newItems)

      true
    end

    def cb_input_bdb_index
      Builtins.y2milestone("cb_input_bdb_index, handlercmd: %1", @handler_cmd)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      if @handler_cmd == :pb_idx_add || @handler_cmd == :pb_idx_edit
        skip = []
        editAttr = ""
        idx = {}
        idxMap = AuthServer.ReadDatabaseIndexes(index)
        if @handler_cmd == :pb_idx_add
          # skip attribute that already have an index defined
          Builtins.foreach(idxMap) do |attr, idx2|
            skip = Builtins.add(skip, attr)
          end
        else
          current_item_id = UI.QueryWidget(:tab_idx, :CurrentItem)
          editAttr = Convert.to_string(
            UI.QueryWidget(:tab_idx, Cell(current_item_id, 0))
          )
          idx = Ops.get(idxMap, editAttr, {})
          Builtins.y2milestone(
            "Selected Attr: %1 %2 %3",
            current_item_id,
            editAttr,
            idx
          )
        end

        newIdx = DatabaseIndexPopup(skip, editAttr, idx)
        if Ops.greater_than(Builtins.size(newIdx), 0)
          AuthServer.ChangeDatabaseIndex(index, newIdx)
          cb_read_bdb_index
        end
      elsif @handler_cmd == :pb_idx_del
        current_item_id = UI.QueryWidget(:tab_idx, :CurrentItem)
        editAttr = Convert.to_string(
          UI.QueryWidget(:tab_idx, Cell(current_item_id, 0))
        )
        Builtins.y2milestone("Selected Attr: %1 %2", current_item_id, editAttr)
        delIdx = {}
        Ops.set(delIdx, "name", editAttr)
        Ops.set(delIdx, "sub", false)
        Ops.set(delIdx, "pres", false)
        Ops.set(delIdx, "eq", false)
        AuthServer.ChangeDatabaseIndex(index, delIdx)
        cb_read_bdb_index
      end
      true
    end

    def cb_read_acl
      Builtins.y2milestone("cb_read_acl()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      acllist = AuthServer.ReadDatabaseAcl(index)

      LdapDatabase.DbAclRead(index, acllist)
    end

    def cb_input_acl
      Builtins.y2milestone("cb_input_acl()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone("calling acl input handler for item '%1'", treeItem)
      LdapDatabase.DbAclInput(@handler_cmd, index)
    end

    def cb_write_acl
      Builtins.y2milestone("cb_write_acl()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      changedAcls = LdapDatabase.DbAclWrite(index)
      return true if changedAcls == nil
      ret = AuthServer.ChangeDatabaseAcl(
        index,
        Convert.convert(
          changedAcls,
          :from => "list <map>",
          :to   => "list <map <string, any>>"
        )
      )
      if !ret
        err = AuthServer.ReadError
        @callback_error = Ops.add(
          Ops.add(Ops.get(err, "msg", ""), "\n"),
          Ops.get(err, "details", "")
        )
      end
      ret
    end

    def cb_read_syncprov
      Builtins.y2milestone("cb_read_syncprov()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      sp = AuthServer.ReadSyncProv(index)
      LdapDatabase.DbSyncProvRead(@handler_cmd, index, sp)
    end

    def cb_input_syncprov
      Builtins.y2milestone("cb_input_syncprov()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone("calling sync input handler for item '%1'", treeItem)
      LdapDatabase.DbSyncProvInput(@handler_cmd, index)
    end

    def cb_write_syncprov
      Builtins.y2milestone("cb_write_syncprov()")
      result = false
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      syncprov = LdapDatabase.DbSyncProvWrite(index)
      result = AuthServer.WriteSyncProv(index, syncprov)
      if !result
        err = AuthServer.ReadError
        @callback_error = Ops.add(
          Ops.add(Ops.get(err, "msg", ""), "\n"),
          Ops.get(err, "details", "")
        )
      end
      result
    end

    def cb_read_synccons
      Builtins.y2milestone("cb_read_synccons()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      srl = AuthServer.ReadSyncRepl(index)
      if Ops.greater_than(Builtins.size(srl), 1)
        UI.ReplaceWidget(
          :syncConsWidget,
          Label(_("Multiple Replication Consumers not supported currently"))
        )
        return true
      else
        sr = Ops.get(srl, 0, {})
        updateref = AuthServer.ReadUpdateRef(index)
        return LdapDatabase.DbSyncConsRead(index, sr, updateref)
      end
    end

    def cb_input_synccons
      Builtins.y2milestone("cb_input_synccons()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      if UI.WidgetExists(:cb_syncrepl)
        return LdapDatabase.DbSyncConsInput(@handler_cmd, index)
      else
        return true
      end
    end

    def cb_check_synccons
      Builtins.y2milestone("cb_check_synccons()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      if UI.WidgetExists(:cb_syncrepl)
        return LdapDatabase.DbSyncConsCheck(index)
      else
        return true
      end
    end

    def cb_write_synccons
      Builtins.y2milestone("cb_write_synccons()")
      treeItem = @current_tree_item
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      return true if !UI.WidgetExists(:cb_syncrepl)
      syncrepl = LdapDatabase.DbSyncConsWrite(index)
      result = false
      result = AuthServer.WriteSyncRepl(
        index,
        Ops.get_map(syncrepl, "syncrepl", {})
      )
      if !result
        err = AuthServer.ReadError
        @callback_error = Ops.add(
          Ops.add(Ops.get(err, "msg", ""), "\n"),
          Ops.get(err, "details", "")
        )
      end
      AuthServer.WriteUpdateRef(index, Ops.get_map(syncrepl, "updateref", {}))
      result
    end

    def cb_input_ppolicy
      Builtins.y2milestone("cb_input_ppolicy()")
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      Builtins.y2milestone(
        "calling db input handler for item '%1'",
        @current_tree_item
      )
      LdapDatabase.DbPpolicyInput(@handler_cmd, index)
    end

    def cb_read_ppolicy
      Builtins.y2milestone("cb_read_ppolicy()")
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      LdapDatabase.DbPpolicyRead(index)
    end

    def cb_write_ppolicy
      treeItem = @current_tree_item
      Builtins.y2milestone("cb_write_policy() treeitem: '%1'", treeItem)
      index = Ops.get_integer(@widget_map, [@current_tree_item, "index"])
      result = true
      ppolicy = LdapDatabase.DbPpolicyWrite(index)
      if Ops.greater_than(Builtins.size(ppolicy), 0)
        result = AuthServer.AddPasswordPolicy(index, ppolicy)
      else
        ppolicy_old = AuthServer.ReadPpolicyOverlay(index)
        if Ops.greater_than(Builtins.size(ppolicy_old), 0)
          # delete ppolicy
          result = AuthServer.AddPasswordPolicy(index, {})
        end
      end
      if !result
        err = AuthServer.ReadError
        @callback_error = Ops.add(
          Ops.add(Ops.get(err, "msg", ""), "\n"),
          Ops.get(err, "details", "")
        )
      end
      result
    end

    #****************************************
    #      tree generation functions       **
    #***************************************

    def addDatabaseWidgetMap(type, label, item_name, index, new_db)
      return if Builtins.haskey(@widget_map, item_name)
      dbIndex = {
        "name"      => _("Index Configuration"),
        "widget"    => @editBdbIndexes,
        "index"     => index,
        "cb_read"   => lambda { cb_read_bdb_index },
        "cb_input"  => lambda { cb_input_bdb_index },
        "help_page" => "index_edit"
      }
      dbPpolicy = {
        "name"      => _("Password Policy Configuration"),
        "widget"    => LdapDatabase.GetPpolicyWidget,
        "index"     => index,
        "cb_read"   => lambda { cb_read_ppolicy },
        "cb_input"  => lambda { cb_input_ppolicy },
        "cb_write"  => lambda { cb_write_ppolicy },
        "help_page" => "ppolicy_edit"
      }
      dbAcl = {
        "name"      => _("Access Control Configuration"),
        "widget"    => LdapDatabase.GetAclWidget,
        "index"     => index,
        "cb_read"   => lambda { cb_read_acl },
        "cb_write"  => lambda { cb_write_acl },
        "cb_input"  => lambda { cb_input_acl },
        "help_page" => "acl_edit"
      }
      dbSyncProv = {
        "name"      => _("Replication Provider"),
        "widget"    => LdapDatabase.GetSyncProvWidget,
        "index"     => index,
        "cb_read"   => lambda { cb_read_syncprov },
        "cb_write"  => lambda { cb_write_syncprov },
        "cb_input"  => lambda { cb_input_syncprov },
        "help_page" => "syncprov_edit"
      }
      dbSyncCons = {
        "name"      => _("Replication Consumer"),
        "widget"    => LdapDatabase.GetSyncConsWidget,
        "index"     => index,
        "cb_read"   => lambda { cb_read_synccons },
        "cb_write"  => lambda { cb_write_synccons },
        "cb_input"  => lambda { cb_input_synccons },
        "cb_check"  => lambda { cb_check_synccons },
        "help_page" => "synccons_edit"
      }
      item_map = {
        "name"      => label,
        "children"  => [Ops.add(item_name, "_acl")],
        "index"     => index,
        "widget"    => @editGenericDatabase,
        "new_db"    => new_db,
        "dynamic"   => true,
        "help_page" => "database_detail_unsupported"
      }
      bdb_item_map = {
        "name"      => label,
        "children"  => [
          Ops.add(item_name, "_index"),
          Ops.add(item_name, "_ppolicy"),
          Ops.add(item_name, "_acl"),
          Ops.add(item_name, "_syncprov"),
          Ops.add(item_name, "_synccons")
        ],
        "index"     => index,
        "widget"    => @editBdbDatabase,
        "new_db"    => new_db,
        "dynamic"   => true,
        "help_page" => "database_detail",
        "cb_read"   => lambda { cb_read_db },
        "cb_write"  => lambda { cb_write_db },
        "cb_input"  => lambda { cb_input_db }
      }
      confdb_item_map = {
        "name"      => label,
        "children"  => [
          Ops.add(item_name, "_acl"),
          Ops.add(item_name, "_syncprov"),
          Ops.add(item_name, "_synccons")
        ],
        "index"     => index,
        "widget"    => @editConfigDatabase,
        "new_db"    => new_db,
        "dynamic"   => true,
        "help_page" => "database_detail_config",
        "cb_read"   => lambda { cb_read_confdb },
        "cb_write"  => lambda { cb_write_confdb },
        "cb_input"  => lambda { cb_input_confdb }
      }
      Builtins.y2milestone(
        "adding database item '%1' as '%2'",
        label,
        item_name
      )

      if type == "bdb" || type == "hdb"
        Ops.set(@widget_map, item_name, bdb_item_map)
        Ops.set(@widget_map, Ops.add(item_name, "_index"), dbIndex)
        Ops.set(@widget_map, Ops.add(item_name, "_ppolicy"), dbPpolicy)
        Ops.set(@widget_map, Ops.add(item_name, "_acl"), dbAcl)
        Ops.set(@widget_map, Ops.add(item_name, "_syncprov"), dbSyncProv)
        Ops.set(@widget_map, Ops.add(item_name, "_synccons"), dbSyncCons)
      elsif type == "config"
        Ops.set(@widget_map, item_name, confdb_item_map)
        Ops.set(@widget_map, Ops.add(item_name, "_acl"), dbAcl)
        Ops.set(@widget_map, Ops.add(item_name, "_syncprov"), dbSyncProv)
        Ops.set(@widget_map, Ops.add(item_name, "_synccons"), dbSyncCons)
      else
        Ops.set(@widget_map, item_name, item_map)
        Ops.set(@widget_map, Ops.add(item_name, "_acl"), dbAcl)
      end

      Ops.set(
        @widget_map,
        ["databases", "children"],
        Builtins.add(
          Ops.get_list(@widget_map, ["databases", "children"], []),
          item_name
        )
      )

      nil
    end

    def generateDynamicTreeItems
      Builtins.y2debug("generating database tree items")
      #generate database entries

      dblist = AuthServer.ReadDatabaseList
      i = 0
      Builtins.foreach(dblist) do |db|
        tmp = Builtins.sformat(
          "%1 (%2)",
          Ops.get(db, "suffix", ""),
          Ops.get(db, "type", "")
        )
        name = Ops.add("database-", Builtins.tostring(i))
        addDatabaseWidgetMap(
          Ops.get(db, "type", ""),
          tmp,
          name,
          Builtins.tointeger(Ops.get(db, "index", "0")),
          false
        )
        i = Ops.add(i, 1)
      end
      Builtins.y2debug(
        "databases map is '%1'",
        Ops.get(@widget_map, "databases", {})
      )

      nil
    end

    def deleteDynamicTreeItems
      Builtins.y2milestone("deleting dynamic tree items")
      @widget_map = Builtins.filter(@widget_map) do |key, val|
        !Ops.get_boolean(val, "dynamic", false)
      end

      Ops.set(@widget_map, ["databases", "children"], [])

      nil
    end
  end
end
