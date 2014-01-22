# encoding: utf-8

require "yast"

module Yast
  class LdapDatabaseClass < Module
    def main
      Yast.import "UI"
      textdomain "auth-server"
      Yast.import "Label"
      Yast.import "AuthServer"
      Yast.import "Ldap"
      Yast.import "LdapPopup"
      Yast.import "Popup"
      Yast.import "Sequencer"
      Yast.import "String"
      Yast.import "Wizard"

      Yast.include self, "auth-server/helps.rb"
      Yast.include self, "auth-server/widgets.rb"
      Yast.include self, "users/ldap_dialogs.rb"


      @baseDb = {
        "rootdn"    => "cn=Administrator",
        "directory" => "/var/lib/ldap"
      }
      @ppolicyNew = {}
      @syncReplNew = {}
      @acllist = []

      @ldapconf_basedn = ""
      @createDbDir = false
      @createBase = true


      @editPolicy = Top(
        VBox(
          VSpacing(1),
          Heading(_("Password Policy Settings")),
          VBox(
            VSpacing(0.25),
            HBox(
              CheckBox(
                Id(:cb_ppolicy_overlay),
                Opt(:notify),
                _("Enable Password Policies"),
                false
              ),
              HSpacing(Opt(:hstretch))
            ),
            HBox(
              CheckBox(
                Id(:cb_ppolicy_hashcleartext),
                _("Hash Clear Text Passwords"),
                false
              ),
              HSpacing(Opt(:hstretch))
            ),
            HBox(
              CheckBox(
                Id(:cb_ppolicy_uselockout),
                _("Disclose \"Account Locked\" Status"),
                false
              ),
              HSpacing(Opt(:hstretch))
            ),
            VSquash(
              HBox(
                InputField(
                  Id(:te_ppolicy_defaultpolicy),
                  Opt(:hstretch),
                  _("Default Policy Object DN"),
                  "cn=Default Policy"
                ),
                HSpacing(0.5),
                VBox(
                  Bottom(
                    CheckBox(
                      Id(:cb_pp_append_basedn),
                      _("&Append Base DN"),
                      true
                    )
                  ),
                  VSpacing(0.3)
                ),
                HSpacing(0.5),
                VBox(
                  Bottom(PushButton(Id(:pb_define_policy), _("Edit Policy"))),
                  VSpacing(0.3)
                )
              )
            ),
            VSpacing(0.25)
          )
        )
      )

      @whatString2Label = {
        "*"       => _("All Entries"),
        "subtree" => _("All Entries in the Subtree"),
        "base"    => _("The Entry with the DN")
      }

      @whoId2String = {
        :who_all        => [_("Everybody"), "*"],
        :who_users      => [_("Authenticated Clients"), "users"],
        :who_anon       => [_("Anonymous Clients"), "anonymous"],
        :who_self       => [_("The accessed Entry (self)"), "self"],
        :who_dn         => [_("The user with the DN"), "dn.base"],
        :who_dn_subtree => [_("All entries in the subtree"), "dn.subtree"],
        :who_group      => [_("All members of the group"), "group"]
      }
      @whoString2Id = {
        "*"          => :who_all,
        "users"      => :who_users,
        "anonymous"  => :who_anon,
        "self"       => :who_self,
        "dn.base"    => :who_dn,
        "dn.subtree" => :who_dn_subtree,
        "group"      => :who_group
      }

      @accessId2String = {
        :access_empty    => [_("<empty>"), ""],
        :access_none     => [_("No Access"), "none"],
        :access_disclose => [
          _("No Access (but disclose information on error)"),
          "disclose"
        ],
        :access_auth     => [_("Authenticate"), "auth"],
        :access_compare  => [_("Compare"), "compare"],
        :access_read     => [_("Read"), "read"],
        :access_write    => [_("Write"), "write"],
        :access_manage   => [_("Manage (full access)"), "manage"]
      }

      @accessString2Id = {
        ""         => :access_empty,
        "none"     => :access_none,
        "disclose" => :access_disclose,
        "auth"     => :access_auth,
        "compare"  => :access_compare,
        "read"     => :access_read,
        "write"    => :access_write,
        "manage"   => :access_manage
      }
    end

    def GetCreateBase
      @createBase
    end

    def ResetCreateBase
      @createBase = true
      true
    end

    def AddDbBasic(createDefaults)
      user_changed_dbdir = false
      db = {}
      numDbs = 0
      if !createDefaults
        dblist = AuthServer.ReadDatabaseList
        numDbs = Ops.subtract(Builtins.size(dblist), 2) # don't count frontend and Config DB
      end
      caption = _("New Database")

      addDbWidget = VBox(
        Heading(_("Basic Database Settings")),
        HSquash(
          VBox(
            Left(ComboBox(Id(:cb_type), _("Database Type"), ["hdb", "bdb"])),
            Left(
              InputField(
                Id(:te_basedn),
                Opt(:hstretch, :notify),
                _("&Base DN"),
                ""
              )
            ),
            VSpacing(0.5),
            Left(
              VSquash(
                HBox(
                  InputField(
                    Id(:te_rootdn),
                    Opt(:hstretch),
                    _("&Administrator DN"),
                    "cn=Administrator"
                  ),
                  HSpacing(),
                  VBox(
                    Bottom(
                      CheckBox(
                        Id(:cb_append_basedn),
                        _("A&ppend Base DN"),
                        true
                      )
                    ),
                    VSpacing(0.3)
                  )
                )
              )
            ),
            VSpacing(0.5),
            Left(
              Password(
                Id(:te_rootpw),
                Opt(:hstretch),
                _("LDAP Administrator &Password"),
                ""
              )
            ),
            Left(
              Password(
                Id(:te_valid_rootpw),
                Opt(:hstretch),
                _("&Validate Password"),
                ""
              )
            ),
            VSpacing(0.5),
            VSquash(
              HBox(
                Left(
                  InputField(
                    Id(:te_directory),
                    Opt(:hstretch, :notify),
                    _("&Database Directory")
                  )
                ),
                HSpacing(0.5),
                Bottom(PushButton(Id(:pb_directory), _("&Browse...")))
              )
            ),
            Left(
              CheckBox(
                Id(:cb_ldapconf),
                _("Use this database as the default for OpenLDAP clients"),
                true
              )
            )
          )
        )
      )
      Wizard.SetContentsButtons(
        caption,
        addDbWidget,
        Ops.get_string(@HELPS, "database_basic", "help not found"),
        Label.BackButton,
        Label.NextButton
      )

      append_checked = true
      if createDefaults
        db = AuthServer.CreateInitialDefaults
      else
        db = deep_copy(@baseDb)
      end

      if Ops.get_string(db, "rootdn", "") != ""
        pos = Builtins.search(
          Ops.get_string(db, "rootdn", ""),
          Ops.get_string(db, "suffix", "")
        )
        if Ops.greater_than(pos, -1)
          Ops.set(
            db,
            "rootdn",
            Builtins.substring(
              Ops.get_string(db, "rootdn", ""),
              0,
              Ops.subtract(pos, 1)
            )
          )
        else
          append_checked = false
        end
      end
      UI.ChangeWidget(Id(:te_basedn), :Value, Ops.get_string(db, "suffix", ""))
      UI.ChangeWidget(Id(:te_rootdn), :Value, Ops.get_string(db, "rootdn", ""))
      UI.ChangeWidget(
        Id(:te_rootpw),
        :Value,
        Ops.get_string(db, "rootpw_clear", "")
      )
      UI.ChangeWidget(
        Id(:te_valid_rootpw),
        :Value,
        Ops.get_string(db, "rootpw_clear", "")
      )
      UI.ChangeWidget(Id(:cb_append_basedn), :Value, append_checked)
      UI.ChangeWidget(
        Id(:te_directory),
        :Value,
        Ops.get_string(db, "directory", "")
      )

      if numDbs == 0
        UI.ChangeWidget(Id(:cb_ldapconf), :Value, true)
      else
        UI.ChangeWidget(Id(:cb_ldapconf), :Value, false)
      end
      ret = :next
      while true
        ret = Convert.to_symbol(UI.UserInput)
        if ret == :pb_directory
          name = UI.AskForExistingDirectory(
            "/var/lib/ldap",
            _("Select Database Directory")
          )
          UI.ChangeWidget(:te_directory, :Value, name) if name != nil
          next
        elsif ret == :te_directory
          user_changed_dbdir = true
        elsif ret == :te_basedn
          if user_changed_dbdir != true && Ops.greater_than(numDbs, 0)
            suffix = String.CutBlanks(
              Convert.to_string(UI.QueryWidget(:te_basedn, :Value))
            )
            suffix = String.Replace(suffix, ",", "_")
            suffix = String.CutRegexMatch(suffix, "[^0-9a-zA-Z_=-]", true)
            dbdir = Ops.add("/var/lib/ldap/", suffix)
            UI.ChangeWidget(:te_directory, :Value, dbdir)
          end
        end
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        end
        break if ret == :back
        if ret == :next
          suffix = String.CutBlanks(
            Convert.to_string(UI.QueryWidget(:te_basedn, :Value))
          )
          rootdn = String.CutBlanks(
            Convert.to_string(UI.QueryWidget(:te_rootdn, :Value))
          )
          rootpw = Convert.to_string(UI.QueryWidget(:te_rootpw, :Value))
          directory = String.CutBlanks(
            Convert.to_string(UI.QueryWidget(:te_directory, :Value))
          )

          #check values
          if suffix == ""
            Popup.Error(_("Base DN must be set."))
            next
          end

          if !createDefaults
            dblist = AuthServer.ReadDatabaseList
            exists = false
            Builtins.foreach(dblist) do |db2|
              if suffix == Ops.get(db2, "suffix", "")
                Popup.Error(_("A database with this Base DN already exists."))
                exists = true
                raise Break
              end
            end
            next if exists
          end
          Ops.set(db, "suffix", suffix)
          Ops.set(db, "directory", directory)
          Ops.set(
            db,
            "type",
            Convert.to_string(UI.QueryWidget(:cb_type, :Value))
          )

          if rootdn != "" &&
              Convert.to_boolean(UI.QueryWidget(:cb_append_basedn, :Value))
            rootdn = Ops.add(Ops.add(rootdn, ","), suffix)
          end
          if rootdn != ""
            Ops.set(db, "rootdn", rootdn)
          else
            db = Builtins.remove(db, "rootdn") if Builtins.haskey(db, "rootdn")
          end

          if rootpw != ""
            Ops.set(db, "rootpw_clear", rootpw)
            Ops.set(db, "pwenctype", "SSHA")
          else
            if Builtins.haskey(db, "rootpw_clear")
              db = Builtins.remove(db, "rootpw_clear")
            end

            if Builtins.haskey(db, "pwenctype")
              db = Builtins.remove(db, "pwenctype")
            end
          end

          if Ops.get_string(db, "rootpw_clear", "") != "" &&
              Ops.get_string(db, "rootdn", "") == ""
            Popup.Error(_("Root DN must be set if a password is given."))
            next
          end
          if Ops.get_string(db, "rootpw_clear", "") != "" &&
              Ops.get_string(db, "rootpw_clear", "") !=
                Convert.to_string(UI.QueryWidget(:te_valid_rootpw, :Value))
            Popup.Error(_("Password validation failed."))
            next
          end
          if !AuthServer.CheckDatabase(db)
            err = AuthServer.ReadError
            Popup.Error(
              Ops.add(
                Ops.add(Ops.get(err, "msg", ""), "\n"),
                Ops.get(err, "details", "")
              )
            )
            next
          end
          rc = AuthServer.CheckSuffixAutoCreate(
            Ops.get_string(db, "suffix", "")
          )
          if Ops.less_than(rc, 0)
            err = AuthServer.ReadError
            Popup.Error(
              Ops.add(
                Ops.add(Ops.get(err, "msg", ""), "\n"),
                Ops.get(err, "details", "")
              )
            )
            next
          elsif Ops.greater_than(rc, 0)
            err = AuthServer.ReadError
            res = Popup.AnyQuestion(
              Label.WarningMsg,
              Builtins.sformat(
                _("The Base Object: \"%1\" cannot be auto created by YaST:\n%2"),
                Ops.get_string(db, "suffix", ""),
                Ops.get(err, "msg", "")
              ),
              Label.OKButton,
              Label.CancelButton,
              :focus
            )
            if res == false
              next
            else
              Builtins.y2debug("Will not create base objects")
              @createBase = false
            end
          end
          if Ops.get_string(db, "directory", "") == ""
            Popup.Error(_("A directory must be specified."))
            next
          end
          if Ops.get_string(db, "directory", "") != "/var/lib/ldap" &&
              SCR.Read(path(".target.dir"), Ops.get_string(db, "directory", "")) == nil
            res = Popup.AnyQuestion(
              Label.WarningMsg,
              _("The directory does not exist. Create it?"),
              Label.YesButton,
              Label.NoButton,
              :focus
            )
            if res == false
              next
            else
              Builtins.y2debug("Create dir == true")
              @createDbDir = true
            end
          end



          if Convert.to_boolean(UI.QueryWidget(:cb_ldapconf, :Value))
            @ldapconf_basedn = suffix
          end
          @baseDb = deep_copy(db)
          break
        end
      end
      ret
    end

    def DbPpolicyRead(dbindex)
      ppolicy_map = deep_copy(@ppolicyNew)
      if Ops.greater_than(dbindex, 0)
        ppolicy_map = AuthServer.ReadPpolicyOverlay(dbindex)
      end
      if Builtins.size(ppolicy_map) != 0
        UI.ChangeWidget(:cb_ppolicy_overlay, :Value, true)
        pp_hash_cleartext = Ops.get_boolean(ppolicy_map, "hashClearText")
        pp_use_lockout = Ops.get_boolean(ppolicy_map, "useLockout")
        pp_default = Ops.get_string(ppolicy_map, "defaultPolicy")
        pp_append_checked = false
        olddb = AuthServer.ReadDatabase(dbindex)
        suffix = Ops.get_string(olddb, "suffix", "")
        pos = Builtins.search(pp_default, suffix)
        if Ops.greater_than(pos, -1)
          chkSuffix = Builtins.substring(pp_default, pos)
          if chkSuffix == suffix
            pp_default = Builtins.substring(pp_default, 0, Ops.subtract(pos, 1))
            pp_append_checked = true
          end
        end
        if pp_hash_cleartext
          UI.ChangeWidget(:cb_ppolicy_hashcleartext, :Value, true)
        else
          UI.ChangeWidget(:cb_ppolicy_hashcleartext, :Value, false)
        end
        if pp_use_lockout
          UI.ChangeWidget(:cb_ppolicy_uselockout, :Value, true)
        else
          UI.ChangeWidget(:cb_ppolicy_uselockout, :Value, false)
        end
        if pp_default != ""
          UI.ChangeWidget(:te_ppolicy_defaultpolicy, :Value, pp_default)
          UI.ChangeWidget(:cb_pp_append_basedn, :Value, pp_append_checked)
        else
          UI.ChangeWidget(:te_ppolicy_defaultpolicy, :Value, "")
          UI.ChangeWidget(:cb_pp_append_basedn, :Value, true)
        end
      else
        UI.ChangeWidget(:cb_ppolicy_overlay, :Value, false)
        UI.ChangeWidget(:cb_ppolicy_hashcleartext, :Enabled, false)
        UI.ChangeWidget(:cb_ppolicy_uselockout, :Enabled, false)
        UI.ChangeWidget(:pb_define_policy, :Enabled, false)
        UI.ChangeWidget(:te_ppolicy_defaultpolicy, :Enabled, false)
      end
      true
    end

    def DbPpolicyWrite(dbindex)
      if UI.QueryWidget(:cb_ppolicy_overlay, :Value) == true
        hashcleartext = Convert.to_boolean(
          UI.QueryWidget(:cb_ppolicy_hashcleartext, :Value)
        )
        uselockout = Convert.to_boolean(
          UI.QueryWidget(:cb_ppolicy_uselockout, :Value)
        )
        pp_default = Convert.to_string(
          UI.QueryWidget(:te_ppolicy_defaultpolicy, :Value)
        )
        ppolicy = {}
        if hashcleartext
          ppolicy = Builtins.add(ppolicy, "hashClearText", true)
        else
          ppolicy = Builtins.add(ppolicy, "hashClearText", false)
        end
        if uselockout
          ppolicy = Builtins.add(ppolicy, "useLockout", true)
        else
          ppolicy = Builtins.add(ppolicy, "useLockout", false)
        end
        if pp_default != ""
          db = deep_copy(@baseDb)
          db = AuthServer.ReadDatabase(dbindex) if Ops.greater_than(dbindex, 0)
          suffix = Ops.get_string(db, "suffix", "")
          if Convert.to_boolean(UI.QueryWidget(:cb_pp_append_basedn, :Value))
            pp_default = Ops.add(Ops.add(pp_default, ","), suffix)
          end
          ppolicy = Builtins.add(ppolicy, "defaultPolicy", pp_default)
          ppolicyEntry = AuthServer.ReadPpolicyDefault(
            Ops.get_string(db, "suffix", "")
          )
          # User might haved change the Default DN, adjust it
          if Ops.greater_than(Builtins.size(ppolicyEntry), 0)
            Ops.set(ppolicyEntry, "dn", pp_default)
            AuthServer.WritePpolicyDefault(
              Ops.get_string(db, "suffix", ""),
              Ops.get_string(ppolicyEntry, "dn", ""),
              Ops.get_map(ppolicyEntry, "ppolicy", {})
            )
          end
        else
          ppolicy = Builtins.add(ppolicy, "defaultPolicy", "")
        end
        Builtins.y2milestone("Policy: %1", ppolicy)
        return deep_copy(ppolicy)
      else
        return {}
      end
    end

    def DbPpolicyInput(handler_cmd, dbindex)
      if handler_cmd == :cb_ppolicy_overlay
        if UI.QueryWidget(:cb_ppolicy_overlay, :Value) == true
          UI.ChangeWidget(:cb_ppolicy_hashcleartext, :Enabled, true)
          UI.ChangeWidget(:cb_ppolicy_uselockout, :Enabled, true)
          UI.ChangeWidget(:te_ppolicy_defaultpolicy, :Enabled, true)
          UI.ChangeWidget(:cb_pp_append_basedn, :Enabled, true)
          UI.ChangeWidget(:pb_define_policy, :Enabled, true) if GetCreateBase()
        else
          UI.ChangeWidget(:cb_ppolicy_hashcleartext, :Enabled, false)
          UI.ChangeWidget(:cb_ppolicy_uselockout, :Enabled, false)
          UI.ChangeWidget(:te_ppolicy_defaultpolicy, :Enabled, false)
          UI.ChangeWidget(:cb_pp_append_basedn, :Enabled, false)
          UI.ChangeWidget(:pb_define_policy, :Enabled, false)
        end
      elsif handler_cmd == :pb_define_policy
        pp_default = Convert.to_string(
          UI.QueryWidget(:te_ppolicy_defaultpolicy, :Value)
        )

        db = deep_copy(@baseDb)
        db = AuthServer.ReadDatabase(dbindex) if dbindex != -1
        if Convert.to_boolean(UI.QueryWidget(:cb_pp_append_basedn, :Value))
          pp_default = Ops.add(
            Ops.add(pp_default, ","),
            Ops.get_string(db, "suffix", "")
          )
        end
        ppolicy = AuthServer.ReadPpolicyDefault(
          Ops.get_string(db, "suffix", "")
        )
        ppolicyEntry = {}
        if Ops.greater_than(Builtins.size(ppolicy), 0)
          ppolicyEntry = Ops.get_map(ppolicy, "ppolicy", {})
        elsif Ops.greater_than(dbindex, 0) # try to read the ppolicy from the server
          Ldap.Import(
            {
              "ldap_server" => "localhost",
              "bind_dn"     => Ops.get_string(db, "rootdn", "")
            }
          )
          Ldap.LDAPInit
          pw = ""
          authinfo = AuthServer.ReadAuthInfo(Ops.get_string(db, "suffix", ""))
          pw = Ops.get(authinfo, "bind_pw", "") if authinfo != nil
          bind_res = "tmp"
          while bind_res != ""
            pw = Ldap.GetLDAPPassword(false) if pw == ""
            bind_res = Ldap.LDAPBind(pw)
            if bind_res != ""
              if Popup.YesNo(
                  Ops.add(
                    Ops.add(
                      Ops.add(
                        _(
                          "Authentication failed. The password is probably incorrect.\n"
                        ) +
                          _("The error message was: '"),
                        bind_res
                      ),
                      "'\n"
                    ),
                    _("Try again?")
                  )
                )
                pw = ""
              else
                break
              end
            end
          end
          if bind_res == ""
            AuthServer.WriteAuthInfo(
              Ops.get_string(db, "suffix", ""),
              { "bind_dn" => Ops.get_string(db, "rootdn", ""), "bind_pw" => pw }
            )

            res = Convert.to_list(
              SCR.Read(
                path(".ldap.search"),
                {
                  "base_dn" => pp_default,
                  "filter"  => "objectclass=*",
                  "scope"   => 0
                }
              )
            )
            if Ops.greater_than(Builtins.size(res), 0)
              Builtins.y2milestone("default_policy does already exist")
              ppolicyEntry = Ops.get_map(res, 0)
            else
              Builtins.y2milestone("default_policy does not yet exist")
            end
          end
        end
        ppolicyEntry_new = PasswordPolicyDialog(ppolicyEntry)
        # PasswordPolicyDialog only returns the changes made to the original
        # Entry, try to merge them here
        Builtins.foreach(
          Convert.convert(
            ppolicyEntry_new,
            :from => "map",
            :to   => "map <string, any>"
          )
        ) { |key, val| Ops.set(ppolicyEntry, key, val) } 

        AuthServer.WritePpolicyDefault(
          Ops.get_string(db, "suffix", ""),
          pp_default,
          Convert.convert(
            ppolicyEntry,
            :from => "map",
            :to   => "map <string, any>"
          )
        )
      end
      true
    end

    def GetPpolicyWidget
      deep_copy(@editPolicy)
    end

    def SelectAttributes(selected)
      selected = deep_copy(selected)
      attrTypes = Convert.convert(
        SCR.Read(path(".ldapserver.schema.attributeTypes")),
        :from => "any",
        :to   => "map <string, map <string, boolean>>"
      )
      attrs = Builtins.maplist(attrTypes) { |k, v| k }
      attrs = Builtins.lsort(attrs)
      selectAttrWidget = Top(
        VBox(
          HSpacing(60),
          HBox(
            VSpacing(15),
            SelectionBox(Id(:sb_attr), _("Available Attribute Types"), attrs),
            VBox(PushButton(Id(:pb_add), "->"), PushButton(Id(:pb_del), "<-")),
            SelectionBox(
              Id(:sb_attr_sel),
              _("Selected Attribute Types"),
              selected
            )
          ),
          PushButton(Id(:ok), Label.OKButton)
        )
      )
      UI.OpenDialog(Opt(:decorated), selectAttrWidget)
      ret = :next
      while true
        ret = Convert.to_symbol(UI.UserInput)
        Builtins.y2milestone("Input event: %1", ret)
        if ret == :ok
          break
        elsif ret == :pb_add
          toadd = Convert.to_string(UI.QueryWidget(:sb_attr, :CurrentItem))
          if toadd != nil
            selected = Builtins.add(selected, toadd)
            selected = Builtins.lsort(selected)
            attrs = Builtins.filter(attrs) { |attr| attr != toadd }
            UI.ChangeWidget(:sb_attr_sel, :Items, selected)
            UI.ChangeWidget(:sb_attr, :Items, attrs)
          end
        elsif ret == :pb_del
          todel = Convert.to_string(UI.QueryWidget(:sb_attr_sel, :CurrentItem))
          if todel != nil
            attrs = Builtins.add(attrs, todel)
            attrs = Builtins.lsort(attrs)
            selected = Builtins.filter(selected) { |attr| attr != todel }
            UI.ChangeWidget(:sb_attr_sel, :Items, selected)
            UI.ChangeWidget(:sb_attr, :Items, attrs)
          end
        end
      end
      UI.CloseDialog
      deep_copy(selected)
    end

    # Popup to add/edit the acl "by" clauses
    def AddAclAccess(suffix, access)
      access = deep_copy(access)
      itemlist = []
      Builtins.foreach(
        [
          :who_all,
          :who_users,
          :who_anon,
          :who_self,
          :who_dn,
          :who_dn_subtree,
          :who_group
        ]
      ) do |i|
        itemlist = Builtins.add(
          itemlist,
          Item(Id(i), Ops.get(@whoId2String, [i, 0], ""))
        )
      end 


      access_itemlist = []
      Builtins.foreach(
        [
          :access_empty,
          :access_none,
          :access_disclose,
          :access_auth,
          :access_compare,
          :access_read,
          :access_write,
          :access_manage
        ]
      ) do |i|
        access_itemlist = Builtins.add(
          access_itemlist,
          Item(Id(i), Ops.get(@accessId2String, [i, 0], ""))
        )
      end 


      widget = VBox(
        VSpacing(1),
        HSquash(
          VSquash(
            VBox(
              Left(
                ComboBox(
                  Id(:cb_who),
                  Opt(:notify),
                  _("Who should this rule apply to"),
                  itemlist
                )
              ),
              Left(
                HBox(
                  InputField(Id(:te_who_dn), Opt(:hstretch), _("Entry DN")),
                  Bottom(PushButton(Id(:pb_who), _("Select")))
                )
              ),
              Left(
                ComboBox(
                  Id(:cb_access),
                  _("Define the Access Level"),
                  access_itemlist
                )
              ),
              RadioButtonGroup(
                Id(:rbg_aclcontrol),
                VBox(
                  Left(
                    RadioButton(
                      Id("stop"),
                      _("Stop access control evaluation here (default)"),
                      true
                    )
                  ),
                  Left(
                    RadioButton(
                      Id("break"),
                      _("Continue with next access control rule (\"break\")")
                    )
                  ),
                  Left(
                    RadioButton(
                      Id("continue"),
                      _("Continue evaluation of this rule (\"continue\")")
                    )
                  )
                )
              ),
              HBox(Wizard.CancelOKButtonBox)
            )
          )
        )
      )
      UI.OpenDialog(Opt(:decorated), widget)

      UI.ChangeWidget(Id(:te_who_dn), :Enabled, false)
      UI.ChangeWidget(Id(:pb_who), :Enabled, false)

      if access != nil
        UI.ChangeWidget(
          Id(:cb_who),
          :Value,
          Ops.get_symbol(access, "type", :nil)
        )
        UI.ChangeWidget(
          Id(:cb_access),
          :Value,
          Ops.get_symbol(access, "level", :nil)
        )
        UI.ChangeWidget(
          Id(:rbg_aclcontrol),
          :CurrentButton,
          Ops.get_string(access, "control", "stop")
        )
        if Ops.get_symbol(access, "type", :nil) == :who_dn ||
            Ops.get_symbol(access, "type", :nil) == :who_dn_subtree ||
            Ops.get_symbol(access, "type", :nil) == :who_group
          UI.ChangeWidget(Id(:pb_who), :Enabled, true)
          UI.ChangeWidget(Id(:te_who_dn), :Enabled, true)
          UI.ChangeWidget(
            Id(:te_who_dn),
            :Value,
            Ops.get_string(access, "value", "")
          )
        end
      end
      ret = :next
      res = {}
      while true
        ret = Convert.to_symbol(UI.UserInput)
        Builtins.y2milestone("Input event: %1", ret)
        if ret == :ok
          type = Convert.to_symbol(UI.QueryWidget(Id(:cb_who), :Value))
          Ops.set(res, "type", type)

          if type == :who_dn || type == :who_dn_subtree || type == :who_group
            Ops.set(res, "value", UI.QueryWidget(Id(:te_who_dn), :Value))
            if Ops.get_string(res, "value", "") == ""
              Popup.Error(_("Please enter a DN in the textfield"))
              next
            else
              if !AuthServer.ValidateDn(Ops.get_string(res, "value", ""))
                Popup.Error(
                  Ops.add(
                    Ops.add(
                      Ops.add("\"", Ops.get_string(res, "value", "")),
                      "\""
                    ),
                    _("is not a valid LDAP DN")
                  )
                )
                next
              end
            end
          end

          Ops.set(res, "level", UI.QueryWidget(Id(:cb_access), :Value))
          Ops.set(
            res,
            "control",
            Convert.to_string(
              UI.QueryWidget(Id(:rbg_aclcontrol), :CurrentButton)
            )
          )

          break
        elsif ret == :cancel
          res = nil
          break
        elsif ret == :cb_who
          cb_val = Convert.to_symbol(UI.QueryWidget(Id(:cb_who), :Value))
          if cb_val == :who_all || cb_val == :who_users || cb_val == :who_anon ||
              cb_val == :who_self
            UI.ChangeWidget(Id(:te_who_dn), :Enabled, false)
            UI.ChangeWidget(Id(:pb_who), :Enabled, false)
          elsif cb_val == :who_dn || cb_val == :who_dn_subtree ||
              cb_val == :who_group
            UI.ChangeWidget(Id(:te_who_dn), :Enabled, true)
            UI.ChangeWidget(Id(:pb_who), :Enabled, true)
            if cb_val == :who_dn
              UI.ChangeWidget(Id(:te_who_dn), :Label, _("Entry DN"))
            elsif cb_val == :who_dn_subtree
              UI.ChangeWidget(Id(:te_who_dn), :Label, _("Subtree DN"))
            elsif cb_val == :who_group
              UI.ChangeWidget(Id(:te_who_dn), :Label, _("Group DN"))
            end
          end
        elsif ret == :pb_who
          dn = LdapPopup.InitAndBrowseTree(
            suffix,
            { "hostname" => "localhost", "port" => "389" }
          )
          UI.ChangeWidget(Id(:te_who_dn), :Value, dn)
        end
      end
      UI.CloseDialog
      deep_copy(res)
    end

    def AddAclTarget(suffix, acl)
      acl = deep_copy(acl)
      itemlist = []
      Builtins.foreach(@whatString2Label) do |k, v|
        itemlist = Builtins.add(itemlist, Item(Id(k), v))
      end 

      addAclWidget = VBox(
        Heading(_("Edit Access Control Rule")),
        HSquash(
          VSquash(
            VBox(
              Frame(
                _("Target Objects"),
                VBox(
                  HBox(
                    Left(
                      ComboBox(
                        Id(:cb_what),
                        Opt(:notify),
                        _("Who should this rule apply to"),
                        itemlist
                      )
                    ),
                    InputField(Id(:te_dn), Opt(:hstretch), _("Entry DN")),
                    Bottom(PushButton(Id(:pb_dn), _("Select")))
                  ),
                  VSpacing(0.5),
                  Left(
                    VBox(
                      Left(
                        CheckBox(
                          Id(:cb_filter),
                          Opt(:notify),
                          _("Matching the filter:")
                        )
                      ),
                      Left(
                        InputField(
                          Id(:te_filter),
                          Opt(:hstretch),
                          _("LDAP Filter")
                        )
                      )
                    )
                  ),
                  VSpacing(0.5),
                  Left(
                    CheckBox(
                      Id(:cb_attrs),
                      Opt(:notify),
                      _("Apply this rule only to the listed attribute")
                    )
                  ),
                  HBox(
                    Left(
                      InputField(Id(:te_attrs), Opt(:hstretch), _("Attributes"))
                    ),
                    Bottom(PushButton(Id(:pb_attrs), _("Edit")))
                  )
                )
              ),
              VSpacing(0.5),
              Frame(
                _("Access Level"),
                VBox(
                  HBox(
                    MinSize(
                      60,
                      7,
                      Table(
                        Id(:tab_access),
                        Opt(:keepSorting),
                        Header(
                          _("Who"),
                          _("DN"),
                          _("Access Level"),
                          _("Flow Control")
                        )
                      )
                    ),
                    VBox(
                      PushButton(Id(:pb_up), _("Up")),
                      PushButton(Id(:pb_down), _("Down"))
                    )
                  ),
                  Left(
                    HBox(
                      PushButton(Id(:pb_add), Label.AddButton),
                      PushButton(Id(:pb_edit), Label.EditButton),
                      PushButton(Id(:pb_del), Label.DeleteButton)
                    )
                  )
                )
              ),
              VSpacing(1),
              HBox(Wizard.CancelOKButtonBox)
            )
          )
        )
      )

      UI.OpenDialog(Opt(:decorated), addAclWidget)

      if acl != nil
        UI.ChangeWidget(
          Id(:cb_what),
          :Value,
          Ops.get_string(acl, ["target", "what"], "*")
        )
        if Ops.get_string(acl, ["target", "what"], "") == "base"
          UI.ChangeWidget(Id(:te_dn), :Enabled, true)
          UI.ChangeWidget(Id(:pb_dn), :Enabled, true)
          UI.ChangeWidget(
            Id(:te_dn),
            :Value,
            Ops.get_string(acl, ["target", "dn"], "")
          )
        elsif Ops.get_string(acl, ["target", "what"], "") == "subtree"
          UI.ChangeWidget(Id(:te_dn), :Enabled, true)
          UI.ChangeWidget(
            Id(:te_dn),
            :Value,
            Ops.get_string(acl, ["target", "dn"], "")
          )
          UI.ChangeWidget(Id(:te_dn), :Label, _("Subtree DN"))
        elsif Ops.get_string(acl, ["target", "what"], "") == "*"
          UI.ChangeWidget(Id(:te_dn), :Enabled, false)
          UI.ChangeWidget(Id(:pb_dn), :Enabled, false)
        end
        if Ops.get_string(acl, ["target", "filter"], "") != ""
          UI.ChangeWidget(Id(:cb_filter), :Value, true)
          UI.ChangeWidget(Id(:te_filter), :Enabled, true)
          UI.ChangeWidget(
            Id(:te_filter),
            :Value,
            Ops.get_string(acl, ["target", "filter"], "")
          )
        else
          UI.ChangeWidget(Id(:cb_filter), :Value, false)
          UI.ChangeWidget(Id(:te_filter), :Enabled, false)
        end
        if Ops.get_string(acl, ["target", "attrs"], "") != ""
          UI.ChangeWidget(Id(:cb_attrs), :Value, true)
          UI.ChangeWidget(Id(:te_attrs), :Enabled, true)
          UI.ChangeWidget(Id(:pb_attrs), :Enabled, true)
          UI.ChangeWidget(
            Id(:te_attrs),
            :Value,
            Ops.get_string(acl, ["target", "attrs"], "")
          )
        else
          UI.ChangeWidget(Id(:cb_attrs), :Value, false)
          UI.ChangeWidget(Id(:te_attrs), :Enabled, false)
        end
      else
        UI.ChangeWidget(Id(:te_dn), :Enabled, false)
        UI.ChangeWidget(Id(:pb_dn), :Enabled, false)
        UI.ChangeWidget(Id(:cb_what), :Value, "*")
        UI.ChangeWidget(Id(:cb_filter), :Value, false)
        UI.ChangeWidget(Id(:te_filter), :Enabled, false)
        UI.ChangeWidget(Id(:cb_attrs), :Value, false)
        UI.ChangeWidget(Id(:te_attrs), :Enabled, false)
        UI.ChangeWidget(Id(:pb_attrs), :Enabled, false)
      end

      ret = :next
      result = {}
      accesslist = Ops.get_list(acl, "access", [])
      updateTable = true
      selected = 0
      while true
        if updateTable
          pos = -1
          itemlist2 = Builtins.maplist(accesslist) do |v|
            pos = Ops.add(pos, 1)
            Item(
              Id(pos),
              Ops.get(@whoId2String, [Ops.get_symbol(v, "type", :none), 0], ""),
              Ops.get_string(v, "value", ""),
              Ops.get(
                @accessId2String,
                [Ops.get_symbol(v, "level", :none), 0],
                ""
              ),
              Ops.get_string(v, "control", "stop")
            )
          end
          UI.ChangeWidget(:tab_access, :Items, itemlist2)
          UI.ChangeWidget(Id(:tab_access), :CurrentItem, selected)
          updateTable = false
        end

        ret = Convert.to_symbol(UI.UserInput)
        Builtins.y2milestone("Input event: %1", ret)
        selected = Convert.to_integer(
          UI.QueryWidget(Id(:tab_access), :CurrentItem)
        )
        if ret == :ok
          what = {}
          Ops.set(what, "what", UI.QueryWidget(Id(:cb_what), :Value))
          Ops.set(what, "dn", UI.QueryWidget(Id(:te_dn), :Value))
          if Ops.get_string(what, "what", "") == "base" ||
              Ops.get_string(what, "what", "") == "subtree"
            if !AuthServer.ValidateDn(Ops.get_string(what, "dn", ""))
              Popup.Error(
                Ops.add(
                  Ops.add(Ops.add("\"", Ops.get_string(what, "dn", "")), "\""),
                  _("is not a valid LDAP DN")
                )
              )
              next
            end
          end
          if Convert.to_boolean(UI.QueryWidget(Id(:cb_attrs), :Value))
            if "" != Convert.to_string(UI.QueryWidget(Id(:te_attrs), :Value))
              # FIXME: Validate attribute types
              Ops.set(what, "attrs", UI.QueryWidget(Id(:te_attrs), :Value))
            else
              Popup.Error(
                _(
                  "Enter a list of valid attributes in the <b>Attributes</b> textfield"
                )
              )
              next
            end
          end

          if Convert.to_boolean(UI.QueryWidget(Id(:cb_filter), :Value))
            if "" != UI.QueryWidget(Id(:te_filter), :Value)
              Ops.set(what, "filter", UI.QueryWidget(Id(:te_filter), :Value))
            else
              Popup.Error(_("Enter valid a LDAP filter in the textfield"))
              next
            end
          end
          if Builtins.size(accesslist) == 0
            Popup.Error(
              _("You must add at least one item to the \"Access Level\" list.")
            )
            next
          end


          Ops.set(result, "target", what)
          Ops.set(result, "access", accesslist)
          Builtins.y2milestone("New ACL: %1", result)
          break
        elsif ret == :cancel
          result = nil
          break
        elsif ret == :cb_what
          cb_val = Convert.to_string(UI.QueryWidget(Id(:cb_what), :Value))
          if cb_val == "*"
            UI.ChangeWidget(Id(:te_dn), :Enabled, false)
            UI.ChangeWidget(Id(:pb_dn), :Enabled, false)
          elsif cb_val == "base" || cb_val == "subtree"
            UI.ChangeWidget(Id(:te_dn), :Enabled, true)
            UI.ChangeWidget(Id(:pb_dn), :Enabled, true)
            if cb_val == "subtree"
              UI.ChangeWidget(Id(:te_dn), :Label, _("Subtree DN"))
            else
              UI.ChangeWidget(Id(:te_dn), :Label, _("Entry DN"))
            end
          end
        elsif ret == :pb_dn
          dn = LdapPopup.InitAndBrowseTree(
            suffix,
            { "hostname" => "localhost", "port" => "389" }
          )
          UI.ChangeWidget(Id(:te_dn), :Value, dn)
        elsif ret == :cb_filter
          if Convert.to_boolean(UI.QueryWidget(Id(:cb_filter), :Value))
            UI.ChangeWidget(Id(:te_filter), :Enabled, true)
          else
            UI.ChangeWidget(Id(:te_filter), :Enabled, false)
          end
        elsif ret == :cb_attrs
          if Convert.to_boolean(UI.QueryWidget(Id(:cb_attrs), :Value))
            UI.ChangeWidget(Id(:te_attrs), :Enabled, true)
            UI.ChangeWidget(Id(:pb_attrs), :Enabled, true)
          else
            UI.ChangeWidget(Id(:te_attrs), :Enabled, false)
            UI.ChangeWidget(Id(:pb_attrs), :Enabled, false)
          end
        elsif ret == :pb_attrs
          attr_string = Convert.to_string(UI.QueryWidget(Id(:te_attrs), :Value))
          attrs = Builtins.splitstring(attr_string, ",")
          attrs = SelectAttributes(attrs)
          attr_string = Builtins.mergestring(attrs, ",")
          UI.ChangeWidget(Id(:te_attrs), :Value, attr_string)
        elsif ret == :pb_add
          access = AddAclAccess(suffix, nil)
          if access != nil
            accesslist = Builtins.add(accesslist, access)
            updateTable = true
          end
        elsif ret == :pb_edit
          if selected != nil
            access = Ops.get(accesslist, selected)
            access = AddAclAccess(suffix, access)
            if access != nil
              Ops.set(accesslist, selected, access)
              updateTable = true
            end
          end
        elsif ret == :pb_del
          if selected != nil
            accesslist = Builtins.remove(accesslist, selected)
            updateTable = true
          end
        elsif ret == :pb_up
          if selected != nil && Ops.greater_than(selected, 0)
            newIndex = Ops.subtract(selected, 1)
            oldItem = Ops.get(accesslist, newIndex)
            Ops.set(accesslist, newIndex, Ops.get(accesslist, selected))
            Ops.set(accesslist, selected, oldItem)
            updateTable = true
            selected = newIndex
          end
        elsif ret == :pb_down
          if selected != nil &&
              Ops.less_than(
                selected,
                Ops.subtract(Builtins.size(accesslist), 1)
              )
            newIndex = Ops.add(selected, 1)
            oldItem = Ops.get(accesslist, newIndex)
            Ops.set(accesslist, newIndex, Ops.get(accesslist, selected))
            Ops.set(accesslist, selected, oldItem)
            updateTable = true
            selected = newIndex
          end
        end
      end
      UI.CloseDialog
      deep_copy(result)
    end

    def GetAclWidget
      aclList = VBox(
        VSpacing(1),
        VBox(
          HBox(
            MinSize(
              60,
              7,
              Table(
                Id(:tab_acl),
                Opt(:keepSorting),
                Header(_("Target"), _("DN"), _("Filter"), _("Attributes"))
              )
            ),
            VBox(
              PushButton(Id(:pb_up), _("Up")),
              PushButton(Id(:pb_down), _("Down"))
            )
          ),
          Left(
            HBox(
              PushButton(Id(:pb_add), Label.AddButton),
              PushButton(Id(:pb_edit), Label.EditButton),
              PushButton(Id(:pb_del), Label.DeleteButton)
            )
          )
        )
      )
      deep_copy(aclList)
    end


    def DbAclRead(dbindex, readAcls)
      readAcls = deep_copy(readAcls)
      @acllist = []
      if readAcls == nil
        Builtins.y2milestone("Unparseable ACLs")
        @acllist = nil
        UI.ChangeWidget(Id(:tab_acl), :Enabled, false)
        UI.ChangeWidget(Id(:pb_add), :Enabled, false)
        UI.ChangeWidget(Id(:pb_del), :Enabled, false)
        UI.ChangeWidget(Id(:pb_edit), :Enabled, false)
        Popup.Error(
          _(
            "The selected database contains access control rules that are currently\nnot supported by YaST. The Access Control Dialog will be disabled.\n"
          )
        )
      else
        Builtins.foreach(readAcls) do |acl|
          targetMap = Ops.get_map(acl, "target", {})
          resMap = {}
          Ops.set(resMap, "target", {})
          Ops.set(resMap, "access", [])
          if Builtins.size(targetMap) == 0
            Ops.set(resMap, ["target", "what"], "*")
          else
            dnMap = Ops.get_map(targetMap, "dn", {})
            if Ops.greater_than(Builtins.size(dnMap), 0)
              Ops.set(
                resMap,
                ["target", "what"],
                Ops.get_string(dnMap, "style", "")
              )
              Ops.set(
                resMap,
                ["target", "dn"],
                Ops.get_string(dnMap, "value", "")
              )
            else
              Ops.set(resMap, ["target", "what"], "*")
            end
            Ops.set(
              resMap,
              ["target", "filter"],
              Ops.get_string(targetMap, "filter", "")
            )
            Ops.set(
              resMap,
              ["target", "attrs"],
              Ops.get_string(targetMap, "attrs", "")
            )
          end
          accessList = []
          Builtins.foreach(Ops.get_list(acl, "access", [])) do |access|
            accessMap = {}
            Ops.set(
              accessMap,
              "level",
              Ops.get(
                @accessString2Id,
                Ops.get_string(access, "level", ""),
                :access_none
              )
            )
            Ops.set(
              accessMap,
              "type",
              Ops.get(@whoString2Id, Ops.get_string(access, "type", ""), :nil)
            )
            Ops.set(accessMap, "value", Ops.get_string(access, "value", ""))
            Ops.set(accessMap, "control", Ops.get_string(access, "control", ""))
            accessList = Builtins.add(accessList, accessMap)
          end
          Ops.set(resMap, "access", accessList)
          @acllist = Builtins.add(@acllist, resMap)
        end 

        pos = -1
        itemlist = Builtins.maplist(@acllist) do |v|
          pos = Ops.add(pos, 1)
          dn = ""
          if Ops.get_string(v, ["target", "what"], "*") != "*" &&
              Ops.get_string(v, ["target", "dn"], "") == ""
            dn = "<Root-DSE>"
          else
            dn = Ops.get_string(v, ["target", "dn"], "")
          end
          Item(
            Id(pos),
            Ops.get(
              @whatString2Label,
              Ops.get_string(v, ["target", "what"], ""),
              ""
            ),
            dn,
            Ops.get_string(v, ["target", "filter"], ""),
            Ops.get_string(v, ["target", "attrs"], "All Attributes")
          )
        end
        UI.ChangeWidget(:tab_acl, :Items, itemlist)
      end
      true
    end

    def DbAclWrite(dbindex)
      return nil if @acllist == nil

      outlist = []
      Builtins.foreach(@acllist) do |acl|
        Builtins.y2milestone("------------------------------")
        Builtins.y2milestone(
          "ACL Target: %1",
          Ops.get_string(acl, ["target", "what"], "<nul>")
        )
        targetmap = {}
        if Ops.get_string(acl, ["target", "what"], "*") != "*"
          dn = {
            "style" => Ops.get_string(acl, ["target", "what"], ""),
            "value" => Ops.get_string(acl, ["target", "dn"], "")
          }
          Ops.set(targetmap, "dn", dn)
        end
        if Ops.get_string(acl, ["target", "filter"], "") != ""
          Ops.set(
            targetmap,
            "filter",
            Ops.get_string(acl, ["target", "filter"], "")
          )
        end
        if Ops.get_string(acl, ["target", "attrs"], "") != ""
          Ops.set(
            targetmap,
            "attrs",
            Ops.get_string(acl, ["target", "attrs"], "")
          )
        end
        Builtins.y2milestone("ACL Target: %1", targetmap)
        outlist_access = []
        Builtins.foreach(Ops.get_list(acl, "access", [])) do |access|
          Ops.set(
            access,
            "level",
            Ops.get(
              @accessId2String,
              [Ops.get_symbol(access, "level", :nil), 1],
              "none"
            )
          )
          Ops.set(
            access,
            "type",
            Ops.get(
              @whoId2String,
              [Ops.get_symbol(access, "type", :nil), 1],
              ""
            )
          )
          Builtins.y2milestone("ACL Access: %1", access)
          outlist_access = Builtins.add(outlist_access, access)
        end
        outlist = Builtins.add(
          outlist,
          { "target" => targetmap, "access" => outlist_access }
        )
      end 

      deep_copy(outlist)
    end

    def DbAclInput(handler_cmd, dbindex)
      db = {}
      db = AuthServer.ReadDatabase(dbindex) if Ops.greater_or_equal(dbindex, 0)
      suffix = Ops.get_string(db, "suffix", "")
      Builtins.y2milestone("suffix: %1", suffix)
      updateTable = false

      selected = Convert.to_integer(UI.QueryWidget(Id(:tab_acl), :CurrentItem))

      if handler_cmd == :pb_add
        aclmap = AddAclTarget(suffix, nil)
        if aclmap != nil
          @acllist = Builtins.add(@acllist, aclmap)
          updateTable = true
        end
      elsif handler_cmd == :pb_del
        if selected != nil
          @acllist = Builtins.remove(@acllist, selected)
          updateTable = true
          selected = 0
        end
      elsif handler_cmd == :pb_edit
        if selected != nil
          aclmap = Ops.get(@acllist, selected)
          aclmap = AddAclTarget(suffix, aclmap)
          if aclmap != nil
            Ops.set(@acllist, selected, aclmap)
            updateTable = true
          end
        end
      elsif handler_cmd == :pb_up
        if selected != nil && Ops.greater_than(selected, 0)
          newIndex = Ops.subtract(selected, 1)
          oldItem = Ops.get(@acllist, newIndex)
          Ops.set(@acllist, newIndex, Ops.get(@acllist, selected))
          Ops.set(@acllist, selected, oldItem)
          updateTable = true
          selected = newIndex
        end
      elsif handler_cmd == :pb_down
        if selected != nil &&
            Ops.less_than(selected, Ops.subtract(Builtins.size(@acllist), 1))
          newIndex = Ops.add(selected, 1)
          oldItem = Ops.get(@acllist, newIndex)
          Ops.set(@acllist, newIndex, Ops.get(@acllist, selected))
          Ops.set(@acllist, selected, oldItem)
          updateTable = true
          selected = newIndex
        end
      end

      if updateTable
        pos = -1
        itemlist = Builtins.maplist(@acllist) do |v|
          pos = Ops.add(pos, 1)
          dn = ""
          if Ops.get_string(v, ["target", "what"], "*") != "*" &&
              Ops.get_string(v, ["target", "dn"], "") == ""
            dn = "<Root-DSE>"
          else
            dn = Ops.get_string(v, ["target", "dn"], "")
          end
          Item(
            Id(pos),
            Ops.get(
              @whatString2Label,
              Ops.get_string(v, ["target", "what"], ""),
              ""
            ),
            dn,
            Ops.get_string(v, ["target", "filter"], ""),
            Ops.get_string(v, ["target", "attrs"], "All Attributes")
          )
        end
        UI.ChangeWidget(:tab_acl, :Items, itemlist)
        UI.ChangeWidget(Id(:tab_acl), :CurrentItem, selected)
      end
      true
    end

    def GetSyncConsWidget
      widget = Top(
        ReplacePoint(
          Id(:syncConsWidget),
          HSquash(
            VBox(
              VSpacing(0.5),
              Left(
                CheckBox(
                  Id(:cb_syncrepl),
                  Opt(:notify),
                  _("This database is a Replication Consumer."),
                  false
                )
              ),
              VSpacing(0.3),
              VBox(
                Id(:f_synccons),
                Left(
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
                        _("Provider Name"),
                        ""
                      ),
                      HSpacing(),
                      HSquash(
                        IntField(Id(:if_sync_port), _("Port"), 0, 65536, 389)
                      ),
                      HSpacing(),
                      VBox(
                        Bottom(
                          CheckBox(Id(:cb_start_tls), _("Use StartTLS"), true)
                        ),
                        VSpacing(0.3)
                      )
                    )
                  )
                ),
                VSpacing(0.3),
                Left(
                  HBox(
                    ComboBox(
                      Id(:cb_sync_type),
                      Opt(:notify),
                      _("Replication Type"),
                      ["refreshAndPersist", "refreshOnly"]
                    ),
                    HSpacing(),
                    VSquash(
                      HBox(
                        Id(:hb_rep_interval),
                        VBox(Bottom(Label(_("Replication Interval")))),
                        HSpacing(),
                        HSquash(
                          IntField(Id(:if_sync_int_d), _("Days"), 0, 99, 0)
                        ),
                        HSpacing(),
                        HSquash(
                          IntField(Id(:if_sync_int_h), _("Hours"), 0, 23, 0)
                        ),
                        HSpacing(),
                        HSquash(
                          IntField(Id(:if_sync_int_m), _("Minutes"), 0, 59, 0)
                        ),
                        HSpacing(),
                        HSquash(
                          IntField(Id(:if_sync_int_s), _("Seconds"), 0, 59, 0)
                        ),
                        HStretch()
                      )
                    )
                  )
                ),
                VSpacing(0.3),
                Left(
                  HBox(
                    InputField(
                      Id(:te_sync_binddn),
                      Opt(:hstretch),
                      _("Authentication DN"),
                      ""
                    ),
                    HSpacing(),
                    Password(
                      Id(:te_sync_cred),
                      Opt(:hstretch),
                      _("Password"),
                      ""
                    )
                  )
                ),
                VSpacing(0.3),
                Left(
                  VSquash(
                    HBox(
                      VBox(
                        Bottom(
                          CheckBox(
                            Id(:cb_update_ref),
                            Opt(:notify),
                            _("Custom update referral")
                          )
                        ),
                        VSpacing(0.3)
                      ),
                      HSpacing(),
                      ComboBox(
                        Id(:cb_updateref_prot),
                        Opt(:notify),
                        _("Protocol"),
                        ["ldap", "ldaps"]
                      ),
                      HSpacing(),
                      InputField(
                        Id(:te_updateref_target),
                        Opt(:hstretch),
                        _("Target Host"),
                        ""
                      ),
                      HSpacing(),
                      HSquash(
                        IntField(
                          Id(:if_updateref_port),
                          _("Port"),
                          0,
                          65536,
                          389
                        )
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
      deep_copy(widget)
    end

    def urlComponentsMatch(url1, url2)
      url1 = deep_copy(url1)
      url2 = deep_copy(url2)
      if Ops.get_string(url1, "protocol", "") !=
          Ops.get_string(url2, "protocol", "")
        return false
      end
      if Ops.get_string(url1, "target", "") !=
          Ops.get_string(url2, "target", "")
        return false
      end
      if Ops.get_integer(url1, "port", 0) != Ops.get_integer(url2, "port", 0)
        return false
      end
      true
    end

    def DbSyncConsRead(index, synccons, updateref)
      synccons = deep_copy(synccons)
      updateref = deep_copy(updateref)
      Builtins.y2milestone("DbSyncConsRead %1", index)
      if Builtins.size(synccons) == 0
        UI.ChangeWidget(:f_synccons, :Enabled, false)
      else
        UI.ChangeWidget(:f_synccons, :Enabled, true)
        UI.ChangeWidget(:cb_syncrepl, :Value, true)
        provider = Ops.get_map(synccons, "provider", {})
        UI.ChangeWidget(
          :te_sync_target,
          :Value,
          Ops.get_string(provider, "target", "")
        )
        UI.ChangeWidget(
          :cb_sync_prot,
          :Value,
          Ops.get_string(provider, "protocol", "")
        )
        if Ops.get_string(provider, "protocol", "") == "ldaps"
          UI.ChangeWidget(:cb_start_tls, :Value, false)
          UI.ChangeWidget(:cb_start_tls, :Enabled, false)
        else
          UI.ChangeWidget(
            :cb_start_tls,
            :Value,
            Ops.get_boolean(synccons, "starttls", true)
          )
        end
        UI.ChangeWidget(
          :if_sync_port,
          :Value,
          Ops.get_integer(provider, "port", 0)
        )
        UI.ChangeWidget(
          :cb_sync_type,
          :Value,
          Ops.get_string(synccons, "type", "")
        )
        if Ops.get_string(synccons, "type", "") == "refreshAndPersist"
          UI.ChangeWidget(:hb_rep_interval, :Enabled, false)
        else
          UI.ChangeWidget(
            :if_sync_int_d,
            :Value,
            Ops.get_integer(synccons, ["interval", "days"], 0)
          )
          UI.ChangeWidget(
            :if_sync_int_h,
            :Value,
            Ops.get_integer(synccons, ["interval", "hours"], 0)
          )
          UI.ChangeWidget(
            :if_sync_int_m,
            :Value,
            Ops.get_integer(synccons, ["interval", "mins"], 0)
          )
          UI.ChangeWidget(
            :if_sync_int_s,
            :Value,
            Ops.get_integer(synccons, ["interval", "secs"], 0)
          )
        end
        UI.ChangeWidget(
          :te_sync_binddn,
          :Value,
          Ops.get_string(synccons, "binddn", "")
        )
        UI.ChangeWidget(
          :te_sync_cred,
          :Value,
          Ops.get_string(synccons, "credentials", "")
        )
        if Builtins.size(updateref) == 0
          # no updateref
          UI.ChangeWidget(:cb_update_ref, :Value, true)
          UI.ChangeWidget(:te_updateref_target, :Value, "")
        elsif urlComponentsMatch(provider, updateref)
          UI.ChangeWidget(:cb_update_ref, :Value, false)
          UI.ChangeWidget(:cb_updateref_prot, :Enabled, false)
          UI.ChangeWidget(:te_updateref_target, :Enabled, false)
          UI.ChangeWidget(:if_updateref_port, :Enabled, false)
        else
          UI.ChangeWidget(:cb_update_ref, :Value, true)
          UI.ChangeWidget(
            :cb_updateref_prot,
            :Value,
            Ops.get_string(updateref, "protocol ", "ldap")
          )
          UI.ChangeWidget(
            :te_updateref_target,
            :Value,
            Ops.get_string(updateref, "target", "")
          )
          UI.ChangeWidget(
            :if_updateref_port,
            :Value,
            Ops.get_integer(updateref, "port", 389)
          )
        end
      end
      true
    end

    def DbSyncConsInput(handler_cmd, index)
      Builtins.y2milestone("DbSyncConsInput %1 %2", handler_cmd, index)
      if handler_cmd == :cb_syncrepl
        if UI.QueryWidget(:cb_syncrepl, :Value) == true
          UI.ChangeWidget(:f_synccons, :Enabled, true)
          if Convert.to_boolean(UI.QueryWidget(:cb_update_ref, :Value)) == true
            UI.ChangeWidget(:te_updateref_target, :Enabled, true)
            UI.ChangeWidget(:cb_updateref_prot, :Enabled, true)
            UI.ChangeWidget(:if_updateref_port, :Enabled, true)
            UI.ChangeWidget(:te_updateref_target, :Value, "")
          else
            UI.ChangeWidget(:te_updateref_target, :Enabled, false)
            UI.ChangeWidget(:cb_updateref_prot, :Enabled, false)
            UI.ChangeWidget(:if_updateref_port, :Enabled, false)
            UI.ChangeWidget(:te_updateref_target, :Value, "")
          end
        else
          UI.ChangeWidget(:f_synccons, :Enabled, false)
        end
      end
      if handler_cmd == :cb_sync_prot
        prot = Convert.to_string(UI.QueryWidget(:cb_sync_prot, :Value))
        port = Convert.to_integer(UI.QueryWidget(:if_sync_port, :Value))
        if prot == "ldaps"
          UI.ChangeWidget(:cb_start_tls, :Value, false)
          UI.ChangeWidget(:cb_start_tls, :Enabled, false)
          UI.ChangeWidget(:if_sync_port, :Value, 636) if port == 389
        else
          UI.ChangeWidget(:cb_start_tls, :Value, true)
          UI.ChangeWidget(:cb_start_tls, :Enabled, true)
          UI.ChangeWidget(:if_sync_port, :Value, 389) if port == 636
        end
      end
      if handler_cmd == :cb_update_ref
        if Convert.to_boolean(UI.QueryWidget(:cb_update_ref, :Value)) == true
          UI.ChangeWidget(:te_updateref_target, :Enabled, true)
          UI.ChangeWidget(:cb_updateref_prot, :Enabled, true)
          UI.ChangeWidget(:if_updateref_port, :Enabled, true)
          UI.ChangeWidget(:te_updateref_target, :Value, "")
        else
          UI.ChangeWidget(:te_updateref_target, :Enabled, false)
          UI.ChangeWidget(:cb_updateref_prot, :Enabled, false)
          UI.ChangeWidget(:if_updateref_port, :Enabled, false)
          UI.ChangeWidget(:te_updateref_target, :Value, "")
        end
      end
      if handler_cmd == :cb_updateref_prot
        prot = Convert.to_string(UI.QueryWidget(:cb_updateref_prot, :Value))
        port = Convert.to_integer(UI.QueryWidget(:if_updateref_port, :Value))
        if prot == "ldaps"
          UI.ChangeWidget(:if_updateref_port, :Value, 636) if port == 389
        else
          UI.ChangeWidget(:if_updateref_port, :Value, 389) if port == 636
        end
      end
      if Convert.to_string(UI.QueryWidget(:cb_sync_type, :Value)) ==
          "refreshAndPersist"
        UI.ChangeWidget(:hb_rep_interval, :Enabled, false)
      else
        UI.ChangeWidget(:hb_rep_interval, :Enabled, true)
      end

      true
    end

    def DbSyncConsCheck(index)
      Builtins.y2milestone("DbSyncConsCheck %1", index)
      if UI.QueryWidget(:cb_syncrepl, :Value) == true
        if Convert.to_string(UI.QueryWidget(:cb_sync_type, :Value)) == "refreshOnly"
          days = Convert.to_integer(UI.QueryWidget(:if_sync_int_d, :Value))
          hours = Convert.to_integer(UI.QueryWidget(:if_sync_int_h, :Value))
          mins = Convert.to_integer(UI.QueryWidget(:if_sync_int_m, :Value))
          secs = Convert.to_integer(UI.QueryWidget(:if_sync_int_s, :Value))
          if days == 0 && hours == 0 && mins == 0 && secs == 0
            Popup.Error(_("Invalid replication interval specified"))
            return false
          end
        end
        prot = Convert.to_string(UI.QueryWidget(:cb_sync_prot, :Value))
        target = Convert.to_string(UI.QueryWidget(:te_sync_target, :Value))
        port = Convert.to_integer(UI.QueryWidget(:if_sync_port, :Value))

        # test connection
        provider = { "protocol" => prot, "target" => target, "port" => port }
        db = deep_copy(@baseDb)
        db = AuthServer.ReadDatabase(index) if Ops.greater_or_equal(index, 0)
        suffix = Ops.get_string(db, "suffix", "")
        testparm = {}
        testparm = Builtins.add(testparm, "target", provider)
        testparm = Builtins.add(
          testparm,
          "starttls",
          Convert.to_boolean(UI.QueryWidget(:cb_start_tls, :Value))
        )
        testparm = Builtins.add(
          testparm,
          "binddn",
          Convert.to_string(UI.QueryWidget(:te_sync_binddn, :Value))
        )
        testparm = Builtins.add(
          testparm,
          "credentials",
          Convert.to_string(UI.QueryWidget(:te_sync_cred, :Value))
        )
        testparm = Builtins.add(testparm, "basedn", suffix)
        if !Convert.to_boolean(
            SCR.Execute(path(".ldapserver.remoteBindCheck"), testparm)
          )
          err = SCR.Error(path(".ldapserver"))
          return Popup.ContinueCancelHeadline(
            _("Checking LDAP connectivity to the provider failed."),
            Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.add(
                      _("The test returned the following error messages:") + "\n\n\"",
                      Ops.get_string(err, "summary", "")
                    ),
                    "\"\n\""
                  ),
                  Ops.get_string(err, "description", "")
                ),
                "\"\n\n"
              ),
              _("Do you still want to continue?")
            )
          )
        end
        if !Convert.to_boolean(
            SCR.Execute(path(".ldapserver.remoteLdapSyncCheck"), testparm)
          )
          err = SCR.Error(path(".ldapserver"))
          return Popup.ContinueCancelHeadline(
            _("Checking the LDAPsync capabilities of the provider failed."),
            Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(
                    Ops.add(
                      _(
                        "Please verify that the target server is enabled to be a LDAPsync provider"
                      ) + "\n\n" +
                        _("The test returned the following error messages:") + "\n\"",
                      Ops.get_string(err, "summary", "")
                    ),
                    "\"\n\""
                  ),
                  Ops.get_string(err, "description", "")
                ),
                "\"\n\n"
              ),
              _("Do you still want to continue?")
            )
          )
        end
      end
      true
    end

    def DbSyncConsWrite(index)
      Builtins.y2milestone("DbSyncConsWrite %1", index)
      syncrepl = {}
      updateref = {}
      if UI.QueryWidget(:cb_syncrepl, :Value) == true
        prot = Convert.to_string(UI.QueryWidget(:cb_sync_prot, :Value))
        target = Convert.to_string(UI.QueryWidget(:te_sync_target, :Value))
        port = Convert.to_integer(UI.QueryWidget(:if_sync_port, :Value))
        provider = { "protocol" => prot, "target" => target, "port" => port }
        syncrepl = Builtins.add(syncrepl, "provider", provider)
        syncrepl = Builtins.add(
          syncrepl,
          "starttls",
          Convert.to_boolean(UI.QueryWidget(:cb_start_tls, :Value))
        )

        type = Convert.to_string(UI.QueryWidget(:cb_sync_type, :Value))
        syncrepl = Builtins.add(syncrepl, "type", type)

        if type == "refreshOnly"
          iv = {
            "days"  => Convert.to_integer(
              UI.QueryWidget(:if_sync_int_d, :Value)
            ),
            "hours" => Convert.to_integer(
              UI.QueryWidget(:if_sync_int_h, :Value)
            ),
            "mins"  => Convert.to_integer(
              UI.QueryWidget(:if_sync_int_m, :Value)
            ),
            "secs"  => Convert.to_integer(
              UI.QueryWidget(:if_sync_int_s, :Value)
            )
          }
          syncrepl = Builtins.add(syncrepl, "interval", iv)
        end
        db = deep_copy(@baseDb)
        db = AuthServer.ReadDatabase(index) if Ops.greater_or_equal(index, 0)
        basedn = Ops.get_string(db, "suffix", "")
        binddn = Convert.to_string(UI.QueryWidget(:te_sync_binddn, :Value))
        cred = Convert.to_string(UI.QueryWidget(:te_sync_cred, :Value))
        syncrepl = Builtins.add(syncrepl, "basedn", basedn)
        syncrepl = Builtins.add(syncrepl, "binddn", binddn)
        syncrepl = Builtins.add(syncrepl, "credentials", cred)
        if Convert.to_boolean(UI.QueryWidget(:cb_update_ref, :Value))
          if Convert.to_string(UI.QueryWidget(:te_updateref_target, :Value)) != ""
            updateref = Builtins.add(
              updateref,
              "protocol",
              Convert.to_string(UI.QueryWidget(:cb_updateref_prot, :Value))
            )
            updateref = Builtins.add(
              updateref,
              "target",
              Convert.to_string(UI.QueryWidget(:te_updateref_target, :Value))
            )
            updateref = Builtins.add(
              updateref,
              "port",
              Convert.to_integer(UI.QueryWidget(:if_updateref_port, :Value))
            )
          end
        else
          updateref = deep_copy(provider)
        end
      end
      Builtins.y2milestone("DbSyncConsWrite syncrepl: %1", syncrepl)
      { "syncrepl" => syncrepl, "updateref" => updateref }
    end

    def GetSyncProvWidget
      widget = Top(
        VBox(
          VSpacing(1),
          VBox(
            HBox(
              CheckBox(
                Id(:cb_synprov_enable),
                Opt(:notify),
                _("Enable ldapsync provider for this database"),
                false
              ),
              HSpacing(Opt(:hstretch))
            ),
            VSpacing(0.5),
            Frame(
              Id(:f_sync_settings),
              _("Checkpoint Settings"),
              VBox(
                HBox(
                  HSquash(
                    IntField(
                      Id(:if_syncprov_checkpoint_ops),
                      _("Operations"),
                      0,
                      2000000000,
                      0
                    )
                  ),
                  HSpacing(1),
                  HSquash(
                    IntField(
                      Id(:if_syncprov_checkpoint_min),
                      _("Minutes"),
                      0,
                      2000000000,
                      0
                    )
                  ),
                  HStretch()
                )
              )
            ),
            VSpacing(0.5),
            Frame(
              Id(:f_sync_slog),
              _("Session Log"),
              VBox(
                Left(
                  CheckBox(
                    Id(:cb_sync_slog),
                    Opt(:notify),
                    _("Enable Session Log")
                  )
                ),
                Left(
                  HSquash(
                    IntField(
                      Id(:if_syncprov_sessionlog),
                      _("Operations"),
                      0,
                      2000000000,
                      0
                    )
                  )
                )
              )
            )
          )
        )
      )
      deep_copy(widget)
    end

    def DbSyncProvRead(handler_cmd, index, syncprov)
      syncprov = deep_copy(syncprov)
      Builtins.y2milestone("DbSyncProvRead %1 %2", handler_cmd, index)
      if Builtins.size(syncprov) == 0
        UI.ChangeWidget(:cb_synprov_enable, :Value, false)
        UI.ChangeWidget(:f_sync_settings, :Enabled, false)
        UI.ChangeWidget(:f_sync_slog, :Enabled, false)
      else
        UI.ChangeWidget(:cb_synprov_enable, :Value, true)
        if Ops.get(syncprov, "checkpoint") != nil
          UI.ChangeWidget(
            :if_syncprov_checkpoint_ops,
            :Value,
            Ops.get_integer(syncprov, ["checkpoint", "ops"], 0)
          )
          UI.ChangeWidget(
            :if_syncprov_checkpoint_min,
            :Value,
            Ops.get_integer(syncprov, ["checkpoint", "min"], 0)
          )
        end
        if Ops.get(syncprov, "sessionlog") != nil
          UI.ChangeWidget(:cb_sync_slog, :Value, true)
          UI.ChangeWidget(
            :if_syncprov_sessionlog,
            :Value,
            Ops.get_integer(syncprov, "sessionlog", 0)
          )
        else
          UI.ChangeWidget(:if_syncprov_sessionlog, :Enabled, false)
        end
      end
      true
    end

    def DbSyncProvInput(handler_cmd, index)
      Builtins.y2milestone("DbSyncProvInput %1 %2", handler_cmd, index)
      if handler_cmd == :cb_synprov_enable
        if UI.QueryWidget(:cb_synprov_enable, :Value) == true
          UI.ChangeWidget(:f_sync_settings, :Enabled, true)
          UI.ChangeWidget(:f_sync_slog, :Enabled, true)
        else
          UI.ChangeWidget(:f_sync_settings, :Enabled, false)
          UI.ChangeWidget(:f_sync_slog, :Enabled, false)
        end
      end
      if UI.QueryWidget(:cb_sync_slog, :Value) == true
        UI.ChangeWidget(:if_syncprov_sessionlog, :Enabled, true)
      else
        UI.ChangeWidget(:if_syncprov_sessionlog, :Enabled, false)
      end
      true
    end

    def DbSyncProvWrite(index)
      Builtins.y2milestone("DbSyncProvWrite %1", index)
      syncprov = {}
      if UI.QueryWidget(:cb_synprov_enable, :Value) == true
        cp_ops = Convert.to_integer(
          UI.QueryWidget(:if_syncprov_checkpoint_ops, :Value)
        )
        cp_min = Convert.to_integer(
          UI.QueryWidget(:if_syncprov_checkpoint_min, :Value)
        )
        slog = Convert.to_integer(
          UI.QueryWidget(:if_syncprov_sessionlog, :Value)
        )
        syncprov = Builtins.add(syncprov, "enabled", true)
        if cp_ops != 0 || cp_min != 0
          cp = { "ops" => cp_ops, "min" => cp_min }
          syncprov = Builtins.add(syncprov, "checkpoint", cp)
        end
        if Ops.greater_than(slog, 0)
          syncprov = Builtins.add(syncprov, "sessionlog", slog)
        end
      end
      deep_copy(syncprov)
    end

    def DbPpolicy
      caption = _("Password Policy Settings")
      contents = deep_copy(@editPolicy)
      Wizard.SetContentsButtons(
        caption,
        contents,
        Ops.get_string(@HELPS, "ppolicy_edit", ""),
        Label.BackButton,
        Label.FinishButton
      )
      ret = :next
      DbPpolicyRead(-1)
      while true
        ret = Convert.to_symbol(UI.UserInput)
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :next
          @ppolicyNew = DbPpolicyWrite(-1)
          break
        elsif ret == :back
          break
        else
          DbPpolicyInput(ret, -1)
        end
      end
      ret
    end

    def DbSyncRepl
      caption = _("Replication Settings")
      contents = GetSyncConsWidget()
      Wizard.SetContentsButtons(
        caption,
        contents,
        Ops.get_string(@HELPS, "synccons_edit", ""),
        Label.BackButton,
        Label.NextButton
      )
      ret = :next
      DbSyncConsRead(-1, {}, {})
      while true
        ret = Convert.to_symbol(UI.UserInput)
        if ret == :abort || ret == :cancel
          if Popup.ReallyAbort(true)
            break
          else
            next
          end
        elsif ret == :next
          if DbSyncConsCheck(-1)
            @syncReplNew = DbSyncConsWrite(-1)
            break
          else
            next
          end
        elsif ret == :back
          break
        else
          DbSyncConsInput(ret, -1)
        end
      end
      ret = :syncrepl if Ops.greater_than(Builtins.size(@syncReplNew), 0)
      ret
    end

    def AddDbWizard
      aliases = {
        "basics"   => lambda { AddDbBasic(false) },
        "syncrepl" => lambda { DbSyncRepl() },
        "ppolicy"  => lambda { DbPpolicy() }
      }

      sequence = {
        "ws_start" => "basics",
        "basics"   => { :next => "syncrepl", :abort => :abort },
        "syncrepl" => {
          :next     => "ppolicy",
          :syncrepl => :next,
          :abort    => :abort
        },
        "ppolicy"  => { :next => :next, :abort => :abort }
      }

      @baseDb = {
        "rootdn"    => "cn=Administrator",
        "directory" => "/var/lib/ldap"
      }

      Wizard.CreateDialog

      ret = Sequencer.Run(aliases, sequence)

      UI.CloseDialog
      deep_copy(ret)
    end

    def GetDatabase
      deep_copy(@baseDb)
    end
    def GetPpolicy
      deep_copy(@ppolicyNew)
    end
    def GetSyncRepl
      deep_copy(@syncReplNew)
    end
    def GetCreateDir
      @createDbDir
    end
    def GetLdapConfBase
      @ldapconf_basedn
    end

    publish :function => :GetCreateBase, :type => "boolean ()"
    publish :function => :ResetCreateBase, :type => "boolean ()"
    publish :function => :AddDbBasic, :type => "symbol (boolean)"
    publish :function => :DbPpolicyRead, :type => "boolean (integer)"
    publish :function => :DbPpolicyWrite, :type => "map <string, any> (integer)"
    publish :function => :DbPpolicyInput, :type => "boolean (symbol, integer)"
    publish :function => :GetPpolicyWidget, :type => "term ()"
    publish :function => :SelectAttributes, :type => "list <string> (list <string>)"
    publish :function => :AddAclAccess, :type => "map (string, map)"
    publish :function => :AddAclTarget, :type => "map (string, map)"
    publish :function => :GetAclWidget, :type => "term ()"
    publish :function => :DbAclRead, :type => "boolean (integer, list <map>)"
    publish :function => :DbAclWrite, :type => "list <map> (integer)"
    publish :function => :DbAclInput, :type => "boolean (symbol, integer)"
    publish :function => :GetSyncConsWidget, :type => "term ()"
    publish :function => :DbSyncConsRead, :type => "boolean (integer, map, map)"
    publish :function => :DbSyncConsInput, :type => "boolean (symbol, integer)"
    publish :function => :DbSyncConsCheck, :type => "boolean (integer)"
    publish :function => :DbSyncConsWrite, :type => "map <string, any> (integer)"
    publish :function => :GetSyncProvWidget, :type => "term ()"
    publish :function => :DbSyncProvRead, :type => "boolean (symbol, integer, map)"
    publish :function => :DbSyncProvInput, :type => "boolean (symbol, integer)"
    publish :function => :DbSyncProvWrite, :type => "map <string, any> (integer)"
    publish :function => :AddDbWizard, :type => "any ()"
    publish :function => :GetDatabase, :type => "map <string, any> ()"
    publish :function => :GetPpolicy, :type => "map <string, any> ()"
    publish :function => :GetSyncRepl, :type => "map <string, any> ()"
    publish :function => :GetCreateDir, :type => "boolean ()"
    publish :function => :GetLdapConfBase, :type => "string ()"
  end

  LdapDatabase = LdapDatabaseClass.new
  LdapDatabase.main
end
