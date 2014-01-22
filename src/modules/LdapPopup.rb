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

# File:	modules/LdapPopup.ycp
# Package:	Configuration of LDAP
# Summary:	Additional user interface functions: special edit popups
# Authors:	Jiri Suchomel <jsuchome@suse.cz>
#
# $Id$
#
# Popups for editing the values of LDAP configuration tables.
require "yast"

module Yast
  class LdapPopupClass < Module
    def main
      Yast.import "UI"
      textdomain "ldap-client"

      Yast.import "Ldap"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"
    end

    # Popup for browsing LDAP tree and selecting the DN
    # WARNING we expect that LDAP connection is already correctly initialized !
    # @param [String] root_dn the starting point (root of tree); if empty string is
    # given, the search for available bases will be done automatically
    # @return DN of selected item, empty string when canceled
    def BrowseTree(root_dn)
      # get display mode
      display_info = UI.GetDisplayInfo
      textmode = Ops.get_boolean(display_info, "TextMode", true)

      # map of already read subtrees
      dns = {}
      # selected DN (return value)
      current_dn = ""

      contents = HBox(
        VSpacing(20),
        VBox(
          HSpacing(70),
          VSpacing(0.2),
          HBox(
            HSpacing(),
            ReplacePoint(Id(:reptree), Tree(Id(:tree), root_dn, [])),
            HSpacing()
          ),
          textmode ?
            HBox(
              HSpacing(1.5),
              PushButton(Id(:ok), Opt(:key_F10), Label.OKButton),
              PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
              # button label
              Right(PushButton(Id(:open), Opt(:key_F6), _("&Open"))),
              HSpacing(1.5)
            ) :
            ButtonBox(
              PushButton(Id(:ok), Opt(:key_F10), Label.OKButton),
              PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton)
            ),
          VSpacing(0.2)
        )
      )

      UI.OpenDialog(Opt(:decorated), contents)

      items = []
      out = Convert.convert(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => root_dn,
            "scope"        => root_dn != "" ? 0 : 1,
            "dn_only"      => true,
            "not_found_ok" => true
          }
        ),
        :from => "any",
        :to   => "list <string>"
      )
      items = Builtins.maplist(out) do |dn|
        Ops.set(dns, dn, false)
        Item(dn, false, [])
      end if Ops.greater_than(
        Builtins.size(out),
        0
      )

      if Ops.greater_than(Builtins.size(items), 0)
        UI.ReplaceWidget(
          Id(:reptree),
          textmode ?
            Tree(Id(:tree), root_dn, items) :
            Tree(Id(:tree), Opt(:notify), root_dn, items)
        )
        # no item is selected
        UI.ChangeWidget(:tree, :CurrentItem, nil)
      elsif root_dn == ""
        bases = Convert.to_list(
          SCR.Read(
            path(".ldap.search"),
            { "base_dn" => "", "scope" => 0, "attrs" => ["namingContexts"] }
          )
        )
        if Ops.greater_than(Builtins.size(bases), 0)
          items = Builtins.maplist(
            Ops.get_list(bases, [0, "namingContexts"], [])
          ) { |dn| Item(dn, false, []) }
        end
        if Ops.greater_than(Builtins.size(items), 0)
          UI.ReplaceWidget(
            Id(:reptree),
            textmode ?
              Tree(Id(:tree), root_dn, items) :
              Tree(Id(:tree), Opt(:notify), root_dn, items)
          )
          UI.ChangeWidget(:tree, :CurrentItem, nil)
        end
      end

      UI.SetFocus(Id(:tree)) if textmode

      subdns = []
      open_items = {}

      update_items = lambda do |its|
        its = deep_copy(its)
        Builtins.maplist(its) do |it|
          dn = Ops.get_string(it, 0, "")
          next Item(dn, true, Builtins.maplist(subdns) { |k| Item(k, false, []) }) if dn == current_dn
          last = Ops.subtract(Builtins.size(it), 1)
          next deep_copy(it) if Builtins.size(Ops.get_list(it, last, [])) == 0
          # `OpenItems doesn't work in ncurses...
          open = Builtins.haskey(open_items, dn) && !textmode
          Item(dn, open, update_items.call(Ops.get_list(it, last, [])))
        end
      end

      retval = root_dn
      while true
        ret = UI.UserInput
        if ret == :tree || ret == :open
          current_dn = Convert.to_string(
            UI.QueryWidget(Id(:tree), :CurrentItem)
          )
          if !Ops.get(dns, current_dn, false)
            subdns = Convert.convert(
              SCR.Read(
                path(".ldap.search"),
                {
                  "base_dn"      => current_dn,
                  "scope"        => 1,
                  "dn_only"      => true,
                  "not_found_ok" => true
                }
              ),
              :from => "any",
              :to   => "list <string>"
            )
            Ops.set(dns, current_dn, true)
            if Ops.greater_than(Builtins.size(subdns), 0)
              open_items = Convert.to_map(UI.QueryWidget(:tree, :OpenItems))
              items = update_items.call(items)
              UI.ReplaceWidget(
                Id(:reptree),
                textmode ?
                  Tree(Id(:tree), root_dn, items) :
                  Tree(Id(:tree), Opt(:notify), root_dn, items)
              )
              UI.ChangeWidget(Id(:tree), :CurrentItem, current_dn)
              open_items = {}
            end
          end
          UI.SetFocus(Id(:tree)) if textmode
        end
        if ret == :cancel
          retval = ""
          break
        end
        if ret == :ok
          dn = Convert.to_string(UI.QueryWidget(Id(:tree), :CurrentItem))
          if dn != nil
            retval = dn
          else
            retval = current_dn
          end
          break
        end
      end
      UI.CloseDialog
      retval
    end

    # Open the LDAP Browse popup and initialize initialize LDAP connection
    # before.
    # @param [Hash] connection init map with information passed to ldap agent
    # (see ldap agent '.ldap' Execute call documentation)
    # @param [String] root_dn the starting point (root of tree); if empty string is
    # given, the search for available bases will be done automatically
    # @return DN of selected item, empty string when canceled
    def InitAndBrowseTree(root_dn, connection)
      connection = deep_copy(connection)
      args = Ops.greater_than(Builtins.size(connection), 0) ?
        connection :
        {
          "hostname"   => Ldap.GetFirstServer(Ldap.server),
          "port"       => Ldap.GetFirstPort(Ldap.server),
          "use_tls"    => Ldap.ldap_tls ? "yes" : "no",
          "cacertdir"  => Ldap.tls_cacertdir,
          "cacertfile" => Ldap.tls_cacertfile
        }
      error = Ldap.LDAPInitWithTLSCheck(args)
      if error != ""
        Ldap.LDAPErrorMessage("init", error)
        return root_dn
      end
      BrowseTree(root_dn)
    end


    # Generic popup for editing attribute's value
    # @param map with settings, it could have these keys:
    #  "attr"	attribute name
    #  "value"	current attribute values
    #  "conflicts" list of forbidden values (e.g. existing 'cn' values)
    #  "single"	if attribute can have only one value
    #  "offer"	list of possible values for current attribute (e.g. existing
    #		groups for "secondaryGroup" attribute)
    #  "browse"	if Browse LDAP Tree widget should be provided for choosing DN
    # @return [Array] of atrtibute values (edited or unchanged)
    def EditAttribute(settings)
      settings = deep_copy(settings)
      attr = Ops.get_string(settings, "attr", "")
      value = Ops.get_list(settings, "value", [])
      conflicts = Ops.get_list(settings, "conflicts", [])
      offer = Ops.get_list(settings, "offer", [])
      single = Ops.get_boolean(settings, "single", false)
      browse = Ops.get_boolean(settings, "browse", false)

      # help text 1/3
      help_text = _("<p>Set the new value for the current attribute.</p>") +
        # help text 2/3
        _(
          "<p>If the attribute can have more values, add new entries\n" +
            "with <b>Add Value</b>. Sometimes the button contains the list of\n" +
            "possible values to use for the current attribute.\n" +
            "If the value of the edited attribute should be a distinguished name (DN),\n" +
            "it is possible to choose it from the LDAP tree using <b>Browse</b>.\n" +
            "</p>\n"
        )

      desc = Ldap.AttributeDescription(attr)

      if desc != ""
        # help text 3/3, %1 is attribute name, description follows.
        # The description will be not translated: maybe add a note
        # "available only in english" to the sentence for other languages?
        # Example:
        # "<p>The description of attribute \"%1\"<br>(available only in english):</p>"
        # or:
        # "<p>The description (only in english) of attribute \"%1\":<br></p>"
        help_text = Ops.add(
          Ops.add(
            help_text,
            Builtins.sformat(
              _("<p>The description of attribute \"%1\":<br></p>"),
              attr
            )
          ),
          Builtins.sformat("<p><i>%1</i></p>", desc)
        )
      end

      org_value = deep_copy(value)
      value_size = Builtins.size(value)

      # horizontal size of popup for
      hsize = Ops.add(Builtins.size(Ops.get(value, 0, "")), 10)

      # Helper for creating items for EditAttribute Popup
      generate_value_list = lambda do
        ret = VBox()
        if single
          ret = Builtins.add(
            ret,
            InputField(
              Id(0),
              Opt(:hstretch),
              # textentry label
              Builtins.sformat(_("&Value of \"%1\" Attribute"), attr),
              Ops.get(value, 0, "")
            )
          )
        else
          ret = Builtins.add(
            ret,
            InputField(
              Id(0),
              Opt(:hstretch),
              # textentry label
              Builtins.sformat(_("&Values of \"%1\" Attribute"), attr),
              Ops.get(value, 0, "")
            )
          )
          i = 1
          while Ops.less_than(i, value_size)
            ret = Builtins.add(
              ret,
              InputField(Id(i), Opt(:hstretch), "", Ops.get(value, i, ""))
            )
            if Ops.greater_than(
                Builtins.size(Ops.add(Ops.get(value, i, ""), 10)),
                hsize
              )
              hsize = Ops.add(Builtins.size(Ops.get(value, i, "")), 10)
            end
            i = Ops.add(i, 1)
          end
        end
        deep_copy(ret)
      end

      values = generate_value_list.call
      # button label
      add_button = PushButton(Id(:new), Opt(:key_F3), _("&Add Value"))

      if Ops.greater_than(Builtins.size(offer), 0) || browse
        # menubutton item (default value)
        mb = [Item(Id(:new), _("&Empty Entry"))]
        mb = Builtins.add(mb, Item(Id(:browse), _("Bro&wse"))) if browse
        Builtins.foreach(
          Convert.convert(offer, :from => "list", :to => "list <string>")
        ) { |it| mb = Builtins.add(mb, Item(Id(it), it)) }
        # button label
        add_button = MenuButton(Id(:mb), Opt(:key_F3), _("&Add Value"), mb)
      end

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(1),
          VBox(
            HSpacing(Ops.greater_than(hsize, 50) ? hsize : 50),
            ReplacePoint(Id(:rp), values),
            single ?
              ButtonBox(
                PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
                PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
                PushButton(Id(:help), Opt(:key_F2), Label.HelpButton)
              ) :
              ButtonBox(
                PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
                PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
                PushButton(Id(:help), Opt(:key_F2), Label.HelpButton),
                add_button
              )
          ),
          HSpacing(1)
        )
      )
      result = nil
      new_value = []

      value_size = 1 if value_size == 0
      UI.SetFocus(Id(Ops.subtract(value_size, 1)))
      while true
        result = UI.UserInput
        if result == :cancel
          new_value = deep_copy(org_value)
          break
        end
        Wizard.ShowHelp(help_text) if result == :help
        if result == :new || Builtins.contains(offer, result) ||
            result == :browse
          j = 0
          value = []
          while Ops.less_than(j, value_size)
            value = Builtins.add(
              value,
              Convert.to_string(UI.QueryWidget(Id(j), :Value))
            )
            j = Ops.add(j, 1)
          end
          if Builtins.contains(offer, result) &&
              Ops.get(value, Ops.subtract(value_size, 1), "") == ""
            # relace last empty entry
            Ops.set(
              value,
              Ops.subtract(value_size, 1),
              Convert.to_string(result)
            )
          elsif result == :browse
            Ops.set(value, Ops.subtract(value_size, 1), BrowseTree(""))
          else
            # add new entry
            value = Builtins.add(
              value,
              result == :new ? "" : Convert.to_string(result)
            )
            value_size = Ops.add(value_size, 1)
          end
          UI.ReplaceWidget(Id(:rp), generate_value_list.call)
          UI.SetFocus(Id(Ops.subtract(value_size, 1)))
        end
        if result == :ok
          j = 0
          duplicate = false
          new_value = []
          while Ops.less_than(j, value_size) && !duplicate
            v = Convert.to_string(UI.QueryWidget(Id(j), :Value))
            if !Builtins.contains(org_value, v) &&
                Builtins.contains(conflicts, v)
              #error popup
              Popup.Error(
                Builtins.sformat(
                  _(
                    "The value '%1' already exists.\nPlease select another one."
                  ),
                  v
                )
              )
              duplicate = true
            end
            new_value = Builtins.add(new_value, v) if v != ""
            j = Ops.add(j, 1)
          end
          next if duplicate
          break
        end
      end
      UI.CloseDialog
      deep_copy(new_value)
    end

    # Popup for adding new configuration module
    # @param [Array] conflicts list of forbidden names ('cn' values)
    # @param [Array] available list of possible object classes for new module
    # @return [Hash] of new module (contains its name and object class)
    def NewModule(available, conflicts)
      available = deep_copy(available)
      conflicts = deep_copy(conflicts)
      descriptions = {
        # description of configuration object
        "suseuserconfiguration"  => _(
          "Configuration of user management tools"
        ),
        # description of configuration object
        "susegroupconfiguration" => _(
          "Configuration of group management tools"
        )
      }
      # label
      r_buttons = VBox(Left(Label(_("Object Class of New Module"))))
      Builtins.foreach(
        Convert.convert(available, :from => "list", :to => "list <string>")
      ) do |class2|
        desc = class2
        if Ops.get_string(descriptions, class2, "") != ""
          desc = Builtins.sformat(
            "%1 (%2)",
            class2,
            Ops.get_string(descriptions, class2, "")
          )
        end
        r_buttons = Builtins.add(
          r_buttons,
          Left(RadioButton(Id(class2), desc, true))
        )
      end
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(1),
          VBox(
            HSpacing(50),
            RadioButtonGroup(Id(:rb), r_buttons),
            InputField(
              Id(:cn),
              Opt(:hstretch),
              # textentry label, do not translate "cn"
              _("&Name of New Module (\"cn\" Value)")
            ),
            ButtonBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton)
            )
          ),
          HSpacing(1)
        )
      )
      result = nil
      new_value = ""
      _class = ""

      UI.SetFocus(Id(:cn))
      while true
        result = UI.UserInput
        if result == :cancel
          new_value = ""
          break
        end
        if result == :ok
          new_value = Convert.to_string(UI.QueryWidget(Id(:cn), :Value))
          if Builtins.contains(conflicts, new_value)
            #error popup
            Popup.Error(
              _("The entered value already exists.\nSelect another one.\n")
            )
            next
          end
          if new_value == ""
            #error popup
            Popup.Error(_("Enter the module name."))
            next
          end
          _class = Convert.to_string(UI.QueryWidget(Id(:rb), :CurrentButton))
          break
        end
      end
      UI.CloseDialog
      { "class" => _class, "cn" => new_value }
    end

    # Popup for adding new default value (default value is template's attribute)
    # @param [Array] conflicts list of attributes already set
    # @param [Array] available list of possible attributes
    # @return [Hash] of new "default value" (contains attribute name and value)
    def AddDefaultValue(available, conflicts)
      available = deep_copy(available)
      conflicts = deep_copy(conflicts)
      # help text 1/3
      help_text = _(
        "<p>Here, set the values of attributes belonging\n" +
          "to an object using the current template. Such values are used as defaults when\n" +
          "the new object is created.</p>\n"
      ) +
        # // help text 2/3 do not translate "defaultObjectClass"
        # _("<p>The list of attributes provided in <b>Attribute Name</b> is the
        # list of allowed attributes for objects described in the \"defaultObjectClass\"
        # entry of the current template.</p>
        # ") +

        # help text 3/3 do not translate "homedirectory"
        _(
          "<p>You can use special syntax to create attribute\n" +
            "values from existing ones. The expression <i>%attr_name</i> will be replaced\n" +
            "with the value of attribute \"attr_name\" (for example, use \"/home/%uid\"\n" +
            "as a value of \"homeDirectory\").</p>\n"
        )

      available = Builtins.filter(
        Convert.convert(available, :from => "list", :to => "list <string>")
      ) { |attr2| !Builtins.contains(conflicts, attr2) }

      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          HSpacing(1),
          VBox(
            HSpacing(50),
            VSpacing(0.5),
            # combobox label
            Left(
              ComboBox(
                Id(:attr),
                Opt(:editable),
                _("Attribute &Name"),
                available
              )
            ),
            VSpacing(0.5),
            # textentry label
            InputField(Id(:val), Opt(:hstretch), _("Attribute &Value")),
            VSpacing(0.5),
            ButtonBox(
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton),
              PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
              PushButton(Id(:help), Opt(:key_F2), Label.HelpButton)
            ),
            VSpacing(0.5)
          ),
          HSpacing(1)
        )
      )
      result = nil
      new_value = ""
      attr = ""

      UI.SetFocus(Id(:attr))
      while true
        result = UI.UserInput
        if result == :cancel
          new_value = ""
          break
        end
        Wizard.ShowHelp(help_text) if result == :help
        if result == :ok
          attr = Convert.to_string(UI.QueryWidget(Id(:attr), :Value))
          new_value = Convert.to_string(UI.QueryWidget(Id(:val), :Value))
          break
        end
      end
      UI.CloseDialog
      { "attr" => attr, "value" => new_value }
    end

    publish :function => :BrowseTree, :type => "string (string)"
    publish :function => :InitAndBrowseTree, :type => "string (string, map)"
    publish :function => :EditAttribute, :type => "list <string> (map)"
    publish :function => :NewModule, :type => "map (list, list)"
    publish :function => :AddDefaultValue, :type => "map (list, list)"
  end

  LdapPopup = LdapPopupClass.new
  LdapPopup.main
end
