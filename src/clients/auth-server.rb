# encoding: utf-8

# File:	clients/auth-server.rb
# Package:	Configuration of ldap-server
# Summary:	Main file
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
#
# Main file for auth-server configuration. Uses all other files.
module Yast
  class AuthServerClient < Client
    def main
      Yast.import "UI"

      #**
      # <h3>Configuration of ldap-server</h3>

      textdomain "auth-server"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("AuthServer module started")

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"
      Yast.import "RichText"
      Yast.import "CommandLine"
      Yast.include self, "auth-server/wizards.rb"



      @cmdline_description = {
        "id"         => "auth-server",
        # Command line help text for the Xldap-server module
        "help"       => _(
          "Configuration of Authentication server"
        ),
        "guihandler" => fun_ref(method(:LdapServerSequence), "any ()"),
        "initialize" => fun_ref(AuthServer.method(:Read), "boolean ()"),
        "finish"     => fun_ref(AuthServer.method(:Write), "boolean ()"),
        "actions"    => {
          "service"         => {
            "handler" => fun_ref(
              method(:serviceHandler),
              "boolean (map <string, string>)"
            ),
            "help"    => _("Enable/Disable the service")
          },
          "addDatabase"     => {
            "handler" => fun_ref(method(:addDatabaseHandler), "boolean (map)"),
            "help"    => _("Add a new database")
          },
          "getDatabaseList" => {
            "handler" => fun_ref(
              method(:getDatabaseListHandler),
              "boolean (map)"
            ),
            "help"    => _("Show a list of currently available databases")
          },
          "getSchemaList"   => {
            "handler" => fun_ref(method(:getSchemaListHandler), "boolean (map)"),
            "help"    => _("Show a list of currently configured schemas")
          },
          "addSchema"       => {
            "handler" => fun_ref(method(:addSchemaHandler), "boolean (map)"),
            "help"    => _("Add a schema to the list")
          }
        },
        "options"    => {
          "enable"   => { "help" => _("Enable the service") },
          "disable"  => { "help" => _("Disable the service") },
          "type"     => {
            "help" => _("Database type (\"hdb\" or \"bdb\")"),
            "type" => "string"
          },
          "basedn"   => {
            "help" => _("Base DN for the database"),
            "type" => "string"
          },
          "rootdn"   => {
            "help" => _("DN for the administrator login"),
            "type" => "string"
          },
          "password" => {
            "help" => _("Administrator password"),
            "type" => "string"
          },
          "enctype"  => {
            "help" => "SSHA, SHA, SMD5, CRYPT, PLAIN",
            "type" => "string"
          },
          "dbdir"    => {
            "help" => _("Directory for the database"),
            "type" => "string"
          },
          "file"     => { "help" => _("File"), "type" => "string" },
          "pos"      => { "help" => _("Position"), "type" => "string" }
        },
        "mappings"   => {
          "service"         => ["enable", "disable"],
          "addDatabase"     => [
            "basedn",
            "rootdn",
            "password",
            "enctype",
            "dbdir",
            "type"
          ],
          "getDatabaseList" => [],
          "getSchemaList"   => [],
          "addSchema"       => ["file"]
        }
      }

      # is this proposal or not?
      @propose = false
      @args = WFM.Args
      if Ops.greater_than(Builtins.size(@args), 0)
        if Ops.is_path?(WFM.Args(0)) && WFM.Args(0) == path(".propose")
          Builtins.y2milestone("Using PROPOSE mode")
          @propose = true
        end
      end

      # main ui function
      @ret = nil

      if @propose
        @ret = InstProposalSequence()
      else
        @ret = CommandLine.Run(@cmdline_description)
      end
      Builtins.y2debug("ret=%1", @ret)

      # Finish
      Builtins.y2milestone("AuthServer module finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret) 

      # EOF
    end

    def serviceHandler(options)
      options = deep_copy(options)
      command = CommandLine.UniqueOption(options, ["enable", "disable"])
      return false if command == nil

      AuthServer.WriteServiceEnabled(command == "enable")

      true
    end

    def getDatabaseListHandler(options)
      options = deep_copy(options)
      dbList = AuthServer.ReadDatabaseList

      s = ""
      Builtins.foreach(dbList) do |db|
        s = Ops.add(
          Ops.add(
            Ops.add(
              Ops.add(Ops.add(s, Ops.get(db, "suffix", "")), " ("),
              Ops.get(db, "type", "")
            ),
            ") "
          ),
          "<br>"
        )
      end 


      CommandLine.Print(RichText.Rich2Plain(Ops.add("<br>", s)))

      false
    end

    def addDatabaseHandler(options)
      options = deep_copy(options)
      ret = false
      db = {}

      #    map<string, any> edb = LdapServer::ReadDatabase();
      #    y2milestone("DBs: %1", edb);
      #
      #
      if Ops.get(options, "basedn") != nil
        Ops.set(db, "suffix", Ops.get_string(options, "basedn", ""))
      else
        CommandLine.Print(_("No base DN provided\n"))
        return false
      end
      Ops.set(db, "type", Ops.get_string(options, "type", "hdb"))
      if Ops.get(options, "rootdn") != nil
        Ops.set(db, "rootdn", Ops.get_string(options, "rootdn", ""))
      end
      if Ops.get(options, "password") != nil
        Ops.set(db, "rootpw_clear", Ops.get_string(options, "password", ""))
      end
      Ops.set(db, "pwenctype", Ops.get_string(options, "enctype", "SSHA"))
      if Ops.get(options, "dbdir") != nil
        Ops.set(db, "directory", Ops.get_string(options, "dbdir", ""))
      end

      if AuthServer.ReadServiceEnabled == false
        Report.Error(
          _("Database cannot be created when the service is not enabled")
        )
        return false
      end

      #    y2milestone("db-options : %1", db);
      #
      ret = AuthServer.AddDatabase(0, db, true, true)

      if !ret
        CommandLine.Print(_("Error while adding the database"))
        err = AuthServer.ReadError
        Report.Error(
          Ops.add(
            Ops.add(Ops.get(err, "msg", ""), "<br>"),
            Ops.get(err, "details", "")
          )
        )
        return false
      end
      true
    end

    def getSchemaListHandler(options)
      options = deep_copy(options)
      s = ""
      i = 0
      Builtins.foreach(AuthServer.ReadSchemaList) do |v|
        if v != "schema" # skip the baseentry (hardcoded schema)
          s = Ops.add(Ops.add(Ops.add(s, " "), v), "<br>")
        end
      end

      CommandLine.Print(RichText.Rich2Plain(Ops.add("<br>", s)))
      false # do not call Write...
    end

    def addSchemaHandler(options)
      options = deep_copy(options)
      if Ops.get_string(options, "file", "") != ""
        file = Ops.get_string(options, "file", "")
        if Builtins.regexpmatch(file, ".*.schema$")
          if !AuthServer.AddSchemaToSchemaList(file)
            err = AuthServer.ReadError
            Report.Error(
              Ops.add(
                Ops.add(Ops.get(err, "msg", ""), "<br>"),
                Ops.get(err, "details", "")
              )
            )
            return false
          end
        elsif !AuthServer.AddLdifToSchemaList(file)
          err = AuthServer.ReadError
          Report.Error(
            Ops.add(
              Ops.add(Ops.get(err, "msg", ""), "<br>"),
              Ops.get(err, "details", "")
            )
          )
          return false
        end
        return true
      end
      false
    end
  end
end

Yast::AuthServerClient.new.main
