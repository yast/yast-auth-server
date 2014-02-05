# encoding: utf-8

# File:	clients/ldap-server_auto.ycp
# Package:	Configuration of ldap-server
# Summary:	Client for autoinstallation
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
#
# This is a client for autoinstallation. It takes its arguments,
# goes through the configuration and return the setting.
# Does not do any changes to the configuration.

# @param function to execute
# @param map/list of ldap-server settings
# @return [Hash] edited settings, Summary or boolean on success depending on called function
# @example map mm = $[ "FAIL_DELAY" : "77" ];
# @example map ret = WFM::CallFunction ("ldap-server_auto", [ "Summary", mm ]);
module Yast
  class AuthServerAutoClient < Client
    def main
      Yast.import "UI"

      textdomain "auth-server"

      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("AuthServer auto started")

      Yast.import "AuthServer"
      Yast.include self, "auth-server/wizards.rb"

      @ret = nil
      @func = ""
      @param = {}

      # Check arguments
      if Ops.greater_than(Builtins.size(WFM.Args), 0) &&
          Ops.is_string?(WFM.Args(0))
        @func = Convert.to_string(WFM.Args(0))
        if Ops.greater_than(Builtins.size(WFM.Args), 1) &&
            Ops.is_map?(WFM.Args(1))
          @param = Convert.to_map(WFM.Args(1))
        end
      end
      Builtins.y2milestone("func=%1", @func)
      Builtins.y2debug("param=%1", @param)

      # Create a summary
      if @func == "Summary"
        @ret = AuthServer.Summary
      # Reset configuration
      elsif @func == "Reset"
        AuthServer.Import({})
        @ret = {}
      # Change configuration (run AutoSequence)
      elsif @func == "Change"
        @ret = LdapServerAutoSequence()
        AuthServer.ReadFromDefaults
      # Import configuration
      elsif @func == "Import"
        @ret = AuthServer.Import(@param)
      # Return actual state
      elsif @func == "Export"
        @ret = AuthServer.Export
      # Return needed packages
      elsif @func == "Packages"
        @ret = AuthServer.AutoPackages
      # Read current state
      elsif @func == "Read"
        Yast.import "Progress"
        Progress.off
        @ret = AuthServer.Read
        Progress.on
      # Write givven settings
      elsif @func == "Write"
        Yast.import "Progress"
        Progress.off
        # LdapServer::write_only = true;
        @ret = AuthServer.Write
        Progress.on
      # Return if configuration  was changed
      # return boolean
      elsif @func == "GetModified"
        @ret = !AuthServer.UseDefaults
      # Set modified flag
      # return boolean
      elsif @func == "SetModified"
        #LdapServer::SetModified (true);
        @ret = true
      else
        Builtins.y2error("Unknown function: %1", @func)
        @ret = false
      end

      Builtins.y2debug("ret=%1", @ret)
      Builtins.y2milestone("AuthServer auto finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret) 

      # EOF
    end
  end
end

Yast::AuthServerAutoClient.new.main
