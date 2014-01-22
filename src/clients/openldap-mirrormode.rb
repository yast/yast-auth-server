# encoding: utf-8

# File:	clients/openldap-mirror-mode.ycp
# Package:	Configuration of OpenLDAP MirrorMode replication
# Summary:	Main file
# Authors:	Ralf Haferkamp <rhafer@suse.de>
#
# $Id$
#
module Yast
  class OpenldapMirrormodeClient < Client
    def main
      Yast.import "UI"

      #**
      # <h3>Configuration of OpenLDAP MirrorMode</h3>

      textdomain "auth-server"

      Yast.import "AuthServer"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("OpenLDAP MirrorMode module started")

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"
      Yast.import "RichText"
      Yast.import "CommandLine"
      Yast.include self, "auth-server/mirrormode-wizard.rb"

      @cmdline_description = {
        "id"         => "openldap-mirrormode",
        # Command line help text for the Xldap-server module
        "help"       => _(
          "Configuration of OpenLDAP MirrorMode replication"
        ),
        "guihandler" => fun_ref(method(:MirrorModeSequence), "any ()"),
        "initialize" => fun_ref(AuthServer.method(:Read), "boolean ()"),
        "finish"     => fun_ref(AuthServer.method(:Write), "boolean ()")
      }

      # main ui function
      @ret = CommandLine.Run(@cmdline_description)
      Builtins.y2debug("ret=%1", @ret)

      # Finish
      Builtins.y2milestone("OpenLDAP MirrorMode module finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret) 

      # EOF
    end
  end
end

Yast::OpenldapMirrormodeClient.new.main
