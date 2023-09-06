# Copyright (c) 2023 SUSE LINUX GmbH, Nuernberg, Germany.
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE LINUX GmbH.

# Authors:      William Brown <wbrown@suse.de>

require 'yast'
require 'ui/dialog'
require 'authserver/dir/ds389'
require 'authserver/dir/client'
Yast.import 'UI'
Yast.import 'Icon'
Yast.import 'Label'
Yast.import 'Popup'

class Deprecation < UI::Dialog
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

  def dialog_content
    VBox(
        Left(Heading(_('This tool is deprecated.'))),
        Left(Heading(_('You should use dscreate directly.'))),
        HBox(
            PushButton(Id(:ok), Label.OKButton),
        ),
        ReplacePoint(Id(:busy), Empty()),
    )
  end

  def ok_handler
    finish_dialog(:next)
  end
end
