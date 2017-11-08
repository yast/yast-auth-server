#!/usr/bin/env rspec
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE LINUX GmbH.

# Authors:      Howard Guo <hguo@suse.com>

ENV['Y2DIR'] = File.expand_path('../../src', __FILE__)

require 'yast'
require 'yast/rspec'
require 'pp'
require 'authserver/dir/ds389'

describe DS389 do
  it 'gen_setup_ini' do
    match = '[General]
FullMachineName=dir.example.com
SuiteSpotUserID=dirsrv
SuiteSpotGroup=dirsrv

[slapd]
ServerPort=389
ServerIdentifier=ExampleDotCom
Suffix=dc=example,dc=com
RootDN=cn=admin
RootDNPwd=pass
AddSampleEntries=No
'
    expect(DS389.gen_setup_ini('dir.example.com', 'ExampleDotCom', 'dc=example,dc=com', 'cn=admin', 'pass')).to eq(match)
  end
end