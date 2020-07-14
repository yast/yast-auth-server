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
require 'authserver/krb/mit'

describe MITKerberos do
  it 'gen_common_conf' do
    match = '[libdefaults]
        # "dns_canonicalize_hostname" and "rdns" are better set to false for improved security.
        # If set to true, the canonicalization mechanism performed by Kerberos client may
        # allow service impersonification, the consequence is similar to conducting TLS certificate
        # verification without checking host name.
        # If left unspecified, the two parameters will have default value true, which is less secure.
        dns_canonicalize_hostname = false
        rdns = false
        default_realm = EXAMPLE.COM

[realms]
        EXAMPLE.COM = {
                kdc = krb.example.com
                admin_server = krb.example.com
        }

[domain_realm]
        .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM

[logging]
    kdc = FILE:/var/log/krb5/krb5kdc.log
    admin_server = FILE:/var/log/krb5/kadmind.log
    default = SYSLOG:NOTICE:DAEMON
'
    expect(MITKerberos.gen_common_conf('EXAMPLE.COM', 'krb.example.com')).to eq(match)
  end

  it 'gen_kdc_comf' do
    match = '[kdcdefaults]
        kdc_ports = 750,88

[realms]
        EXAMPLE.COM = {
                database_module = contact_ldap
        }

[dbdefaults]

[dbmodules]
        contact_ldap = {
                db_library = kldap
                ldap_kdc_dn = "cn=kdc"
                ldap_kadmind_dn = "cn=adm"
                ldap_kerberos_container_dn = "cn=container"
                ldap_service_password_file = /pass
                ldap_servers = ldaps://dir.example.net
        }

[logging]
        kdc = FILE:/var/log/krb5/krb5kdc.log
        admin_server = FILE:/var/log/krb5/kadmind.log
'
    expect(MITKerberos.gen_kdc_conf('EXAMPLE.COM', 'cn=kdc', 'cn=adm', 'cn=container', '/pass', 'dir.example.net')).to eq(match)
  end

  shared_context "kdb5_ldap_util mock" do
    before do
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with("/usr/lib/mit/sbin/kdb5_ldap_util").and_return(old_path)
      allow(File).to receive(:exist?).with("/usr/sbin/kdb5_ldap_util").and_return(!old_path)

      allow(File).to receive(:chmod)

      allow(Open3).to receive(:popen2e).and_return([stdin, stdouterr, waiter])
    end

    let(:stdin) { instance_double(IO, puts: true, close: true) }

    let(:stdouterr) { instance_double(IO, readlines: outerr) }

    let(:waiter) { instance_double(Process::Waiter, value: status) }

    let(:status) { instance_double(Process::Status, exitstatus: exitstatus) }

    let(:outerr) { [] }

    let(:exitstatus) { 0 }

    let(:old_path) { false }
  end

  shared_examples "kdb5_ldap_util" do |method, *args|
    context "when the kdb5_ldap_util is found in /usr/sbin" do
      let(:old_path) { false }

      it "calls kdb5_ldap_util from /usr/sbin" do
        expect(Open3).to receive(:popen2e).with("/usr/sbin/kdb5_ldap_util", any_args)

        MITKerberos.send(method, *args)
      end
    end

    context "when the kdb5_ldap_util is not found in /usr/sbin" do
      let(:old_path) { true }

      it "calls kdb5_ldap_util from /usr/lib/mit/sbin" do
        expect(Open3).to receive(:popen2e).with("/usr/lib/mit/sbin/kdb5_ldap_util", any_args)

        MITKerberos.send(method, *args)
      end
    end

    context "on success" do
      let(:outerr) { ["message1", "error1"] }

      let(:exitstatus) { 0 }

      it "returns stdouterr and true" do
        result = MITKerberos.send(method, *args)

        expect(result).to eq(["message1\\nerror1", true])
      end
    end

    context "on failure" do
      let(:outerr) { ["message1", "error1"] }

      let(:exitstatus) { 1 }

      it "returns stdouterr and false" do
        result = MITKerberos.send(method, *args)

        expect(result).to eq(["message1\\nerror1", false])
      end
    end
  end

  describe ".save_password_into_file" do
    include_context "kdb5_ldap_util mock"

    it "calls kdb5_ldap_util with correct arguments" do
      expect(Open3).to receive(:popen2e)
        .with(/kdb5_ldap_util/, "stashsrvpw", "-f", "path/to/file", "-w", "pass", "example")

      MITKerberos.save_password_into_file("example", "pass", "path/to/file")
    end

    include_examples "kdb5_ldap_util", :save_password_into_file, "example", "pass", "path/to/file"
  end

  describe ".init_dir" do
    include_context "kdb5_ldap_util mock"

    it "calls kdb5_ldap_util with correct arguments" do
      expect(Open3).to receive(:popen2e)
        .with(/kdb5_ldap_util/,
          "-H", "ldaps://addr",
          "-D", "dn",
          "-w", "a_pass",
          "create", "-r", "name",
          "-subtrees", "c_dn",
          "-s", "-P", "m_pass")

      MITKerberos.init_dir("addr", "dn", "a_pass", "name", "c_dn", "m_pass")
    end

    include_examples "kdb5_ldap_util", :init_dir, "addr", "dn", "a_pass", "name", "c_dn", "m_pass"
  end
end
