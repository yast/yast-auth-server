yast2-auth-server
=================

[![Travis Build](https://travis-ci.org/yast/yast-auth-server.svg?branch=master)](https://travis-ci.org/yast/yast-auth-server)
[![Jenkins Build](http://img.shields.io/jenkins/s/https/ci.opensuse.org/yast-auth-server-master.svg)](https://ci.opensuse.org/view/Yast/job/yast-auth-server-master/)


With this YaST2 module you can configure LDAP and Kerberos authentication services

Installation
------------

To install the latest stable version on openSUSE or SLE, use zypper:

    $ sudo zypper install yast2-auth-server

Running
-------

To run the module, use the following command:

    $ sudo /usr/sbin/yast2 auth-server

This will run the module in text mode. For more options, including running in
your desktop environment, see section on [running YaST](https://en.opensuse.org/SDB:Starting_YaST) in the YaST documentation.

