[![Travis Build](https://travis-ci.org/yast/yast-auth-server.svg?branch=master)](https://travis-ci.org/yast/yast-auth-server)
# yast2-auth-server
The program assists system administrators to create new directory server and
Kerberos server instances that help to maintain centralised user identity
database for a network.

The features are:
  * Create new directory server instance.
  * Create new Kerberos server instance.
  * Integrate Kerberos server with directory server.

## Install
To install the latest stable version on openSUSE or SLE, use zypper:

    $ sudo zypper install yast2-auth-server

# Run
Visit Yast control panel and launch "Create New Kerberos Server" or "Create New Directory Server".

# Development

You need to prepare your environment with:

```
ruby_version=$(ruby -e "puts RbConfig::CONFIG['ruby_version']")
zypper install -C "rubygem(ruby:$ruby_version:yast-rake)"
zypper install git yast2-devtools yast2-testsuite
```

You can then run the auth-server module with:

```
rake run
```

