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
zypper install -C "rubygem(ruby:$ruby_version:rspec)"
zypper install git yast2-devtools yast2-testsuite yast
```

You can then run the auth-server module with:

```
rake run
rake run[module name]
rake run[ldap-server]
```

For the 389-ds setup, you'll require a CA + pkcs12 bundle with a cert to use. You can generate
these with certutil from the package mozilla-nss-tools.

```
mkdir local_ca
cd local_ca
echo "password" > password.txt
certutil -N -f password.txt -d .
certutil -S -n CAissuer -t "C,C,C" -x -f password.txt -d . -v 24 -g 4096 -Z SHA256 --keyUsage certSigning -2 --nsCertType sslCA -s "CN=ca.nss.dev.example.com,O=Testing,L=example,ST=Queensland,C=AU"

certutil -S -n Server-Cert -t ",," -c CAissuer -f password.txt -d . -s "CN=test_b.dev.example.com,O=Testing,L=example,ST=Queensland,C=AU"

certutil -L -n CAissuer -a -d . > ca.pem
pk12util -o server-export.p12 -d . -k password.txt -n Server-Cert

/home/admin/local_ca/
```

# Tests

```
rake test:unit
```

# Logs

They can be found in:

```
~/.y2log
/var/log/YaST2/y2log
```

For example logging you can execute YaST with debugging environment variables.

```
Y2DEBUG=1 rake run[ldap-server]
```




