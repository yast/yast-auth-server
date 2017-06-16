FROM yastdevel/cpp:sle12-sp3
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  cyrus-sasl-devel \
  libldapcpp-devel \
  perl-Digest-SHA1 \
  perl-X500-DN \
  perl-gettext \
  yast2 \
  yast2-ldap \
  yast2-users
COPY . /usr/src/app

