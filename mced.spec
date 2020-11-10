# Copyright 2020 Google Inc. All Rights Reserved.

#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Don't build debuginfo packages.
%define debug_package %{nil}

Name: mcedaemon
Epoch:   1
Version: %{version}
Release: %{revision}%{?dist}
Summary: mced watches the system for machine check exceptions.
License: GPL2
Url: https://github.com/thockin/mcedaemon
Source0: mcedaemon-%{version}.tar.gz

BuildArch: %{_arch}

%description
mced is a very small daemon which monitors /dev/mcelog for machine check events, and then reports them to other applications.
%prep
%autosetup

%build
make STATIC=1

%install
install -d %{buildroot}%{_bindir}
install -m 0755 mced %{buildroot}%{_bindir}
install -m 0755 mce_listen %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/systemd/system
install -m 0644 mced.service %{buildroot}%{_sysconfdir}/systemd/system
install -d %{buildroot}%{_sysconfdir}/mced
install -m 0644 examples/mce_decode.conf %{buildroot}%{_sysconfdir}/mced
install -m 0644 examples/mcelog.conf %{buildroot}%{_sysconfdir}/mced

%files
%{_bindir}/mced
%{_bindir}/mce_listen
%{_sysconfdir}/systemd/system/mced.service
%{_sysconfdir}/mced/mce_decode.conf
%{_sysconfdir}/mced/mcelog.conf

%post
if [ $1 -eq 1 ]; then
  # Initial installation
  systemctl enable mced.service >/dev/null 2>&1 || :

  if [ -d /run/systemd/system ]; then
    systemctl start mced.service >/dev/null 2>&1 || :
  fi
else
  # Package upgrade
  if [ -d /run/systemd/system ]; then
    systemctl try-restart mced.service >/dev/null 2>&1 || :
  fi
fi

%preun
if [ $1 -eq 0 ]; then
  # Package removal, not upgrade
  systemctl --no-reload disable mced.service >/dev/null 2>&1 || :
  if [ -d /run/systemd/system ]; then
    systemctl stop mced.service >/dev/null 2>&1 || :
  fi
fi
