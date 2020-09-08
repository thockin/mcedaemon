# Copyright 2018 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Don't build debuginfo packages.
%define debug_package %{nil}
%define version 2.0.5

Name: mcedaemon
Epoch:   1
Version: %{version}
Release: g1%{?dist}
Summary: mced in particular watches for machine check exceptions from the system.
License: GPL2
Url: https://github.com/thockin/mcedaemon
Source0: mcedaemon-%{version}.tar.gz

BuildArch: %{_arch}

%description
mced is a very small daemon which monitors /dev/mcelog for machine check events, and then reports them to other applications.
%prep
%autosetup

%build
make

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
