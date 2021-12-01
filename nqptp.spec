Name:           nqptp
Version:        1.1
Release:        1%{?dist}
Summary:        Not-Quite PTP (Precision Time Protocol)
# MIT licensed except for tinysvcmdns under BSD, 
# FFTConvolver/ under GPLv3+ and audio_sndio.c 
# under ISC
License:        MIT and BSD and GPLv3+ and ISC
URL:            https://github.com/mikebrady/nqptp
Source0:        https://github.com/mikebrady/%{name}/archive/%{version}/%{name}-%{version}.tar.gz

%{?systemd_requires}
BuildRequires:  systemd
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  git
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  gcc-c++

%description
nqptp is a daemon that monitors timing data from any PTP
(Precision_Time_Protocol) clocks – up to 32 peers – it sees on ports
319 and 320. It maintains records for each clock, identified by Clock
ID and IP.

%prep
%setup -n nqptp

%build
autoreconf -i -f
%configure
%make_build

%install
%make_install

mkdir -p %{buildroot}/%{_unitdir}
mv %{buildroot}/lib/systemd/system/%{name}.service %{buildroot}/%{_unitdir}

%pre

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
/usr/bin/nqptp
%{_unitdir}/%{name}.service
%doc README.md RELEASE_NOTES.md
%license LICENSE

%changelog
* Wed Dec 01 2021 Derek Atkins <derek@ihtfp.com> 1.1-1
- Initial spec file
