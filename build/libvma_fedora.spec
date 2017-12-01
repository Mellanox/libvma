Name: libvma
Version: 8.0.1
Release: 1%{?dist}
Summary: A library for boosting TCP and UDP traffic (over RDMA hardware)

License: GPLv2 or BSD
Url: https://github.com/Mellanox/libvma
Source: http://www.mellanox.com/downloads/Accelerator/%{name}-%{version}.tar.gz
#arm is excluded since libvma fails to compile on arm. 
#Reason: libvma uses assembly commands that are not supported by arm.
ExcludeArch: %{arm} 
Requires: pam
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: librdmacm-devel libibverbs-devel libnl3-devel
BuildRequires: automake autoconf libtool

%global use_systemd %(if ( test -d "%{_unitdir}" > /dev/null); then echo -n '1'; else echo -n '0'; fi)

%description
libvma is a LD_PRELOAD-able library that boosts performance
of TCP and UDP traffic.
It allows application written over standard socket API to handle 
fast path data traffic from user space over Ethernet and/or 
Infiniband with full network stack bypass and get better throughput, 
latency and packets/sec rate.
No application binary change is required for that.
libvma is supported by RDMA capable devices that support
"verbs" IBV_QPT_RAW_PACKET QP for Ethernet and/or IBV_QPT_UD QP for IPoIB.

%package devel
Summary: Header files required to develop with libvma 
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers files required to develop with the libvma library.

%package utils
Summary: Libvma utilities
Requires: %{name}%{?_isa} = %{version}-%{release}

%description utils
Tools for collecting and analyzing libvma statistic.

%prep
%setup -q

%build
./autogen.sh
%configure 
make %{?_smp_mflags} V=1

%install
%make_install
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%{_libdir}/%{name}*.so.*
#libvma.so in needed in the main package so that 
#'LD_PRELOAD=libvma.so <command>' works.
%{_libdir}/%{name}.so
%license COPYING LICENSE
%doc README.txt journal.txt VMA_VERSION
%config(noreplace) %{_sysconfdir}/libvma.conf
%config(noreplace) %{_sysconfdir}/security/limits.d/30-libvma-limits.conf
%{_sbindir}/vmad
%config(noreplace) %{_sysconfdir}/init.d/vma
%if "%{use_systemd}" == "1"
%config(noreplace) %{_sysconfdir}/systemd/system/vma.service
%endif

%files devel
%{_includedir}/*

%files utils
%{_bindir}/vma_stats

%changelog
* Thu Dec 03 2016 Alex Vainman <igor.ivanov.va@gmail.com>
- Add daemon

* Thu Mar 13 2016 Alex Vainman <alexv@mellanox.com> - 8.0.1-1
- New upstream release
- Move to dual license: GPLv2 or BSD
- ExcludeArch update
- Removal of extra space in:
  config(noreplace) {_sysconfdir}/security/limits.d/30-libvma-limits.conf
- Add V=1 to make

* Wed Mar  2 2016 Alex Vainman <alexv@mellanox.com> - 7.0.14-2
- Added reasoning for archs exclusion
- Package description improvement
- Removal of the pre scriplet
- Added COPYING and LICENSE files to the package

* Sun Feb 21 2016 Alex Vainman <alexv@mellanox.com> - 7.0.14-1
- New upstream release
- Removal of redundant macros and obsolete/unneeded tags
- Added ExcludeArch, BuildRequires and Require sections
- Fixes and cleanups in the build and installation sections
- Install 30-libvma-limits.conf file under 
  /etc/security/limits.d/
- Fixes related to files/directories ownerships
- Removal of vma_perf_envelope.sh from the utility package
- Update Source tag URL
- Fix most of the rpmlint warnings

* Mon Jan  4 2016 Avner BenHanoch <avnerb@mellanox.com> - 7.0.12-1
- Initial Packaging
