Name: libvma
Version: 7.0.14
Release: 1%{?dist}
Summary: A library for boosting TCP and UDP traffic (over RDMA hardware)

License: GPLv2
Url: https://github.com/Mellanox/libvma
Source: http://www.mellanox.com/downloads/Accelerator/%{name}-%{version}.tar.gz
ExcludeArch: %{arm} %{ix86} s390x ppc64 ppc64le 
Requires: pam
Requires(pre): grep coreutils
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: librdmacm-devel libibverbs-devel libnl3-devel
BuildRequires: automake autoconf libtool

%description
libvma is a LD_PRELOAD-able library that boosts performance
of TCP and UDP traffic
Part of Mellanox's enhanced services
Allows application written over standard socket API
to run over Infiniband/Ethernet from user space with full network stack bypass
and get better throughput, latency and packets/sec rate.

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
make %{?_smp_mflags}

%install
%make_install
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%pre
if [ `grep "^[^#]" /etc/security/limits.conf /etc/security/limits.d/* 2> /dev/null |grep memlock|grep unlimited | wc -l` -le 0 ]; then
        echo "- Changing max locked memory to unlimited (in /etc/security/limits.d/30-libvma-limits.conf)"
        echo "  Please log out from the shell and login again in order to update this change "
        echo "  Read more about this topic in the VMA's User Manual"
fi

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%{_libdir}/%{name}*.so.*
%{_libdir}/%{name}.so
%doc README.txt journal.txt VMA_VERSION
%config(noreplace) %{_sysconfdir}/libvma.conf
%config (noreplace) %{_sysconfdir}/security/limits.d/30-libvma-limits.conf

%files devel
%{_includedir}/*

%files utils
%{_bindir}/vma_stats

%changelog
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
