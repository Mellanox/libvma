%define prefix /
%define vma_ver __VERSION
%define release __RELEASE
%define date __DATE
%define time __TIME
%define revision __REVISION
%define major __MAJOR
%define kernel  %(eval uname -r | tr - _)
%define distribution %(if [ -e /etc/SuSE-release ]; then echo suse; else if [ -e /etc/redhat-release ]; then echo rh; fi;fi;)
%define include_dir /usr/include/mellanox

%define lib_dir /usr/share/%{name}-%{vma_ver}-%{release}

%if %{distribution}==suse
%define os_release %(VER_MAJOR="`cat /etc/SuSE-release | grep VERSION | awk -F "= " ' { print $2 }'`" ; echo "sles${VER_MAJOR}")
%define doc_dir /usr/share/doc/packages/%{name}-%{vma_ver}-%{release}
%else
%define os_release %(VER_MAJOR="`cat /etc/redhat-release | awk -F " " '{ print $7 }' | cut -b1`" ; echo "RHEL${VER_MAJOR}")
%define doc_dir /usr/share/doc/%{name}-%{vma_ver}-%{release}
%endif

%define arch %(eval arch)
%define ofed_ver %(eval ofed_info|grep OFED|head -1)
%define hostname %(eval hostname)
#%define _build_name_fmt %%{ARCH}/%%{NAME}-%%{VERSION}-%%{RELEASE}-%{os_release}-%%{ARCH}-%{ofed_ver}-%{hostname}.rpm
%define _build_name_fmt %%{ARCH}/%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%define prefix_dir /usr 
%ifarch x86_64 ppc64
%define dest_dir %prefix_dir/lib64
%define dest_dir32 %prefix_dir/lib
%else
%define dest_dir %prefix_dir/lib
%endif
%define ofed_dir %{prefix_dir}
%define vma_conf_dir %{_sysconfdir}

%define _use_internal_dependency_generator 0

Summary: Enhanced Service library for boosting TCP and UDP traffic (over OFED)
Name: libvma
Version: %vma_ver
Release: %release
License: GPLv2
Vendor: Mellanox
Group: Acceleration
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Source: %{name}-%{version}.tar.gz
requires: librdmacm, libibverbs, libnl

%description

VMA library is a performance booster of TCP and UDP traffic
Part of Mellanox's enhanced services
Allows application written over standard socket API
To run over Infiniband/Ethernet from userspace with full network stack bypass
and get better throughput, latency and packets/sec rate

%prep
%setup -q

%build
%define build_32 %(eval echo ${BUILD_32:-0})
%define build_bullseye %(eval echo ${BUILD_BULLSEYE:-0})
# in case of 64-bit arch - build it both fot 32 and 64 bit
#edit version.h
export date=%{date}
export time=%{time}
export revision=%{revision}

%ifarch x86_64
%if %{build_32}==1
	CFLAGS='-O3 -m32 -L/usr/lib' CXXFLAGS='-O3 -m32 -L/usr/lib' LDFLAGS='-m32 -L/usr/lib' FFLAGS='-m32 -L/usr/lib' \
	./configure --enable-build32 --with-ofed=%{ofed_dir} --prefix=%{prefix_dir} --libdir=%{dest_dir}
	make sockperf
	#rename all the 32 bit file
	mv src/vma/.libs src/vma/.libs32
	mv tests/sockperf/src/sockperf tests/sockperf32
	make clean
	make distclean
%endif
%endif

%ifarch ppc64
%if %{build_32}==1
	export CC='gcc'
	export CXX='g++'
	./configure --with-ofed=%{ofed_dir} --prefix=%{prefix_dir} --libdir=%{dest_dir}
	make sockperf
	#rename all the 32 bit file
	mv src/vma/.libs src/vma/.libs32
	mv tests/sockperf/src/sockperf tests/sockperf32
	make clean
	make distclean
	export CC='gcc -m64'
	export CXX='g++ -m64'
%endif
%endif

# build the binaries
export revision=1
./configure --with-ofed=%{ofed_dir} --prefix=%{prefix_dir} --libdir=%{dest_dir}
%if %{build_bullseye}==0
	make sockperf
%endif

%install
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}
mkdir -p $RPM_BUILD_ROOT/%{dest_dir}
mkdir -p $RPM_BUILD_ROOT/%{prefix_dir}/bin/

%ifarch x86_64 ppc64
%if %{build_32}==1
	mkdir -p $RPM_BUILD_ROOT/%{dest_dir32}
%endif
%endif

# The names of the liberary and the links 
%define first_file_name %{name}.so
%if %{release}==0
	%define sec_file_name %{name}.so.%{vma_ver}
	%define third_file_name %{name}.so.%{major}
%else
	%define sec_file_name %{name}-%{release}.so.%{vma_ver}
	%define third_file_name %{name}-%{release}.so.%{major}
%endif

%if %{build_bullseye}==1
	rm -rf "/tmp/test.cov"
	export PATH="/.autodirect/mswg/release/vma/bullseye/bin:$PATH"
	export COVFILE="$PWD/test.cov"
	cov01 -1
	cov01 -s
%endif

make DESTDIR=${RPM_BUILD_ROOT} install

%if %{build_bullseye}==1
	cp "$COVFILE" "/tmp/test.cov"
	cov01 -0
	#cd -
	make sockperf
	#cd build/vma
%endif

if [ -e /%{dest_dir}/%{first_file_name} ]; then rm -f /%{dest_dir}/%{first_file_name}; fi
chmod 6755 $RPM_BUILD_ROOT/%{dest_dir}/%{sec_file_name} $RPM_BUILD_ROOT%{dest_dir}/%{first_file_name}


%ifarch x86_64 ppc64
%if %{build_32}==1
	install -s -m 6755 src/vma/.libs32/%{sec_file_name} $RPM_BUILD_ROOT/%{dest_dir32}/%{sec_file_name}
	cp -d src/vma/.libs32/%{first_file_name} $RPM_BUILD_ROOT/%{dest_dir32}/%{first_file_name}
	cp -d src/vma/.libs32/%{third_file_name} $RPM_BUILD_ROOT/%{dest_dir32}/%{third_file_name}

	if [ -e /%{dest_dir32}/%{first_file_name} ]; then rm -f /%{dest_dir32}/%{first_file_name}; fi
	#chmod 6755 $RPM_BUILD_ROOT/%{dest_dir32}/%{name}.so
	install -m 755 tests/sockperf32 $RPM_BUILD_ROOT/%{prefix_dir}/bin/sockperf32
%endif
%endif


rm -f $RPM_BUILD_ROOT/%{dest_dir}/%{name}.la $RPM_BUILD_ROOT/%{dest_dir}/%{name}.a
rm -f $RPM_BUILD_ROOT/%{prefix_dir}/bin/vlogger_test $RPM_BUILD_ROOT/%{dest_dir}/libvlogger.a $RPM_BUILD_ROOT/%{dest_dir}/libvlogger.la
rm -f $RPM_BUILD_ROOT/%{prefix_dir}/bin/state_machine_test $RPM_BUILD_ROOT/%{dest_dir}/libstate_machine.la $RPM_BUILD_ROOT/%{dest_dir}/libstate_machine.a
rm -f $RPM_BUILD_ROOT/%{prefix_dir}/bin/udp_perf $RPM_BUILD_ROOT/%{prefix_dir}/bin/pps_test
# removed default installation, and do it ourslef afters
rm -rf $RPM_BUILD_ROOT/%{prefix_dir}/share/
rm -rf $RPM_BUILD_ROOT/%{prefix_dir}/include/
rm -rf $RPM_BUILD_ROOT/%{prefix_dir}/etc/
#
mkdir -p $RPM_BUILD_ROOT%{doc_dir}
mkdir -p $RPM_BUILD_ROOT%{include_dir}
mkdir -p $RPM_BUILD_ROOT%{lib_dir}/
mkdir -p $RPM_BUILD_ROOT%{lib_dir}/scripts
mkdir -p $RPM_BUILD_ROOT%{vma_conf_dir}
install -m 644 README.txt $RPM_BUILD_ROOT%{doc_dir}/README.txt
install -m 644 journal.txt $RPM_BUILD_ROOT%{doc_dir}/journal.txt
install -m 644 VMA_VERSION $RPM_BUILD_ROOT%{doc_dir}/VMA_VERSION
install -m 755 tests/vma_perf_envelope/vma_perf_envelope.sh $RPM_BUILD_ROOT%{lib_dir}/scripts/vma_perf_envelope.sh
install -m 644 src/vma/vma_extra.h $RPM_BUILD_ROOT%{include_dir}/vma_extra.h

install -m 755 src/vma/util/libvma.conf $RPM_BUILD_ROOT%{vma_conf_dir}

install -m 755 tests/sockperf/src/sockperf $RPM_BUILD_ROOT/%{prefix_dir}/bin/sockperf


cd src/stats

install -s -m 755 vma_stats $RPM_BUILD_ROOT/%{prefix_dir}/bin/vma_stats

%post
if [ `grep memlock /etc/security/limits.conf |grep unlimited |wc -l` -le 0 ]; then 
	echo "*             -   memlock        unlimited" >> /etc/security/limits.conf
	echo "*          soft   memlock        unlimited" >> /etc/security/limits.conf
	echo "*          hard   memlock        unlimited" >> /etc/security/limits.conf
fi

ldconfig
echo "- Changing max locked memory to unlimited (in /etc/security/limits.conf)"
echo "  Please log out from the shell and login again in order to update this change "
echo "  Read more about this topic in the VMA's User Manual"
echo ""
echo "- VMA README.txt is installed at: %{doc_dir}/README.txt"
echo "- Please refer to VMA journal for the latest changes: %{doc_dir}/journal.txt"
%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

%postun
[ -d %{lib_dir}/scripts/license ] && rmdir %{lib_dir}/scripts/license
[ -d %{lib_dir}/scripts/ ] && rmdir %{lib_dir}/scripts
[ -d %{lib_dir} ] && rmdir %{lib_dir}
[ -d %{doc_dir} ] && rmdir %{doc_dir}


%files

%defattr(-,root,root,-)
%{prefix}/%{dest_dir}/%{sec_file_name}
%{prefix}/%{dest_dir}/%{third_file_name}
%{prefix}/%{dest_dir}/%{first_file_name}
%{prefix}/%{doc_dir}/VMA_VERSION
%{prefix}/%{doc_dir}/README.txt
%{prefix}/%{doc_dir}/journal.txt
%{prefix}/%{lib_dir}/scripts/vma_perf_envelope.sh
%{prefix}/%{include_dir}/vma_extra.h
%{prefix}/%{prefix_dir}/bin/vma_stats
%{prefix}/%{prefix_dir}/bin/sockperf

%ifarch x86_64 ppc64
%if %{build_32}==1
%{prefix}/%{dest_dir32}/%{first_file_name}
%{prefix}/%{dest_dir32}/%{sec_file_name}
%{prefix}/%{dest_dir32}/%{third_file_name}
%{prefix}/%{prefix_dir}/bin/sockperf32
%endif
%endif

%config(noreplace) %{vma_conf_dir}/libvma.conf
