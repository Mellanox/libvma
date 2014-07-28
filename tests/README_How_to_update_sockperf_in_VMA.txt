1.	Commit changes to sockperf on google code: 'svn ci'
2.	Check out clean sockperf: 'svn co https://sockperf.googlecode.com/svn/branches/sockperf_v2 sockperf'
3.	Build: cd sockperf && ./autogen.sh && ./configure && make
	Note: In order to support new archs (e.g. aarch64) need to run
	autogen.sh with newer autoconf/make tools. It can be done by running on
	newer system, like Ubnutu14.04, or upgrading autoconf/make tools.
	After running autogen.sh, the rest can be done on the old system.
4.  Shrink sources to .tar.gz using 'make dist'
5.	Upload as new Download package to google docs with some details about the major changes
6.	Add the major changes to the wiki page
7.	On vma:
	a. git rm old_sockperf.tar: svn rm tests/sockperf-OLD.tar.gz
	b. git add new_sockperf.tar: svn add tests/sockperf-NEW.tar.gz
	c. update SOCKPERF_VERSION with NEW_REV (instead OLD_REV) string in tests/Makefile.am
	d. git status should show 3 files: Makefile.am, sockperf-OLD and sockperf-NEW
	d. git ci
	e. git push
