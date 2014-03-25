#
# Regular cron jobs for the fteproxy package
#
0 4	* * *	root	[ -x /usr/bin/fteproxy_maintenance ] && /usr/bin/fteproxy_maintenance
