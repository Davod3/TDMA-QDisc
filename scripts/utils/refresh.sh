echo "" > /var/log/kern.log
echo "" > /var/log/syslog
service syslog restart
journalctl --vacuum-size=50M
