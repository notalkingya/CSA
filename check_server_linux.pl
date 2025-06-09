#!env perl
#Author: autoCreated
my $para_num = "1";
my %para;
@array_pre_flag = ();
@array_redhat_flag = ();
@array_debian_flag = ();
@array_suse_flag = ();
@array_ubuntu_flag = ();
@array_centos_flag = ();
@array_other_linux_flag = ();
@array_appendix_flag = ();
@array_circle_flag = ();

$para{Linux_su_password} = $ARGV[1];
$para{Linux_su_user} = $ARGV[2];

$pre_cmd{29} = "awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow
echo \"result=\"`awk -F: '( \$2 == \"\" ) { print \$1 }' /etc/shadow |wc -l`
";
push(@array_other_linux_flag, 29);push(@array_redhat_flag, 29);push(@array_debain_flag, 29);push(@array_suse_flag, 29);push(@array_ubuntu_flag, 29);push(@array_centos_flag, 29);$pre_cmd{5783} = "if [ -f /etc/pam.d/system-auth ];then
cat /etc/pam.d/system-auth|grep -v \"^[[:space:]]*#\"|egrep \"password[[:space:]]+requisite[[:space:]]+pam_cracklib.so\"
i=1
for parameter in minlen dcredit ucredit lcredit ocredit
do
echo \$parameter
if [[ -n `cat /etc/pam.d/system-auth|grep -v \"^[[:space:]]*#\"|egrep \"password[[:space:]]+requisite[[:space:]]+pam_cracklib.so\"|grep \"\$parameter\"` ]];then
echo \"result\$i=\"`cat /etc/pam.d/system-auth 2>/dev/null|grep -v \"^[[:space:]]*#\"|egrep \"password[[:space:]]+requisite[[:space:]]+pam_cracklib.so\"|head -n1|awk -F\"\$parameter=\" '{print\$2}'|awk '{print\$1}'`
else
echo \"result\$i=Parameters are not configured\"
fi
i=`expr \$i + 1`
done
unset parameter
else
echo \"result=The /etc/pam.d/system-auth file not found\"
fi
";
push(@array_other_linux_flag, 5783);push(@array_redhat_flag, 5783);push(@array_centos_flag, 5783);$pre_cmd{5784} = "cat /etc/passwd|awk -F: '{print \$1,\$3}'|sort -t ' ' -k 2n|uniq -f1 -D
echo \"result=\"`cat /etc/passwd|awk -F: '{print \$1,\$3}'|sort -t ' ' -k 2n|uniq -f1 -D|wc -l`
";
push(@array_other_linux_flag, 5784);push(@array_redhat_flag, 5784);push(@array_centos_flag, 5784);$pre_cmd{5787} = "if [[ `cat /etc/redhat-release |grep -aPo \"(?<=release\\s)\\d\"` -lt 7 ]];then
export LANG=en_US.UTF-8
if [ -f /etc/rsyslog.conf ];then
chkconfig --list|grep rsyslog
elif [ -f /etc/syslog.conf ];then
chkconfig --list|grep syslog
fi
elif [[ `cat /etc/redhat-release |grep -aPo \"(?<=release\\s)\\d\"` -eq 7 ]];then
systemctl list-unit-files|grep rsyslog
fi
";
push(@array_other_linux_flag, 5787);push(@array_redhat_flag, 5787);push(@array_centos_flag, 5787);$pre_cmd{5788} = "ps -ef|awk '{if(\$8~\"syslog\")print}'
if [[ -n `ps -ef|awk '{if(\$8~\"syslog\")print}'` ]];then
echo \"result=Log service is running\"
function venus(){
echo conf_file=\$1
if [ -f \$1 ];then
cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"\\*\\.\\*[[:space:]]+@\\S+\"
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"\\*\\.\\*[[:space:]]+@\\S+\"` ]];then
echo \"result0=yes\"
else
echo \"result0=no\"
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"kern\\.warning;\\*\\.err;authpriv\\.none[[:space:]]+@\"` ]];then
echo \"result1=yes\"
else
echo \"result1=no\"
fi
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"\\*\\.info;mail\\.none;authpriv\\.none;cron\\.none[[:space:]]+@\"` ]];then
echo \"result2=yes\"
else
echo \"result2=no\"
fi
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"\\*\\.emerg[[:space:]]+@\"` ]];then
echo \"result3=yes\"
else
echo \"result3=no\"
fi
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|egrep \"local7\\.\\*[[:space:]]+@\"` ]];then
echo \"result4=yes\"
else
echo \"result4=no\"
fi
fi
else
echo \"result=conf_file not found\"
fi
}
syslog_type=`ps -ef|awk '{if(\$8~\"syslog\")print\$8}'|awk -F\"/\" '{for(i=1;i<=NF;i++)if(\$i~/syslog/)print\$i}'`
echo syslog_type=\$syslog_type
case \$syslog_type in
syslogd)
conf_file=\"/etc/syslog.conf\"
venus \"\$conf_file\"
;;
rsyslogd)
conf_file=\"/etc/rsyslog.conf\"
venus \"\$conf_file\"
;;
*)
echo \"syslog_type not found\"
esac
unset syslog_type conf_file ip_address
else
echo \"result=Log service not running\"
fi
";
push(@array_other_linux_flag, 5788);push(@array_redhat_flag, 5788);push(@array_centos_flag, 5788);$pre_cmd{5792} = "if [[ -f /etc/rsyslog.conf ]];then
ls -l /etc/rsyslog.conf
echo \"result=\"`ls -l /etc/rsyslog.conf|awk '{print\$1}'|sed \"s/\\.//g\"|cut -b 2-|egrep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
elif [[ -f /etc/syslog.conf ]];then
ls -l /etc/syslog.conf
echo \"result=\"`ls -l /etc/syslog.conf|awk '{print\$1}'|sed \"s/\\.//g\"|cut -b 2-|egrep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
else
echo \"The rsyslog.conf file not found\"
fi
";
push(@array_other_linux_flag, 5792);push(@array_redhat_flag, 5792);push(@array_centos_flag, 5792);$pre_cmd{5793} = "rpm -qa
";
push(@array_other_linux_flag, 5793);push(@array_redhat_flag, 5793);push(@array_centos_flag, 5793);$pre_cmd{5794} = "cat /etc/hosts.allow 2>/dev/null|grep -v \"^#\"|grep -v \"^\$\"|egrep -i \"sshd|telnet|all\"
cat /etc/hosts.deny 2>/dev/null|grep -v \"^#\"|grep -v \"^\$\"|egrep -i \"all:[[:space:]]*all\"
if [[ -n `cat /etc/hosts.allow 2>/dev/null|grep -v \"^#\"|grep -v \"^\$\"|egrep -i \"sshd|telnet|all\"` ]];then
echo \"result1=yes\"
else
echo \"result1=no\"
fi
if [[ -n `cat /etc/hosts.deny 2>/dev/null|grep -v \"^#\"|grep -v \"^\$\"|egrep -i \"all:[[:space:]]*all\"` ]];then
echo \"result2=yes\"
else
echo \"result2=no\"
fi
";
push(@array_other_linux_flag, 5794);push(@array_redhat_flag, 5794);push(@array_centos_flag, 5794);$pre_cmd{5795} = "cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"
if [[ -n `cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"` ]];then
echo \"result=\"`cat /etc/profile |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"|grep \"TMOUT\"|awk -F\"=\" '{print\$2}'|awk '{print\$1}'`
else
echo \"result=Configuration error\"
fi
";
push(@array_other_linux_flag, 5795);push(@array_redhat_flag, 5795);push(@array_centos_flag, 5795);$pre_cmd{5833} = "if [ -f /etc/profile ];then
if [[ -n `cat /etc/profile|egrep -v \"^#|\\\"\"|grep \"umask\"|tail -1|awk '{print\$2}'` ]];then
echo \"result=\"`cat /etc/profile|egrep -v \"^#|\\\"\"|grep \"umask\"|tail -1|awk '{print\$2}'`
else
echo \"result=Configuration error\"
fi
else
echo \"result=The /etc/profile file not found\"
fi
";
push(@array_other_linux_flag, 5833);push(@array_redhat_flag, 5833);push(@array_debain_flag, 5833);push(@array_suse_flag, 5833);push(@array_ubuntu_flag, 5833);push(@array_centos_flag, 5833);$pre_cmd{5835} = "ps -ef|awk '{if(\$8~\"sshd\")print}'
if [[ -n `ps -ef|awk '{if(\$8~\"sshd\")print}'` ]];then
echo \"result=ssh is running\"
else
echo \"result=ssh not running\"
fi
";
push(@array_other_linux_flag, 5835);push(@array_redhat_flag, 5835);push(@array_debain_flag, 5835);push(@array_suse_flag, 5835);push(@array_ubuntu_flag, 5835);push(@array_centos_flag, 5835);$pre_cmd{5890} = "if [[ `cat /etc/redhat-release |grep -aPo \"(?<=release\\s)\\d\"` -lt 7 ]];then
export LANG=en_US.UTF-8
chkconfig --list |egrep \"telnet|klogin|kshell|ntalk|tftp\"
chkconfig --list |egrep \"sendmail\"|awk '{print \$1\" \"\$5\" \"\$7}'
echo \"telnet=\"`chkconfig --list |egrep \"telnet\"|grep \"on\"|wc -l`
echo \"klogin=\"`chkconfig --list |egrep \"klogin\"|grep \"on\"|wc -l`
echo \"kshell=\"`chkconfig --list |egrep \"kshell\"|grep \"on\"|wc -l`
echo \"ntalk=\"`chkconfig --list | egrep \"ntalk\"|grep \"on\"|wc -l`
echo \"tftp=\"`chkconfig --list | egrep \"tftp\" |grep \"on\" |wc -l`
echo \"sendmail=\"`chkconfig --list |egrep \"sendmail\"|awk '{print \$1\" \"\$5\" \"\$7}'|egrep \"on\"|wc -l`
elif [[ `cat /etc/redhat-release |grep -aPo \"(?<=release\\s)\\d\"` -eq 7 ]];then
systemctl status telnet 2>/dev/null|grep -w Active
echo \"telnet=\"`systemctl status telnet 2>/dev/null|grep -w Active|grep -w running|wc -l`
systemctl status klogin 2>/dev/null|grep -w Active
echo \"klogin=\"`systemctl status klogin 2>/dev/null|grep -w Active|grep -w running|wc -l`
systemctl status kshell 2>/dev/null|grep -w Active
echo \"kshell=\"`systemctl status kshell 2>/dev/null|grep -w Active|grep -w running|wc -l`
systemctl status ntalk 2>/dev/null|grep -w Active
echo \"ntalk=\"`systemctl status ntalk 2>/dev/null|grep -w Active|grep -w running|wc -l`
systemctl status tftp 2>/dev/null|grep -w Active
echo \"tftp=\"`systemctl status tftp 2>/dev/null|grep -w Active|grep -w running|wc -l`
systemctl status sendmail 2>/dev/null|grep -w Active
echo \"sendmail=\"`systemctl status sendmail 2>/dev/null|grep -w Active|grep -w running|wc -l`
fi
";
push(@array_other_linux_flag, 5890);push(@array_redhat_flag, 5890);push(@array_centos_flag, 5890);$pre_cmd{5891} = "ps -ef|awk '{if(\$8~\"nfsd\")print}'
if [[ -n `ps -ef|awk '{if(\$8~\"nfsd\")print}'` ]];then
exportfs 2>/dev/null
cat /etc/exports 2>/dev/null|grep -v \"^[[:space:]]*#\"
if [[ -z `exportfs 2>/dev/null` ]]&&[[ -z `cat /etc/exports 2>/dev/null|grep -v \"^[[:space:]]*#\"` ]];then
echo \"result=No sharing was found\"
else
echo \"result=Discovering Shared Content\"
fi
else
echo \"result=nfs not running\"
fi
";
push(@array_other_linux_flag, 5891);$pre_cmd{5895} = "i=1
for parameter in PASS_MIN_DAYS PASS_MAX_DAYS PASS_MIN_LEN PASS_WARN_AGE
do
cat /etc/login.defs 2>/dev/null|grep -v \"^[[:space:]]*#\"|egrep -w \$parameter
if [[ -n `cat /etc/login.defs 2>/dev/null|grep -v \"^[[:space:]]*#\"|egrep -w \$parameter` ]];then
echo \"result\$i=\"`cat /etc/login.defs 2>/dev/null|grep -v \"^[[:space:]]*#\"|egrep -w \$parameter|awk '{print\$2}'`
else
echo \"result\$i=Parameters are not configured\"
fi
let i=i+1
done
";
push(@array_other_linux_flag, 5895);push(@array_redhat_flag, 5895);push(@array_debain_flag, 5895);push(@array_suse_flag, 5895);push(@array_ubuntu_flag, 5895);push(@array_centos_flag, 5895);$pre_cmd{5896} = "cat /etc/passwd 2>/dev/null| awk -F: '{print\$1}'|while read username
do
if [[ -z `cat /etc/passwd 2>/dev/null|grep -v \"^[[:space:]]*#\"|awk -F\":\" '{if(\$7~\"nologin\")print\$1}'|grep -w \$username` ]];then
if [[ -n `cat /etc/passwd 2>/dev/null|grep -v \"^[[:space:]]*#\"|awk -F\":\" '{if(\$2==\"x\")print\$1}'|grep -w \$username` ]];then
if [[ -z `cat /etc/shadow 2>/dev/null|grep -v \"^[[:space:]]*#\"|grep -w \$username|awk -F\":\" '{print\$2}'|cut -b 1|awk '{if(\$1==\"!\"||\$1==\"*\")print}'` ]];then
if [[ -z `cat /etc/shadow 2>/dev/null|grep -v \"^[[:space:]]*#\"|grep -w \$username|awk -F\":\" '{print\$2}'|cut -b 1-2|awk '{if(\$1==\"!!\")print}'` ]];then
echo The \$username user is normal
if [[ -n `cat /etc/shadow 2>/dev/null|grep \"\$username\"|awk -F\":\" '{print\$4}'` ]];then
PASS_MIN_DAYS=`cat /etc/shadow 2>/dev/null|grep \"\$username\"|awk -F\":\" '{print\$4}'`
else
PASS_MIN_DAYS=null
fi
if [[ -n `cat /etc/shadow 2>/dev/null|grep \"\$username\"|awk -F\":\" '{print\$5}'` ]];then
PASS_MAX_DAYS=`cat /etc/shadow 2>/dev/null|grep \"\$username\"|awk -F\":\" '{print\$5}'`
else
PASS_MAX_DAYS=null
fi
echo \"USER_NAME=\$username\" \"PASS_MIN_DAYS=\$PASS_MIN_DAYS\"  \"PASS_MAX_DAYS=\$PASS_MAX_DAYS\"
unset username PASS_MIN_DAYS PASS_MAX_DAYS
else
echo \"The \$username user has been disabled\"
fi
else
echo \"The \$username user has been disabled\"
fi
else
echo \"The \$username user has been disabled\"
fi
else
echo \"The \$username user has been disabled\"
fi
done
";
push(@array_other_linux_flag, 5896);push(@array_redhat_flag, 5896);push(@array_centos_flag, 5896);$pre_cmd{5897} = "if [[ -n `ls  /lib*/security/pam_tally.so 2>/dev/null` ]];then
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally.so\"` ]];then
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally.so\"|egrep \"deny=\\w+\"` ]];then
echo \"result1=\"`cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally.so\"|awk -F\"deny=\" '{print\$2}'|awk '{print\$1}'`
else
echo \"result1=Configuration error\"
fi
else
echo \"result1=Configuration error\"
fi
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally.so\"` ]];then
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally.so\"|grep \"no_magic_root\"` ]];then
echo \"result2=yes\"
else
echo \"result2=no\"
fi
else
echo \"result2=Configuration error\"
fi
elif [[ -n `ls  /lib*/security/pam_tally2.so 2>/dev/null` ]];then
cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"` ]];then
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"|egrep \"deny=\\w+\"` ]];then
echo \"result1=\"`cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"|awk -F\"deny=\" '{print\$2}'|awk '{print\$1}'`
else
echo \"result1=Configuration error\"
fi
else
echo \"result1=Configuration error\"
fi
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"` ]];then
if [[ -n `cat /etc/pam.d/system-auth 2>/dev/null|egrep \"auth[[:space:]]*required[[:space:]]*\\S*pam_tally2.so\"|egrep \"no_magic_root|even_deny_root_account\"` ]];then
echo \"result2=yes\"
else
echo \"result2=no\"
fi
else
echo \"result2=Configuration error\"
fi
else
echo \"result=pam_tally not found\"
fi
";
push(@array_other_linux_flag, 5897);push(@array_redhat_flag, 5897);push(@array_debain_flag, 5897);push(@array_suse_flag, 5897);push(@array_ubuntu_flag, 5897);push(@array_centos_flag, 5897);$pre_cmd{5898} = "i=1
for FILE in /etc/passwd /etc/group /etc/shadow /etc/crontab
do
if [ -f \$FILE ];then
ls -l \$FILE
echo \"result\$i=\"`ls -l \$FILE|awk '{print\$1}'|sed \"s/\\.//g\"|cut -b 2-|egrep -v \"[r-][w-]-[r-]--[r-]--\"|wc -l`
else
echo \"result\$i=file not found\"
fi
i=`expr \$i + 1`
done
";
push(@array_other_linux_flag, 5898);push(@array_redhat_flag, 5898);push(@array_debain_flag, 5898);push(@array_suse_flag, 5898);push(@array_ubuntu_flag, 5898);push(@array_centos_flag, 5898);$pre_cmd{5899} = "i=1
for username in daemon bin sys adm uucp lp nobody
do
echo \$username
if [[ -n `cat /etc/passwd|grep -v \"^[[:space:]]*#\"|awk -F\":\" '{print\$1}'|grep -w \$username` ]];then
if [[ -z `cat /etc/passwd|grep -v \"^[[:space:]]*#\"|awk -F\":\" '{if(\$7~\"nologin\")print\$1}'|grep -w \$username` ]];then
if [[ -n `cat /etc/passwd|grep -v \"^[[:space:]]*#\"|awk -F\":\" '{if(\$2==\"x\")print\$1}'|grep -w \$username` ]];then
if [[ -z `cat /etc/shadow|grep -v \"^[[:space:]]*#\"|grep -w \$username|awk -F\":\" '{print\$2}'|cut -b 1|awk '{if(\$1==\"!\"||\$1==\"*\")print}'` ]];then
echo \"result\$i=The user is normal\"
else
echo \"result\$i=The user is disabled\"
fi
else
echo \"result\$i=The user is disabled\"
fi
else
echo \"result\$i=The user is disabled\"
fi
else
echo \"result\$i=The user does not exist\"
fi
i=`expr \$i + 1`
done
";
push(@array_other_linux_flag, 5899);push(@array_redhat_flag, 5899);push(@array_debain_flag, 5899);push(@array_suse_flag, 5899);push(@array_ubuntu_flag, 5899);push(@array_centos_flag, 5899);$pre_cmd{5900} = "find /var/log/ -type f -exec ls -l {} \\;|egrep \"[rwx-][rwx-][rwx-][rwx-][rwx-][rwx-][rwx-][rwx-]w[rwx-]\"
echo \"result=\"`find /var/log/ -type f -exec ls -l {} \\;|egrep \"[rwx-][rwx-][rwx-][rwx-][rwx-][rwx-][rwx-][rwx-]w[rwx-]\"|wc -l`
";
push(@array_other_linux_flag, 5900);push(@array_redhat_flag, 5900);push(@array_debain_flag, 5900);push(@array_suse_flag, 5900);push(@array_ubuntu_flag, 5900);push(@array_centos_flag, 5900);$pre_cmd{5901} = "if [[ -n `ps -ef|awk '{if(\$8~\"syslog\")print}'` ]];then
echo \"result=Log service is running\"
function venus(){
echo conf_file=\$1
if [ -f \$1 ];then
cat \$1 |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"| egrep  \".*@10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\"
if [[ -n `cat \$1 |grep -v \"^[[:space:]]*#\"|grep -v \"^\$\"| egrep \".*@10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\"` ]];then
echo \"result0=yes\"
else
echo \"result0=no\"
fi
else
echo \"result=conf_file not found\"
fi
}
syslog_type=`ps -ef|awk '{if(\$8~\"syslog\")print\$8}'|awk -F\"/\" '{for(i=1;i<=NF;i++)if(\$i~/syslog/)print\$i}'`
echo syslog_type=\$syslog_type
case \$syslog_type in
syslogd)
conf_file=\"/etc/syslog.conf\"
venus \"\$conf_file\"
;;
rsyslogd)
conf_file=\"/etc/rsyslog.conf\"
venus \"\$conf_file\"
;;
*)
echo \"syslog_type not found\"
esac
unset syslog_type conf_file ip_address
else
echo \"result=Log service not running\"
fi
";
push(@array_other_linux_flag, 5901);push(@array_redhat_flag, 5901);push(@array_centos_flag, 5901);$pre_cmd{-11} = "hostname
";
push(@array_pre_flag, -11);$pre_cmd{-12} = "lsb_release -a
";
push(@array_pre_flag, -12);$pre_cmd{-13} = "cat /etc/passwd
";
push(@array_pre_flag, -13);$pre_cmd{-14} = "cat /etc/group
";
push(@array_pre_flag, -14);$pre_cmd{-15} = "cat /etc/shadow
";
push(@array_pre_flag, -15);$pre_cmd{-16} = "chkconfig --list
";
push(@array_pre_flag, -16);$pre_cmd{-17} = "netstat -anp
";
push(@array_pre_flag, -17);$pre_cmd{-18} = "ps -ef
";
push(@array_pre_flag, -18);$pre_cmd{-19} = "uname -r
";
push(@array_pre_flag, -19);$pre_cmd{-20} = "w -h
";
push(@array_pre_flag, -20);$pre_cmd{-22} = "w -fh
";
push(@array_pre_flag, -22);$pre_cmd{-21} = "/sbin/ifconfig -a
";
push(@array_pre_flag, -21);$pre_cmd{-24} = "df
";
push(@array_pre_flag, -24);$pre_cmd{-25} = "if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf | sed '/^\\s*#/d'|sed '/^\\s*\$/d';elif [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | sed '/^\\s*#/d'|sed '/^\\s*\$/d';else cat /etc/syslog-ng/syslog-ng.conf | sed '/^\\s*#/d'|sed '/^\\s*\$/d';fi
";
push(@array_pre_flag, -25);$pre_cmd{-26} = "last -100 | grep -v \"wtmp\"
";
push(@array_pre_flag, -26);$pre_cmd{-27} = "lastb -100
";
push(@array_pre_flag, -27);$pre_cmd{-28} = "ls -l /etc/shadow /etc/gshadow /etc/group /etc/passwd|awk '{print \$1\" \"\$NF}'
";
push(@array_pre_flag, -28);$pre_cmd{-29} = "uname -p
";
push(@array_pre_flag, -29);$pre_cmd{-30} = "faillog -a
";
push(@array_pre_flag, -30);


sub get_os_info
{
	my %os_info = (
 "initSh"=>"","hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"initSh"} = `unset LANG`;
	$os_info{"hostname"} = `uname -n`;
	$os_info{"osname"} = `uname -s`;
	$os_info{"osversion"} = `lsb_release -a;cat /etc/issue;cat /etc/redhat-release;uname -a`;
	foreach (%os_info){   chomp;}
	return %os_info;
}

sub add_item
{
	 my ($string, $flag, $value)= @_;
	 $string .= "\t\t".'<script>'."\n";
	 $string .= "\t\t\t<id>$flag</id>\n";
	 $string .= "\t\t\t<value><![CDATA[$value]]></value>\n";
	 $string .= "\t\t</script>\n";
	return $string;
}
sub generate_xml
{
	$ARGC = @ARGV;
	if($ARGC lt 1)
	{
		print qq{usag:uuid.pl IP };
		exit;
	}
	my %os_info = get_os_info();
	my $os_name = $os_info{"osname"};
	my $host_name = $os_info{"hostname"};
	my $os_version = $os_info{"osversion"};
	my $date = ` date "+%Y-%m-%d %H:%M:%S"`;
	chomp $date;
	my $coding = `echo \$LANG`;
	my $coding_value = "UTF-8";
	chomp $coding;
	if($coding =~ "GB")
	{
        $coding_value = "GBK"
    }
	my $ipaddr = $ARGV[0];
	my $xml_string = "";
	
	$xml_string .='<?xml version="1.0" encoding="'.$coding_value.'"?>'."\n";
	$xml_string .='<result>'."\n";
	$xml_string .= '<osName><![CDATA['."$os_name".']]></osName>'."\n";
	$xml_string .= '<version><![CDATA['."$os_version".']]></version>'."\n";
	$xml_string .= '<ip><![CDATA['."$ipaddr".']]></ip>'."\n";
	$xml_string .= '<type><![CDATA[/server/Linux]]></type>'."\n";
	$xml_string .= '<startTime><![CDATA['."$date".']]></startTime>'."\n";
	$xml_string .= '<pId><![CDATA[1000]]></pId>'."\n";

	$xml_string .=	"\t".'<scripts>'."\n";
	$centos = "CentOS";
	$redhat = "Red Hat";
	$suse = "Suse";
	$debian = "Debian";
	$ubuntu = "Ubuntu";
	if($os_version=~ /$centos/i){
	@array_circle_flag = @array_centos_flag
	}
	elsif($os_version=~ /$redhat/i){
	@array_circle_flag = @array_redhat_flag
	}
	elsif($os_version=~ /$debian/i){
	@array_circle_flag = @array_debian_flag
	}
	elsif($os_version=~ /$ubuntu/i){
	@array_circle_flag = @array_ubuntu_flag
	}
	elsif($os_version=~ /$suse/i){
	@array_circle_flag = @array_suse_flag
	}
	else{	
	@array_circle_flag = @array_other_linux_flag
	}
	foreach $key (@array_circle_flag)
	{
		print $key."\n";
		$value = $pre_cmd{$key};
		my $tmp_result = $value.`$value`;
		chomp $tmp_result;
		$tmp_result =~ s/>/&gt;/g;
		$tmp_result =~ s/[\x00-\x08\x0b-\x0c\x0e-\x1f]//g;
		$xml_string = &add_item( $xml_string, $key, $tmp_result );
	}	
	foreach $key (@array_pre_flag)
		{
			print $key."\n";
			$value = $pre_cmd{$key};
			my $tmp_result = $value.`$value`;
			chomp $tmp_result;
			$tmp_result =~ s/>/&gt;/g;
			$tmp_result =~ s/[\x00-\x08\x0b-\x0c\x0e-\x1f]//g;
			$xml_string = &add_item( $xml_string, $key, $tmp_result );
		}
	$xml_string .= "\t</scripts>\n";
	
	my $enddate = ` date "+%Y-%m-%d %H:%M:%S"`;
	$xml_string .= '<endTime><![CDATA['."$enddate".']]></endTime>'."\n";
	
	$xml_string .= "</result>"."\n";
	$xmlfile = $ipaddr."_"."linux"."_chk.xml";
	print $xmlfile."\n";
	open XML,">$ENV{'PWD'}/".$xmlfile or die "Cannot create ip.xml:$!";
	print XML $xml_string;
    print "write  result to $ENV{'PWD'}/$xmlfile\n";
    print "execute end!\n";
 }
 generate_xml();
