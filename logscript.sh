####Log monitoring#############3

#########Check all outgoing connections and log to a file###########
##########The random high ports are the ephemeral ports, which indicates that you likely have one or more programs connection outwards from this system.
#####

netstat -np | grep -v ^unix > log_conn.log

########Grep important data from syslog#########
echo "===================================" >> log_conn.log
echo "======Begin Logging syslog events==" >> log_conn.log
echo "===================================" >> log_conn.log

grep -r 'Accepted password' /var/log/syslog >> log_conn.log
grep -r 'failed password' /var/log/syslog >>log_conn.log
grep -r 'Accepted publickey' /var/log/syslog >> log_conn.log
grep -r 'session closed' /var/log/syslog >> log_conn.log
grep -r 'delete user' /var/log/syslog >> log_conn.log
grep -r 'new user' /var/log/syslog >> log_conn.log
grep -r 'password changed' /var/log/syslog >> log_conn.log
grep -r 'session opened' /var/log/syslog >> log_conn.log
grep -r 'failure' /var/log/syslog >> log_conn.log
grep -r 'FAILED' /var/log/syslog >> log_conn.log
grep -r 'failed' /var/log/syslog >> log_conn.log


###############SSH Configuration #####################################
echo "==============================================">>log_conn.log
echo "====Begin SSH Configuration Check=============">>log_conn.log
echo "==============================================">>log_conn.log 

###############Check Permit Root Login################################
cat /etc/ssh/sshd_config | grep PermitRootLogin | grep yes
if [ $?==0 ]; then
                sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
               	echo $(date): PermitRootLogin rule detected in SSH >> log_conn.log
           	msg=$(echo PermitRootLogin rule changed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )

fi

######################Check Protocol ##################################
cat /etc/ssh/sshd_config | grep Protocol | grep 1
if [ $?==0 ]; then
                sed -i 's/Protocol 2,1/Protocol 2/g' /etc/ssh/sshd_config
                sed -i 's/Protocol 1,2/Protocol 2/g' /etc/ssh/sshd_config
               	echo $(date): Protocol rule detected in SSH >> log_conn.log
        	msg=$(echo SSH Protocol changed to exclusively 1 | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
fi

##################Check X11 Forwarding#################################
grep X11Forwarding /etc/ssh/sshd_config | grep yes
if [ $?==0 ]; then
                sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
               	echo $(date): X11Forwarding rule detected in SSH >> log_conn.log
     	        msg=$(echo X11Forwarding rule changed to no | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )

fi

#################Sudoers require password#############################
grep PermitEmptyPasswords /etc/ssh/sshd_config | grep yes
if [ $?==0 ]; then
                sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
               	echo $(date): PermitEmptyPasswords rule detected in SSH >> log_conn.log
     	        msg=$(echo PermitEmptyPasswords rule changed to no | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )

fi


###########################SUDOERS CHECK BEGIN ##############################
grep NOPASSWD /etc/sudoers
if [ $?==0 ]; then
               tits=$(grep NOPASSWD /etc/sudoers)
		sed -i 's/$tits/ /g' /etc/sudoers
		echo $(date): NOPASSWD rule detected >> log_conn.log
     	        msg=$(echo SUDOERS NOPASSWD rule removed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )
fi

#cd /etc/sudoers.d && ls /etc/sudoers.d | grep -v cyberpatriot | grep -v scor | xargs rm
#     	        msg=$(echo Removed any sudoers.d rules other than cyberpatriot | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g'  )

#cat /etc/apt/apt.conf.d/10periodic | grep APT::Periodic::Update-Package-Lists | grep 0 >> /dev/null
#if [ $?==0 ]; then
#	sed -i 's/APT::Periodic::Update-Package-Lists "0"/APT::Periodic::Update-Package-Lists "1"/g' /etc/apt/apt.conf.d/10periodic
#	echo $(date): Periodic Updates enabled >> log_conn.log
	
#fi


#################Secure the apache web service#####################
echo "=============================================" >> log_conn.log
echo "===========Apache Web Server=================" >> log_conn.log
echo "=============================================" >> log_conn.log

if [ -e /etc/apache2/apache2.conf ]; then
    echo \<Directory \> >> /etc/apache2/apache2.conf
    echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
    echo -e ' \t Order Deny.Allow' >> /etc/apache2/apache2.conf
    echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
    echo \<Directory \/\> >> /etc/apache2/apache2.conf
    echo UserDir disabled root >> /etc/apache2/apache2.conf
    echo $(date): Apache securtuy measures enabled >> log_conn.log
fi

###############SYN COOKIE Protection #############################
echo "=============================================" >> log_conn.log
echo "===========SYN Cookie=================" >> log_conn.log
echo "=============================================" >> log_conn.log

sysctl -w net.ipv4.tcp_syncookies=0
if [ "$?" -eq "0" ]; then
              echo $(date): SYN Cookie protection enabled >> log_conn.log
fi

###############Only allow root in cron############################
cd /etc
/bin/rm -f cron.deny at.deny
echo root > cron.allow
echo root > at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
cd -
echo "Cron configured properly" >> log_conn.log


##############Crticial file permissions###########################
chown -R root:root /etc/apache2

echo "File permission for apache updated" >> log_conn.log

############Password Protection ##################################

echo "\n"
echo "=====================================" >> log_conn.log
echo "======Passwd Protection Module=======" >> log_conn.log
echo "=====================================" >> log_conn.log

echo $(date): Passwd with UID 1000 or more >> log_conn.log
cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 >> log_conn.log
echo "Please change passwds for these users" >> log_conn.log

echo "\n"
echo "Setting Password Policy" >> log_conn.log
apt-get install libpam-cracklib -y &> /dev/null

grep "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent " /etc/pam.d/common-auth

if [ "$?" -eq "1" ]; then	
	echo "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent " >> /etc/pam.d/common-auth
	echo "password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1" >> /etc/pam.d/common-password
	echo "password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root" >>  /etc/pam.d/common-password
	echo $(date): Super password policy applied >> log_conn.log
fi

##################TCP SYN Cookies#############################
echo "======================================================="
echo "====TCP SYN flood/redirect protection=================="
echo "======================================================="
sysctl -w net.ipv4.tcp_syncookies=1
echo $(date): RCP SYN Cookie Flood Protection >> log_conn.log

#################Prevent Routing#############################
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0


if [ $? -eq 0 ]; then
     	        msg=$(echo IP Forwarding and redirects disallowed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
fi

echo $(date): IP forwarding and redirects disallowed >> log_conn.log

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0

if [ $? -eq 0 ]; then
     	        msg=$(echo Accepting redirects and secure redirects disallowed | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g' )
fi
echo $(date):  Accepting redirects and secure redirects disallowed >> log_conn.log
sysctl -p

echo $(date): Locating world writable files .... >> log_conn.log


##################Failed Logins ###############################
echo "=======================================================" >> log_conn.log
echo "========Failed Logins==================================" >> log_conn.log
echo "=======================================================" >> log_conn.log

cat /var/log/faillog >> log_conn.log

echo "==================Empty passwords======================" >> log_conn.log
awk -F: '($2 == "") {print}' /etc/shadow >> log_conn.log




#################Defining the password policies################
#OLDFILE=/etc/login.defs
#NEWFILE=/etc/login.defs.new
#PASS_MAX_DAYS=15
#PASS_MIN_DAYS=3
#PASS_MIN_LEN=8
#PASS_WARN_AGE=7

#SEDSCRIPT=$(mktemp)
##Change the arguments at the same position##
#cat - > $SEDSCRIPT <<EOF
#s/\(PASS_MAX_DAYS\)\s*[0-9]*/\1 $PASS_MAX_DAYS/
#s/\(PASS_MIN_DAYS\)\s*[0-9]*/\1 $PASS_MIN_DAYS/
#s/\(PASS_WARN_AGE\)\s*[0-9]*/\1 $PASS_WARN_AGE/
#EOF

#sed -f $SEDSCRIPT $OLDFILE > $NEWFILE

########Add non-existing arguments#########################
#grep -q "^PASS_MAX_DAYS\s" $NEWFILE || echo "PASS_MAX_DAYS $PASS_MAX_DAYS" >> $NEWFILE
#grep -q "^PASS_MIN_DAYS\s" $NEWFILE || echo "PASS_MIN_DAYS $PASS_MIN_DAYS" >> $NEWFILE
#grep -q "^PASS_WARN_AGE\s" $NEWFILE || echo "PASS_WARN_AGE $PASS_WARN_AGE" >> $NEWFILE
#rm $SEDSCRIPT

##################Check the result##########################
#grep ^PASS $NEWFILE

#echo "HERE" >> log_conn.log

##############Copy the results back##########################
#cat $NEWFIE > $OLDFILE
#if [ $? -eq 0 ]; then
#                msg=$(echo Password min and max warning age is set | sed 's/\//%2F/g' | sed 's/\./%2E/g' | sed 's/\ /%20/g')
#                break>>/dev/null
#fi

#echo $(date): Password age established >> log_conn.log
 
#########Configure Tripwire###############

#####Patch the system######################
#apt-get update
