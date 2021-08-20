#!/bin/bash
# MIT License

# Saves Script's current dir
dir=$(pwd)

# Colors
red=$'\e[1;31m'
green=$'\e[1;32m'
blue=$'\e[0;34m'
magenta=$'\e[0;35m'
cyan=$'\e[0;36m'
yellow=$'\e[0;93m'
white=$'\e[0m'
bold=$'\e[1m'
grey=$'\e[0;37m'
reset=$'\033[39m'
plus_sign="$grey[$green+$grey]"
error="$grey[$red!!$grey]"

# Checks if the EUID is root's
if [ "$EUID" -ne 0 ] ; then 
	echo "[!!] You must run as root"
	exit
fi

# Changes the read/write perms on files that should be restricted
file_perms(){
	sudo chmod 644 /etc/passwd
	echo "$plus_sign$reset Set permissions for $cyan/etc/passwd$reset."
	sudo chmod 640 /etc/shadow
	echo "$plus_sign$reset Set permissions for $cyan/etc/shadow$reset."
	sudo chmod 600 /etc/gshadow
	echo "$plus_sign$reset Set permissions for $cyan/etc/gshadow$reset."
	sudo chmod 640 /etc/group
	echo "$plus_sign$reset Set permissions for $cyan/etc/group$reset."
	sudo chmod 600 /etc/sudoers
	echo "$plus_sign$reset Set permissions for $cyan/etc/sudoers$reset."
	sudo chmod 600 /var/spool/cron
	echo "$plus_sign$reset Set permissions for $cyan/var/spool/cron$reset."
	sudo chmod 600 /etc/fstab
	echo "$plus_sign$reset Set permissions for $cyan/etc/fstab$reset."
}

# Checks the accounts in /etc/passwd and compares it to a list of authorized users
check_passwd(){ 
	rm nonauth_users
	touch nonauth_users

	names=$@	# sets names equal to the content of the authorizerd user list
	accounts=$(cat /etc/passwd | awk -F ":" '{if ($3 > 999) {print $1}}' | sort)
	
	# Checks that all accounts on the system with a UID of 1000+ are on the authorized user list
	# if an account is not it gets added to the nonauth_users output file
	for account in $accounts ; do
		authed="N"
		for name in $names ; do
			if [ $account = $name ] ; then
				authed="Y"
			fi
		done
		if [ $authed = "N" ] ; then
			echo "$account" >> nonauth_users
		fi
	done
	# Lists the users not in the authorized user list
	echo "The Unauthorized Users Include:"
	cat nonauth_users
	# Prompts about deleting unauth users
	read -p "Do you want to delete those users (y/n)? " delusers_prompt
	if [ $delusers_prompt = "y" ] ; then
		for delname in $(cat nonauth_users) ; do
		userdel -r $delname
	    echo "[+] Successfully deleted $delname"
	    done 
	fi
}

# Prompts the user the name of the admin group (Default: sudo) 
# and asks user if the list of all auth admins is correct if it is replaces the current list with correct list
check_group(){
	read -p "Admin group name (Default: sudo):" admin_group
	if [ -z $admin_group ] ; then # Checks if the user input is 'zero'/empty/null 
		admin_group=sudo
	fi

	auth_members=$@

	read -p "Is ($auth_members) all authorized admin users (y/n)? " correct_admins

	if [ $correct_admins = "y" ] ; then
		get_admin_group=$(cat /etc/group | awk -v admin=$admin_group -F ":" '{if ($1 == admin) {print $1 ":" $2 ":" $3 ":"}}')
		sed -iE "s/$get_admin_group.*/$get_admin_group$auth_members/g" /etc/group
	fi
}

# Prompts the user for the name of the authorized users list (Default: users)
get_auth_list(){
	read -p "Authorized Users List File [Add + to end of name if admin] (Default: users): " auth_list
	if [ -z $auth_list ] ; then # Checks if the user input is 'zero'/empty/null 
		auth_list="users"
	fi

	auth_users="nobody"
	admins=""

	# Looks through the auth list and adds users to auth_users and admins(if a + is at the end of name) 
	for name in $(cat $dir/$auth_list) ; do
		if [[ $name == *"+"* ]] ; then 
			name=$(echo $name | sed 's/.$//')
			admins+="$name,"
		fi
		auth_users+=" $name"
	done

	check_passwd $auth_users
	check_group $(echo $admins | sed 's/.$//')
}

disable_root(){

	# Goes to /etc/passwd and changes /bin/bash to /sbin/nologin
	sed -iE 's/root:x:0:0:root:\/root:.*/root:x:0:0:root:\/root:\/sbin\/nologin/g' /etc/passwd
	
	# Goes to /etc/shadow and locks the root password
	passwd -l root
}

configure_ssh() {
	sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
	sed -i 's/.*Protocol.*/Protocol 2/g' /etc/ssh/sshd_config
	sed -i 's/.*X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
	sed -i 's/.*UsePam no/UsePam yes/g' /etc/ssh/sshd_config
	sed -i 's/.*RSAAuthentication no/RSAAuthentication yes/g' /etc/ssh/sshd_config
	sed -i 's/.*PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
	sed -i 's/.*StrictModes no/StrictModes yes/g' /etc/ssh/sshd_config
	sed -i 's/.*LoginGraceTime.*/LoginGraceTime 60/g' /etc/ssh/sshd_config
	sed -i 's/.*IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config
	sed -i 's/.*TCPKeepAlive yes/TCPKeepAlive no/g' /etc/ssh/sshd_config
	sed -i 's/.*UsePrivilegeSeperation no/UsePrivilegeSeperation yes/g' /etc/ssh/sshd_config
	sed -i 's/.*PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
	sed -i 's/.*PermitBlacklistedKeys yes/PermitBlacklistedKeys no/g' /etc/ssh/sshd_config
	sed -i 's/.*HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config
	sed -i 's/.*PrintMotd yes/PrintMotd no/g' /etc/ssh/sshd_config
}

# Disables ssh password auth by setting PasswordAuthentication to no in sshd_config
disable_ssh_passwordAuth() {
	sed -iE 's/.*PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
}

sysctl_config(){
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	echo """
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_challenge_ack_limit = 2147483647
net.ipv4.tcp_invalid_ratelimit = 500
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.accept_ra_rtr_pref = 0
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
""" > /etc/sysctl.conf
}

banner(){
	echo """

		 █████╗ ██╗ █████╗ ██╗     ██╗  ██╗
		██╔══██╗██║██╔══██╗██║     ██║  ██║
		██║  ╚═╝██║██║  ╚═╝██║     ███████║
		██║  ██╗██║██║  ██╗██║     ██╔══██║
		╚█████╔╝██║╚█████╔╝███████╗██║  ██║
		 ╚════╝ ╚═╝ ╚════╝ ╚══════╝╚═╝  ╚═╝
 	Cybersecurity and Intelligene Club Linux Hardening Script
	
	"""
}

menu_text(){
	if [[ $1 -eq 0 ]]; then
		echo "hardening ➥ "
	elif [[ $1 -eq 1 ]]; then
		echo "hardening ($red$auto_or_manual$reset) ➥ "
	elif [[ $1 -eq 2 ]]; then
		echo "hardening ($red$auto_or_manual/$hardening_option$reset) ➥ "
	fi
}

selection_menu(){

	banner
	echo "Please select Automatic or Manual:"
	echo -e "\t\n1) Automatic\t\n2) Manual\n" 

	while [ 1 ]; do
		read -p "$(menu_text 0)" {auto_or_manual,,}
		if [[ auto_or_manual -eq 1 ]]; then
			echo "AUTOMATIC"
			break
		elif [[ auto_or_manual -eq 2 ]] || [[ auto_or_manual == "manual" ]]; then
			auto_or_manual="manual"
			break
		fi
	done

	echo -e "\nPlease select which option you would like to proceed in: "
	echo -e "\n\t1) Services\n\t2) File Permissions\n\t3) User Listing\n\t4) PAM Configuration\n\t5) Firewall Configuration\n\t6) TCP SYN Cookies\n\t7) SYSCTL Configuration\n\t8) Updates\n\t9) Software Removal\n\t10) Sudo Hardening"
	while [ 1 ]; do
		read -p "$(menu_text 1)" {hardening_option,,}
		if [[ hardening_option -eq 1 ]] || [[ hardening_option == "services" ]] || [[ hardening_option == "service" ]]; then
			hardening_option="services"
			break
		elif [[ hardening_option -eq 2 ]] || [[ hardening_option == "file permissions" ]] || [[ hardening_option == "file_permissions" ]]; then
			hardening_option="file_permissions"
			break
		elif [[ hardening_option -eq 3 ]] || [[ hardening_option == "user_listing" ]] || [[ hardening_option == "user listing" ]]; then
			hardening_option="user_listing"
			break
		elif [[ hardening_option -eq 4 ]] || [[ hardening_option == "pam" ]] || [[ hardening_option == "pam_config" ]] || [[ hardening_option == "pam_configuration" ]] || [[ hardening_option == "pam config" ]]; then
			hardening_option="pam_configuration"
			break
		elif [[ hardening_option -eq 5 ]] || [[ hardening_option == "firewall" ]] || [[ hardening_option == "firewall_config" ]] || [[ hardening_option == "firewall config" ]] || [[ hardening_option == "firewall configuration" ]]; then
			hardening_option="firewall_configuration"
			break
		elif [[ hardening_option -eq 6 ]] || [[ hardening_option == "tcp syn cookies" ]] || [[ hardening_option == "tcp_syn_cookies" ]] || [[ hardening_option == "tcp" ]]; then
			hardening_option="tcp_syn_cookies"
			break
		elif [[ hardening_option -eq 7 ]] || [[ hardening_option == "sysctl" ]] || [[ hardening_option == "sysctl config" ]] || [[ hardening_option == "sysctl_config" ]] || [[ hardening_option == "sysctl_configuration" ]] || [[ hardening_option == "sysctl configuration" ]]; then
			hardening_option="sysctl_configuration"
			break
		elif [[ hardening_option -eq 8 ]] || [[ hardening_option == "updates" ]] || [[ hardening_option == "update" ]]; then
			hardening_option="updates"
			break
		elif [[ hardening_option -eq 9 ]] || [[ hardening_option == "software removal" ]] || [[ hardening_option == "software_removal" ]]; then
			hardening_option="software_removal"
			break
		elif [[ hardening_option -eq 10 ]] || [[ hardening_option == "sudo" ]]; then
			hardening_option="sudo_hardening"
			break
		fi
	done
	echo "$(menu_text 2)"

}

sysctl_config