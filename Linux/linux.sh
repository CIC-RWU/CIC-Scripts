#!/bin/bash
# MIT License

# Saves Script's current dir
dir=$(pwd)

# Colors
red=$'\e[1;31m'
green=$'\e[1;32m'
blue=$'\e[1;34m'
magenta=$'\e[1;35m'
cyan=$'\e[1;36m'
yellow=$'\e[1;93m'
white=$'\e[0m'
bold=$'\e[1m'
norm=$'\e[21m'

# Checks if the EUID is root's
if [ "$EUID" -ne 0 ] ; then 
	echo "[!!] You must run as root"
	exit
fi

# Changes the read/write perms on files that should be restricted
file_perms(){
	sudo chmod 644 /etc/passwd 
	sudo chmod 640 /etc/shadow 
	sudo chmod 600 /etc/gshadow
	sudo chmod 640 /etc/group
	sudo chmod 600 /etc/sudoers
	sudo chmod 600 /var/spool/cron
	sudo chmod 600 /etc/fstab
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
		auth_list=users
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