#!/bin/bash
# MIT License

# Saves File's current dir to var
dir=$(pwd)

# Checks if the EUID is root's
if [ "$EUID" -ne 0 ] ; then 
	echo "Run as Root"
	exit
fi
file_perms(){
	sudo chmod 644 /etc/passwd 
	sudo chmod 640 /etc/shadow 
	sudo chmod 600 /etc/gshadow
	sudo chmod 640 /etc/group
	sudo chmod 600 /etc/sudoers
	sudo chmod 600 /var/spool/cron
	sudo chmod 600 /etc/fstab
}


del_users(){
	for delname in $1 ; do
		userdel -r $delname
	done 
}

check_passwd(){
	rm nonauth_users
	touch nonauth_users

	if [ -e $dir/$1 ] ; then
		echo "nobody" >> $dir/$1
		names=$(cat $dir/$1)
		accounts=$(cat /etc/passwd | awk -F ":" '{if ($3 > 999) {print $1}}' | sort)
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
		echo "The Unauthorized Users Include:"
		nonauth=$(cat nonauth_users)
		echo $nonauth

		read -p "Do you want to delete those users (y/n): " delusersprompt
		if [ $delusersprompt = "y" ] ; then
			del_users $nonauth
		fi 
	else
		echo "[!!] $1 does not exist"
	fi
}

get_user_list(){
	read -p "Authorized Users List File (Default: users): " auth_list

	if [ -z $auth_list ] ; then
		check_passwd users
	else
		check_passwd $auth_list
	fi 
}

remove_sudo(){

}

check_groups(){

}

get_sudoer_list(){
	read -p "Authorized Sudoers List File (Default: sudoers): " sudo_list
	
	if [ -z $sudo_list ] ; then
		check_groups sudoers
	else
		check_groups $sudo_list
	fi 
}