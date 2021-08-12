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


# Deletes users given a list of usernames
del_users(){
	for delname in $1 ; do
		userdel -r $delname
	done 
}

# Checks the accounts in /etc/passwd and compares it to a list of authorized users
check_passwd(){ 
	rm nonauth_users
	touch nonauth_users

	if [ -e $dir/$1 ] ; then 	# checks if the given file exsists in the dir the script is in
		names=$(cat $dir/$1)	# sets names equal to the content of the authorizerd user list
		accounts=$(cat /etc/passwd | awk -F ":" '{if ($3 > 999) {print $1}}' | sort)
		
		# Checks that all accounts on the system with a UID of 1000+ are on the authorized user list
		# 	If an account is not it gets added to the nonauth_users output file
		for account in $accounts ; do 	
			authed="N"
			for name in $names ; do 	
				if [[ $account = $name || $account = "nobody" ]] ; then
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

		# Prompts about deleting unauth useres
		read -p "Do you want to delete those users (y/n): " delusersprompt
		if [ $delusersprompt = "y" ] ; then
			del_users $(cat nonauth_users) # Calls passes the content of nonauth_users to del_users
		fi 
	else
		# If the given file of authorized users does not exsist
		echo "[!!] $1 does not exist"
	fi
}

# Prompts the user for the name of the authorized users list (Default: users)
get_user_list(){
	read -p "Authorized Users List File (Default: users): " auth_list

	if [ -z $auth_list ] ; then # Checks if the user input is 'zero'/empty/null 
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
