#!/bin/sh
get_admins() {
    cat /etc/group | grep adm && cat /etc/group | grep sudo
}

get_installed_programs() {
    dnf list installed || yum list installed || apt list --installed 
}

get_listeningports() {
    netstat -tunlp
}

get_services() {
    systemctl --type=service --state=running --all
}

get_networkinfo() {
    ip a | grep inet && ip a | grep ether 
}

get_os() {
    OS=$(cat /etc/os-release | grep PRETTY_NAME)
    OSNAME=${OS#*=}
    printf "$OSNAME\n"
}




"$@"

