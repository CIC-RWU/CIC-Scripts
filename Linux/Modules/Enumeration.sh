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

find_extension() {
    $extension   

    find / -type f -name "*.$extension"
}

"$@"

