get_admins{
    adminGroups=$()
    adminGroups+=$(cat /etc/group | grep adm)
    adminGroups+=$(cat /etc/group | grep sudo)
    adminGroups+=$(cat /etc/group | grep admin)

    $adminsGroups
}

get_installed_programs{
    dnf list installed || yum list installed || apt list --installed 
}

get_locallisteningports{
    $listeningports=$(netstat -tunlp)
}

get_services{
    systemctl --type=service --state=running
}

