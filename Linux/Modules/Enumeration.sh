get_admins{
    adminGroups=$()
    tempadm=$(cat /etc/group | grep adm)
    adminGroups+=${tempadm##*:}
    tempadm=$(cat /etc/group | grep sudo)
    adminGroups+=${tempadm##*:}
    tempadm+=$(cat /etc/group | grep admin)
    adminGroups+=${tempadm##*:}

    $admins
}

get_installed_programs{
    dnf list installed || yum list installed || apt list --installed 
}

get_locallisteningports{
    $listeningports=$(sudo netstat -tunlp)
}

get_services{
    systemctl --type=service --state=running
}

