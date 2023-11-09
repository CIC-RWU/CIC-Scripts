#!/bin/sh
linux_enumeration () {
    echo "########## IP/MAC Address enumeration"
    if command -v ip &>/dev/null;
        then
            ip a
    elif command -v hostname -I &>/dev/null;
        then
            hostname -I
    fi
    echo "########## All User account enumeration"
    cat /etc/passwd | cut -f1 -d:
    echo "########## All Sudoers/wheel accounts"
    cat /etc/group | grep 'sudo\|wheel'
    echo "########## Files that have SUID/SGID bits set"
    find / -type f -perm -04000 -ls 2>/dev/null
    echo "########## Running a search to see if any binaries have capabilities set"
    if command -v getcap &>/dev/null;
        then
            getcap -r / 2>/dev/null
    fi
    echo "########## Getting all installed packages"
    if command -v apt &>/dev/null;
        then
            apt list --installed
    elif commmand -v rpm &>/dev/null;
        then
            rpm -qa
    fi
}

linux_enumeration