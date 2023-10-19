#!/bin/sh
get_admins() {
    cat /etc/group | grep adm && cat /etc/group | grep sudo
}

get_admins