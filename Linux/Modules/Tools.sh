update_all(){
    sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
}

: '
.EXAMPLE 
find_extension ".mp3"
'
find_extension() {  
    find / -type f -name "*$1"
}

disable_guest() {
    echo "allow-guest=false" | tee -a /etc/lightdm/lightdm.conf 
    echo "greeter-hide-users=true" | tee -a /etc/lightdm/lightdm.conf 

    tail /etc/lightdm/lightdm.conf 
}

disable_scheduling() {
    systemctl mask cron; systemctl stop cron
}

remove_hacking() {
    sudo dpkg --purge hydra netcat john aircrack-ng medusa nmap ophcrack dsniff cain kismet knocker p0f minetest openarena freeciv brainiac
}