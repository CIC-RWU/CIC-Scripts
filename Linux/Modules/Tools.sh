update_all(){
    sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
}

find_extension() {  
    find / -type f -name "*$1"
}