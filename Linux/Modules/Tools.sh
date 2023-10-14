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