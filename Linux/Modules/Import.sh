#!/bin/sh

echo "Loading Custom Functions PP"

: <<'END'
Run in the bash shell to autoload the commands each time you open the bash shell. Run the command below.
Change the path to where ever the Modules folder is stored 

echo "source '/mnt/hgfs/Github - CIC Scripts/CIC-Scripts/Linux/Modules/Import.sh'" | tee -a ~/.bashrc

END

source "/mnt/hgfs/Github - CIC Scripts/CIC-Scripts/Linux/Modules/Enumeration.sh"
source "/mnt/hgfs/Github - CIC Scripts/CIC-Scripts/Linux/Modules/Tools.sh"
