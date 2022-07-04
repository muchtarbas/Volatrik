#!/usr/bin/bash

#colour
cyellow='\e[0;33m'
cgreen='\033[92m'

#OS Information
minfo=windows.info.Info
#Process List
declare -a plist
plist=(windows.pslist.PsList windows.psscan.PsScan windows.pstree.PsTree)
#Command line
cline=windows.cmdline.CmdLine
#DLLs
dll="windows.dlllist.DllList"
#Dumpfiles
dump="windows.dumpfiles.DumpFiles"
#Service
declare -a svc
svc=(windows.svcscan.SvcScan windows.getservicesids.GetServiceSIDs)
#Network
declare -a net
net=(windows.netscan.NetScan windows.netstat.NetStat)
#Registry
declare -a reg
reg=(windows.registry.certificates.Certificates windows.registry.hivescan.HiveScan windows.registry.hivelist.HiveList windows.registry.printkey.PrintKey windows.registry.userassist.UserAssist)
#Malware
declare -a mal
mal=(windows.malfind.Malfind windows.driverirp.DriverIrp windows.ssdt.SSDT)
#Files Dump
fdump="windows.dumpfiles.DumpFiles"
#Yara
yara_rule=malware_rules.yar
yara=windows.vadyarascan.VadYaraScan

#banner
banner(){
echo -e $cgreen"   __ __   ___   _       ____  ______  ____   ____  __  _  "
echo -e $cgreen"  |  |  | /   \ | |     /    ||      ||    \ |    ||  |/ ] "
echo -e $cgreen"  |  |  ||     || |    |  o  ||      ||  D  ) |  | |  ' /  "
echo -e $cgreen"  |  |  ||  O  || |___ |     ||_|  |_||    /  |  | |    \  "
echo -e $cgreen"  |  :  ||     ||     ||  _  |  |  |  |    \  |  | |     \ "
echo -e $cgreen"   \   / |     ||     ||  |  |  |  |  |  .  \ |  | |  .  | "
echo -e $cgreen"    \_/   \___/ |_____||__|__|  |__|  |__|\_||____||__|\_| "				
}


#info
inpo(){
	echo "Scanning Info"
	vol -f $vname $minfo > $dir/$minfo 2>/dev/null
	echo "Success"
	sleep 2
	menu
}

#Process list
process_list(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	       Process List               [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[1]	${plist[0]}"
	echo -e "	[2]	${plist[1]}"
	echo -e "	[3]	${plist[2]}"
	echo -e "	[4]	Select by PID"
	echo -e "	[5]	Dump Process PID"
	echo -e "	[6]	Back To Menu"
	echo ""
	echo -ne "	Pilih : " ;tput sgr0
	read pilih_plist
	
	if test $pilih_plist == '1'
		then
		echo "Processing ${plist[0]}"
		vol -f $vname ${plist[0]} > $dir/${plist[0]} 2>/dev/null
		echo "Success"
		sleep 2
		process_list
	elif test $pilih_plist == '2'
		then
		echo "Processing ${plist[1]}"
		vol -f $vname ${plist[1]} > $dir/${plist[1]} 2>/dev/null
		echo "Success"
		sleep 2
		process_list
	elif test $pilih_plist == '3'
		then
		echo "Processing ${plist[2]}"
		vol -f $vname ${plist[2]} > $dir/${plist[2]} 2>/dev/null
		echo "Success"
		sleep 2
		process_list
	elif test $pilih_plist == '4'
		then
		echo -ne "	PID : ";tput sgr0
		read pid
		mkdir -p $dir/$pid  2>/dev/null
		echo -e ""
		echo -e "Processing"
		vol -f $vname ${plist[1]} --pid $pid > $dir/$pid/${plist[1]} 2>/dev/null
		echo "Success"
		sleep 2
		process_list
	elif test $pilih_plist == '5'
		then
		echo "Processing $fdump"
		echo -ne "	PID : ";tput sgr0
		read pid
		mkdir -p $dir/dump/$pid/ 2>/dev/null
		dump_output=""
		echo -e "Processing"
		vol -f $vname -o $dir/dump/$pid/ $fdump --pid $pid 2>/dev/null
		echo "Success"
		sleep 2
		process_list
	elif test $pilih_plist == '6'
		then
		menu
	else
		process_list
	fi
}

#Dlls
dlls(){
	echo "Scanning DLLs"
	vol -f $vname $dll > $dir/$dll 2>/dev/null
	echo "Success"
	sleep 2
	menu
}

#Services
services(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	         Services                 [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[1]	${svc[0]}"
	echo -e "	[2]	${svc[1]}"
	echo -e "	[3]	Back To Menu"
	echo ""
	echo -ne "	Pilih : " ;tput sgr0
	read pilih_services
	
	if test $pilih_services == '1'
		then
		echo "Processing ${svc[0]}"
		vol -f $vname ${svc[0]} > $dir/${svc[0]} 2>/dev/null
		echo "Success"
		sleep 2
		services
	elif test $pilih_services == '2'
		then
		echo "Processing ${svc[1]}"
		vol -f $vname ${svc[1]} > $dir/${svc[1]} 2>/dev/null
		echo "Success"
		sleep 2
		services
	elif test $pilih_services == '3'
		then
		menu
	else
		services
	fi
	
}

#Network
network(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	           Network                [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[1]	${net[0]}"
	echo -e "	[2]	${net[1]}"
	echo -e "	[3]	Back To Menu"
	echo ""
	echo -ne "	Pilih : " ;tput sgr0
	read pilih_network
	
	if test $pilih_network == '1'
		then
		echo "Processing ${net[0]}"
		vol -f $vname ${net[0]} > $dir/${net[0]} 2>/dev/null
		echo "Success"
		sleep 2
		network
	elif test $pilih_network == '2'
		then
		echo "Processing ${net[1]}"
		vol -f $vname ${net[1]} > $dir/${net[1]} 2>/dev/null
		echo "Success"
		sleep 2
		network
	elif test $pilih_network == '3'
		then
		menu
	else
		network
	fi
	
}

#Registry
registry(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	         Registry                 [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[1]	${reg[0]}"
	echo -e "	[2]	${reg[1]}"
	echo -e "	[3]	${reg[2]}"
	echo -e "	[4]	${reg[3]}"
	echo -e "	[5]	${reg[4]}"
	echo -e "	[6]	Back To Menu"
	echo ""
	echo -ne "	Pilih : " ;tput sgr0
	read pilih_registry
	
	if test $pilih_registry == '1'
		then
		echo "Processing ${reg[0]}"
		vol -f $vname ${reg[0]} > $dir/${reg[0]} 2>/dev/null
		echo "Success"
		sleep 2
		registry
	elif test $pilih_registry == '2'
		then
		echo "Processing ${reg[1]}"
		vol -f $vname ${reg[1]} > $dir/${reg[1]} 2>/dev/null
		echo "Success"
		sleep 2
		registry
	elif test $pilih_registry == '3'
		then
		echo "Processing ${reg[2]}"
		vol -f $vname ${reg[2]} > $dir/${reg[2]} 2>/dev/null
		echo "Success"
		sleep 2
		registry
	elif test $pilih_registry == '4'
		then
		echo "Processing ${reg[3]}"
		vol -f $vname ${reg[3]} > $dir/${reg[3]} 2>/dev/null
		echo "Success"
		sleep 2
		registry
	elif test $pilih_registry == '5'
		then
		echo "Processing ${reg[4]}"
		vol -f $vname ${reg[4]} > $dir/${reg[4]} 2>/dev/null
		echo "Success"
		sleep 2
		registry
	elif test $pilih_registry == '6'
		then
		menu
	else
		registry
	fi
	
}

#Malware
malware(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	          Malware                 [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[1]	${mal[0]}"
	echo -e "	[2]	${mal[1]}"
	echo -e "	[3]	${mal[2]}"
	echo -e "	[4]	Back To Menu"
	echo ""
	echo -ne "	Pilih : " ;tput sgr0
	read pilih_malware
	
	if test $pilih_malware == '1'
		then
		echo "Processing ${mal[0]}"
		vol -f $vname ${mal[0]} > $dir/${mal[0]} 2>/dev/null
		echo "Success"
		sleep 2
		malware
	elif test $pilih_malware == '2'
		then
		echo "Processing ${mal[1]}"
		vol -f $vname ${mal[1]} > $dir/${mal[1]} 2>/dev/null
		echo "Success"
		sleep 2
		malware
	elif test $pilih_malware == '3'
		then
		echo "Processing ${mal[2]}"
		vol -f $vname ${mal[2]} > $dir/${mal[2]} 2>/dev/null
		echo "Success"
		sleep 2
		malware
	elif test $pilih_malware == '4'
		then
		menu
	else
		malware
	fi
}

#Yara
yara(){
	echo "Scanning Yara"
	vol -f $vname $yar --yara-file $yara_rule > $dir/$yar 2>/dev/null
	echo "Success"
	sleep 2
	menu
}

#Manual
manual(){
	clear
	clear
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	      Manual Command              [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo ""
	echo -e "	[00]	Back To Menu"
	echo -ne "	Command : "; tput sgr0
	read command
	if test $command == "00" 2>/dev/null
		then
		menu
	else
		echo -ne "     Output File : "; tput sgr0
		read output
		echo "Processing $command"
		mkdir -p $dir/manual  2>/dev/null
		vol -f $vname $command > $dir/manual/$output 2>/dev/null
		echo ""
		echo "Success"
		sleep 2
		manual
	fi
}

#menu
menu() {
	clear
	clear
	resize -s 25 60 > /dev/null
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	    Muchtar Arif Bastian         [-]"
	echo -e $cgreen"       [-]	         Version 1.0             [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo " "
	echo -e $cyellow"	[$cgreen"01"$cyellow]$cgreen  Info"
	echo -e $cyellow"	[$cgreen"02"$cyellow]$cgreen  Process List**"
	echo -e $cyellow"	[$cgreen"03"$cyellow]$cgreen  DLLs"
	echo -e $cyellow"	[$cgreen"04"$cyellow]$cgreen  Services**"
	echo -e $cyellow"	[$cgreen"05"$cyellow]$cgreen  Network**"
	echo -e $cyellow"	[$cgreen"06"$cyellow]$cgreen  Registry**"
	echo -e $cyellow"	[$cgreen"07"$cyellow]$cgreen  Malware**"
	echo -e $cyellow"	[$cgreen"08"$cyellow]$cgreen  Yara"
	echo -e $cyellow"	[$cgreen"09"$cyellow]$cgreen  Manual"
	echo -e $cyellow"	[$cgreen"10"$cyellow]$cgreen  Exit"
	echo -e " "
	echo -ne $cgreen"Pilih Menu : " ; tput sgr0
	read voltrick


	if test $voltrick == '1'
		then
		inpo
	elif test $voltrick == '2'
		then
		process_list
        elif test $voltrick == '3'
		then
		dlls
	elif test $voltrick == '4'
		then
		services
	elif test $voltrick == '5'
		then
		network
	elif test $voltrick == '6'
		then
		registry
	elif test $voltrick == '7'
		then
		malware
	elif test $voltrick == '8'
		then
		yara
	elif test $voltrick == '9'
		then
		manual
	elif test $voltrick == '10'
		then
		stop
		clear
		exit
	else
		clear
		menu
	fi
}

#case
kasus() {
	clear
	clear
	resize -s 25 60 > /dev/null
	banner
	echo -e $cgreen"       [--------------------------------------------]"
	echo -e $cgreen"       [-]	    Muchtar Arif Bastian          [-]"
	echo -e $cgreen"       [-]	         Version 1.0              [-]"
	echo -e $cgreen"       [--------------------------------------------]"
	echo " "
	echo -ne "	Case Name   : " ;tput sgr0
	read nama
	echo -ne "	Auditor     : " ;tput sgr0
	read auditor
	echo -ne "	Memori Name : " ;tput sgr0
	read vname
	tanggal=$(date)
	mkdir -p $nama  2>/dev/null
	dir=$nama
	echo "Detail kasus" > $nama/detail_kasus 2>/dev/null
	echo "" | tee -a $nama/detail_kasus  2>/dev/null
	echo "Case Name 	: $nama" | tee -a $nama/detail_kasus 2>/dev/null
	echo "Date		: $tanggal" | tee -a $nama/detail_kasus 2>/dev/null
	echo "Auditor		: $auditor" | tee -a $nama/detail_kasus 2>/dev/null
	echo "Memori Name	: $vname" | tee -a $nama/detail_kasus 2>/dev/null
	echo ""
	echo "Opening Voltrick"
	sleep 2	
	menu
}

kasus
