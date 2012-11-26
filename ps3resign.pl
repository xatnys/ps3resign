#!/usr/bin/perl -wl

# Copyright (C) 2012 xatnys <xatnys@gmail.com>
#
# Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0


use File::Find;
use File::Path "make_path";
use File::Copy;
use File::Basename;
use Cwd "abs_path";
use feature 'switch';

my %params = ( 	key_revision=>"04",
				fw_version=>"0003004000000000",
				auth_id=>"1010000001000003",
				vendor_id=>"01000002",
				self_type=>"APP",
				app_version=>"0001000000000000",
				compress_data=>"TRUE",
				computed_type=>undef,
				CID=>undef,
				SFOversion=>"03.4000"
			);
my $scetool = undef;
if ( !-e "scetool.exe" ) {
	die "error: scetool.exe not found\n";
} else {
	$scetool = abs_path("scetool.exe");
}

if (scalar @ARGV > 1) { 
	$params{CID}=shift;
}

$file = shift or die "no input specified";

find({ wanted => \&process, no_chdir => 1 }, $file);
sub process {
	my ( $new_dir, $ext ) = undef;
	my $dir = $File::Find::dir;
	my $base = $_;
	my $full = $File::Find::name;
	if ( $dir eq "./" || $dir eq "\\." ) {
		$new_dir = "output/"; 
	} else { 
		( $new_dir = $dir ) =~ s/([^\/.]+)\/?/output\/$1_OUT\//;	
	}
	
	if ( !-e $new_dir ) {
		print "old dir: $dir | new dir: $new_dir";
		make_path($new_dir);
	}
	
	if ( -f $full ) {
		print "processing $base...";
		@file = ( $base =~ /.+\/(.+)\.(.+)/ );
		$new_dir.="/$file[0].$file[1]";
		# print "filename: $file[0]\nextension: $file[1]";
		given (lc($file[1])) {
			when ("sfo") { 
				if (!processSfo($base,$new_dir)) { continue }
			}
			when (/(bin|self)/) {
				if (!processSelf($base,$new_dir)) { continue }
			}
			default { 
				print "   * copying normal file ($file[0].$file[1])";
				copy($full,$new_dir);
			}
		}
	}
}

sub hexFromBytes {
	return hex join '',reverse @_;
}
sub processSfo {
	my ( $inFile, $outFile ) = @_;
	if ( -e $inFile ) {
		open FILE, $inFile or print $! and return 0;
	} else {
		print "No input file specified."; return 0;
	}
	my @hex = ( ( unpack "H*", join("",<FILE>) ) =~ m/../g  );
	close FILE;

	if ( join("",@hex[0..3]) != "00505346" ) { 
		print "   <> Invalid SFO"; return 0;
	}
	print "   * Parsing SFO... ";
	
	my $index_table_N = hexFromBytes(@hex[0x10..0x13]);
	my $index_table_size = 0x10;
	my $index_table_start = 0x14;
	my $key_table_start = hexFromBytes(@hex[0x08..0x0b]);
	my $data_table_start = hexFromBytes(@hex[0x0c..0x0f]);

	for (my $curByte = $index_table_start; $curByte < $index_table_start + $index_table_N*$index_table_size; $curByte+=$index_table_size ) {
		if ( $curByte + $index_table_start <= $index_table_start + $index_table_N*$index_table_size ) {
			$keyWidth = hex($hex[$curByte + $index_table_size]) - hex($hex[$curByte]) - 1;
			if ( $keyWidth == 14 ) { 
				$keyOffset = hex($hex[$curByte+1] . $hex[$curByte]);
				$keyAddr = $key_table_start+$keyOffset;

				if ( join("",map chr(hex($_)), @hex[$keyAddr..$keyAddr+$keyWidth-1]) eq "PS3_SYSTEM_VER") {

					$dataAddr = hexFromBytes(@hex[$curByte+12..$curByte+15]);
					$dataOffset = $data_table_start+$dataAddr;
					$dataLen = hexFromBytes(@hex[$curByte+4..$curByte+7]);
					# print "found PS3_SYSTEM_VER @ $keyAddr | dataOffset: $dataOffset | value: " . join("",map chr(hex) , @hex[$dataOffset..$dataOffset+$dataLen-1]);
					my @targ = (unpack "H*", $params{SFOversion}) =~ m/../g;
					for (my $curByte2 = 0; $curByte2 < $dataLen-1; $curByte2++) { #$dataLen = stringLen + 1 null byte
						$hex[$dataOffset+$curByte2] = $targ[$curByte2];
					}
					# print "new value: " . join("", map(chr(hex($_)), @hex[$dataOffset..$dataOffset+$dataLen-1]));
				}
			}
		}
	}
	
	my @bytes = map pack('C', hex($_)), @hex;

	open FILE, ">", $outFile;
	binmode FILE;
	syswrite FILE, join'',@bytes;
	close FILE;

	return 1;
}

sub processSelf {
	my ( $inFile, $outFile ) = @_;
	my $base=basename($inFile);
	my $tmp="tmp/" . dirname($inFile);
	my $log = ( $^O eq "MSWin32" ) ? " >> scetool.log" : " &>> scetool.log";

	if ( !-e $tmp ) { 
		make_path("$tmp"); 
	}

	system("$scetool -i \"$inFile\" > \"$tmp/$base.INFO\"");

	open INFO, "<", "$tmp/$base.INFO" or die $!;
	while ( defined( my $line = <INFO> ) ){
	 	if ( $line =~ m/\sHeader Type\s+\[(\w+)\]/ ) {
	 		chomp( $params{computed_type} = $1 );
	 	}
	 	if ( $line =~ m/\sSELF-Type\s\[(\w+)\s\w+\]/ ) {
	 		$params{self_type} = "NPDRM";
	 	}
	 	if ( !defined($params{CID}) && $line =~ m/\sContentID\s+(\S+)/) {
	 		chomp( $params{CID} = $1 );
	 	}
	}
	close INFO;

	if ( !defined($params{computed_type}) ) {
		return 0; 
	} else {
		print "   * decrypting $params{computed_type} to $tmp";
		system("$scetool -d \"$inFile\" \"$tmp/$base.OUT\"" . $log);
	}

	my $bp="-v -s FALSE -0 $params{computed_type} -1 $params{compress_data} -2 $params{key_revision} -3 $params{auth_id} -4 $params{vendor_id} -A $params{app_version} -6 $params{fw_version} -5 $params{self_type} ";
	if ($params{self_type} eq "NPDRM") {
		print "   * NPDRM cid: $params{CID}";
		$bp.="-b FREE -c EXEC -f $params{CID} -g $base";
	}

	system("$scetool $bp -e \"$tmp/$base.OUT\" \"$outFile\"" . $log);

	return 1;
}