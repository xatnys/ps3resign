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
use Digest::SHA1;

my $sha1=Digest::SHA1->new;
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
my $in = shift or print "no input specified" and exit;
if ( -e $in && $in =~ m/.+(\.pkg)/ ) {
	my $full = abs_path $in;
	if (!processPkg($full)) { 
		print "failed to extract pkg." and exit; 
	}
	$in = $full =~ s/.+[\\\/](.+)\..+/extract\/$1\//r;
}

find({ wanted => \&process, no_chdir => 1 }, $in);
sub process {
	my ( $new_dir, $ext ) = undef;
	my $dir = $File::Find::dir;
	my $base = $_;
	my $full = $File::Find::name;
	if ( $dir eq "./" || $dir eq "\\." ) {
		$new_dir = "output/"; 
	} else { 
		( $new_dir = $dir ) =~ s/extract\/?([^\/.]+)\/?/output\/$1_OUT\//;	
		print $new_dir;
	}
	
	if ( !-e $new_dir ) {
		print "old dir: $dir | new dir: $new_dir";
		make_path($new_dir);
	}
	
	if ( -f $full ) {
		print "processing $base...";
		my @file = ( $base =~ /.+[\\\/](.+)\.(.+)/ );
		$new_dir.="/$file[0].$file[1]";
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
	return hex join '', @_;
}
sub hexFromBytesBE {
	return hex join '',reverse @_;
}

sub processPkg {
	( my $file ) = @_;
	my $e_path = $file =~ s/.+[\\\/](.+)\..+/extract\/$1\//r;
	
	open FILE, "< :raw", $file or print $! and return 0; # always open non-text files as raw/binary!!
	my @hex =  unpack "(H2)*", join ("",<FILE>) ;
	close FILE;
	if ( !@hex || join("",@hex[0..3]) ne "7f504b47" ) { return 0; }

	if ( !-e "extract/") { make_path "extract"; }
	if ( !-e $e_path ) { make_path $e_path; }

	my $dataOffset = hexFromBytes(@hex[0x20..0x27]);
	my $dataSize = hexFromBytes(@hex[0x28..0x2F]);
	my $numFiles = hexFromBytes(@hex[0x14..0x17]);
	
	my $cur = 0x00;
	@key = ( @hex[0x60..0x67], @hex[0x60..0x67], @hex[0x68..0x6F], @hex[0x68..0x6F], (0x00) x 24 );
	$packedKey = pack("(H2)*", @key);
	$packedAddr = pack("(H2)*", sprintf("%16x",$cur) =~ m/../g);
	$sha1->add($packedKey . $packedAddr);
	my @digest = $sha1->hexdigest =~ m/../g;
	
	for (my $idx = 0; $idx < $dataSize ; $idx++) {
		if ($idx != 0 && $idx % 16 == 0) {
			$packedAddr = pack("(H2)*", sprintf("%16x",++$cur) =~ m/../g);
			$sha1->add($packedKey . $packedAddr);
			@digest = $sha1->hexdigest =~ m/../g;
		}
		$hex[$dataOffset+$idx] = unpack("(H2)*",pack("(H2)*",$hex[$dataOffset+$idx]) ^ pack("(H2)*",$digest[$idx & 0xf]));
	}

	for (my $idx = 0; $idx < $numFiles; $idx++) { 
		my $dOff = $dataOffset+32*$idx;
		$fNameOff = $dataOffset + hexFromBytes(@hex[$dOff..$dOff+3]);
		$fNameLen = hexFromBytes(@hex[$dOff+4..$dOff+7]) - 1;
		$fDataOff = $dataOffset + hexFromBytes(@hex[$dOff+8..$dOff+15]);
		$fDataSize = hexFromBytes(@hex[$dOff+16..$dOff+23]) -1;
		$flags = join "",@hex[$dOff+24..$dOff+27];
		$fName = unpack("U0a*",pack("(H2)*", @hex[$fNameOff..$fNameOff+$fNameLen])) =~ s/\000//r; # strip trailing null
		given($flags & 0xff) {
			when(3) {
				open FILE, "> :raw", $e_path . $fName;
				syswrite FILE, pack("(H2)*", @hex[$fDataOff..$fDataOff+$fDataSize]);
				close FILE;
			}
			when(4) { make_path $e_path . $fName }
			default { print "unknown!"; }
		}
	}
	return 1;
}
sub processSfo {
	my ( $inFile, $outFile ) = @_;
	if ( -e $inFile ) {
		open FILE, "< :raw", $inFile or print $! and return 0;
	} else {
		print "No input file specified."; return 0;
	}
	my @hex = ( ( unpack "H*", join("",<FILE>) ) =~ m/../g  );
	close FILE;

	if ( join("",@hex[0..3]) != "00505346" ) { 
		print "   <> Invalid SFO"; return 0;
	}
	print "   * Parsing SFO... ";
	
	my $index_table_N = hexFromBytesBE(@hex[0x10..0x13]);
	my $index_table_size = 0x10;
	my $index_table_start = 0x14;
	my $key_table_start = hexFromBytesBE(@hex[0x08..0x0b]);
	my $data_table_start = hexFromBytesBE(@hex[0x0c..0x0f]);

	for (my $curByte = $index_table_start; $curByte < $index_table_start + $index_table_N*$index_table_size; $curByte+=$index_table_size ) {
		if ( $curByte + $index_table_start <= $index_table_start + $index_table_N*$index_table_size ) {
			$keyWidth = hex($hex[$curByte + $index_table_size]) - hex($hex[$curByte]) - 1;
			if ( $keyWidth == 14 ) { 
				$keyOffset = hex($hex[$curByte+1] . $hex[$curByte]);
				$keyAddr = $key_table_start+$keyOffset;

				if ( join("",map chr(hex($_)), @hex[$keyAddr..$keyAddr+$keyWidth-1]) eq "PS3_SYSTEM_VER") {

					$dataAddr = hexFromBytesBE(@hex[$curByte+12..$curByte+15]);
					$dataOffset = $data_table_start+$dataAddr;
					$dataLen = hexFromBytesBE(@hex[$curByte+4..$curByte+7]);
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

	open FILE, "> :raw", $outFile;
	syswrite FILE, join'',@bytes;
	close FILE;

	return 1;
}

sub processSelf {
	my ( $inFile, $outFile ) = @_;
	my $base = basename($inFile);
	my $tmp = "tmp/" . dirname($inFile);
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

	my $bp = "-v -s FALSE -0 $params{computed_type} -1 $params{compress_data} -2 $params{key_revision} -3 $params{auth_id} -4 $params{vendor_id} -A $params{app_version} -6 $params{fw_version} -5 $params{self_type} ";
	if ($params{self_type} eq "NPDRM") {
		print "   * NPDRM cid: $params{CID}";
		$bp .= "-b FREE -c EXEC -f $params{CID} -g $base";
	}

	system("$scetool $bp -e \"$tmp/$base.OUT\" \"$outFile\"" . $log);

	return 1;
}