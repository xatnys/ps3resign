#!/usr/bin/perl -wl

# Copyright (C) 2012 xatnys <xatnys@gmail.com>
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

use File::Find;
use File::Path "make_path";
use File::Copy;
use feature 'switch';

my %params = ( 	key_revision=>"04",
				fw_version=>"0003004000000000",
				auth_id=>"1010000001000003",
				vendor_id=>"01000002",
				self_type=>"APP",
				app_version=>"0001000000000000"	
			);

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
				print "Parsing SFO... "; if (!processSfo($base,$new_dir)) { next }
			}
			when (/(bin|self)/) {
				if (!processSelf($base,$new_dir)) { next }
			}
			when (/.*/) {
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
		print "Invalid SFO"; return 0;
	}

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
					my @targ = (unpack "H*", "03.4000") =~ m/../g;
					for (my $curByte2 = 0; $curByte2 < $dataLen; $curByte2++) {
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

}

sub processSelf {
	use File::Basename;
	my ( $inFile, $outFile ) = @_;

	$base=basename($inFile);
	$tmp="tmp/" . dirname($inFile);
	if ( !-e $tmp ) { 
		make_path($tmp); 
	}
	my $log = " &>> scetool.log";
	system("./scetool.exe -i \"$inFile\" > $tmp/$base.INFO");
	$params{'computed_type'}=`grep -oP '^\\sHeader Type\\s*\\[\\K\\w+(?=\\])' $tmp/$base.INFO`; #we end up with trailing whitespace that needs to be stripped here
	$params{'computed_type'} =~ s/^\s+|\s+$//g;
	print $params{'computed_type'};
	if ( !length($params{'computed_type'}) ) { print "false self"; return 0; }

	print "* decrypting SELF to $tmp";
	system("./scetool.exe -d \"$inFile\" \"$tmp/$base.OUT\"" . $log);

	$boilerplate="./scetool.exe -v -s FALSE -0 $params{'computed_type'} -2 $params{'key_revision'} -3 $params{'auth_id'} -4 $params{'vendor_id'} -A $params{'app_version'} -6 $params{'fw_version'}";
	system($boilerplate . " -5 $params{self_type} -e \"$tmp/$base.OUT\" \"$outFile\"" . $log);

	return 1;
}