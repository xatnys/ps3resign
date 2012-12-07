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

my %params = (	key_revision=>"04",
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

sub processPkg {
	( my $inFile ) = @_;
	my $e_path = $inFile =~ s/.+[\\\/](.+)\..+/extract\/$1\//r; #/

	open FILE, "< :raw", $inFile;
	@file = unpack("C*",join '',<FILE>);
	close FILE;
	
	my %pkgHead;
	my @hfields = qw( magic pkg_type numItems dataOffset dataSize keyA keyB );
	@pkgHead{ @hfields } = unpack('H8L>@20L>@32(H16)(H16)@96(a8)(a8)', pack("C134",@file));
	
	$pkgHead{dataSize} = hex($pkgHead{dataSize});
	$pkgHead{dataOffset} = hex($pkgHead{dataOffset});

	if ($pkgHead{magic} ne "7f504b47") { return 0; }

	if ( !-e $e_path ) { make_path $e_path; }

	my $sha1 = Digest::SHA1->new;
	my $packedKey = $pkgHead{keyA} x 2 . $pkgHead{keyB} x 2;
	my $byte=0;
	my $digest;
	my %blu = map {( sprintf('%02x',$_) => $_ )} (0..255);	
	for (my $x = 0; $x < $pkgHead{dataSize}; $x+=16) {
		$sha1->add($packedKey . pack("x24(H16)", sprintf("%016x",$byte++)));
		$digest = $sha1->hexdigest;
		for (my $i = 0; $i < 16; $i++) {
			@file[$pkgHead{dataOffset}+$x+$i] ^= $blu{substr($digest,$i*2,2)};
		}
	}
	
	$decrypted = pack("C*", @file);
	# saveRaw($decrypted);
	for (my $idx = 0; $idx < $pkgHead{numItems}; $idx++) {
		my %fileEnt;
		my @ffields = qw( nameOffset nameLen dataOffset dataSize flags );
		@fileEnt{@ffields} = unpack(sprintf('@%dL>L>(H16)(H16)L>',$idx*32 + $pkgHead{dataOffset}),$decrypted);

		$fileEnt{name}=unpack(sprintf('@%dA%d',$fileEnt{nameOffset} + $pkgHead{dataOffset},$fileEnt{nameLen}),$decrypted);
		$fileEnt{dataOffset} = hex($fileEnt{dataOffset}) + $pkgHead{dataOffset};
		$fileEnt{dataSize} = hex$fileEnt{dataSize};

		given($fileEnt{flags} & 0xff) {
			when(3) {
				open FILE, "> :raw", $e_path . $fileEnt{name};
				syswrite FILE, unpack(sprintf('@%da%d',$fileEnt{dataOffset},$fileEnt{dataSize}),$decrypted);
				close FILE;
			}
			when(4) { make_path $e_path . $fileEnt{name} }
			default { print "unknown!"; }
		}
	
	}
	return 1;
	sub saveRaw {
		open OUTPUT, "> :raw", "data.raw";
		syswrite OUTPUT, shift;
		close OUTPUT;
		exit;
	}
}

sub processSfo {
	my ( $inFile, $outFile ) = @_;
	
	print "   * Parsing SFO... ";
	open FILE, "< :raw", $inFile or print $! and return 0;
	my @hex = unpack("C*", join '',<FILE>);
	my $file = pack("C*", @hex);
	close FILE;
	
	my %sfoHead;
	my @hfields = qw( magic version keyTbl dataTbl numTblEnt );
	@sfoHead{@hfields} = unpack("(H8)(H8)LLL", pack("C20", @hex)) or return 0;

	if ( $sfoHead{magic} != "00505346" ) { 
		print "   <> Invalid SFO" and return 0;
	}

	my $keyLen;
	my %iTblEnt;
	my @ifields = qw( keyOff fmt len lenmax dataOff keyOffX );
	for (my $i = 0; $i < $sfoHead{numTblEnt}; $i++) {
		@iTblEnt{@ifields} = unpack(sprintf('@%dS(H4)LLLS',$i*16+20), $file);
		if ($i == $sfoHead{numTblEnt}-1) { 
			$keyLen = $sfoHead{dataTbl} - ($sfoHead{keyTbl} + $iTblEnt{keyOff});
		} else {
			$keyLen = $iTblEnt{keyOffX} - $iTblEnt{keyOff};
		}
		$iTblEnt{keyOff}+=$sfoHead{keyTbl};
		$iTblEnt{dataOff}+=$sfoHead{dataTbl};
		$iTblEnt{name} = unpack(sprintf("@%dA%d", $iTblEnt{keyOff}, $keyLen ), $file) =~ s/\000//r;
		if ($iTblEnt{name} eq "PS3_SYSTEM_VER") {
			my @targ = unpack("U0C*", $params{SFOversion});
			for (my $x = 0; $x < $iTblEnt{len}-1; $x++) { #$dataLen = stringLen + 1 null byte
				$hex[$iTblEnt{dataOff}+$x] = $targ[$x];
			}
		}
	}

	open FILE, "> :raw", $outFile;
	syswrite FILE, join'', pack('C*', @hex);
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