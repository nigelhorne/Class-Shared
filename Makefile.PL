use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME             => 'Class::Shared',
	VERSION_FROM     => 'lib/Class/Shared.pm',
	ABSTRACT         => 'Share one instance of a class between processes over a socket',
	AUTHOR           => 'Nigel Horne',
	LICENSE          => 'perl_5',
	MIN_PERL_VERSION => '5.010',
	EXE_FILES        => ['bin/class-shared'],
	PREREQ_PM        => {
		'Digest::SHA'      => 0,
		'File::Basename'   => 0,
		'File::Spec'       => 0,
		'Fcntl'            => 0,
		'Getopt::Long'     => 0,
		'IO::Socket::UNIX' => 0,
		'POSIX'            => 0,
		'Socket'           => 0,
		'Storable'         => 0,
	},
	TEST_REQUIRES    => {
		'File::Temp' => 0,
		'Test::More' => '0.98',
	},
	META_MERGE       => {
		resources => {
			license => 'https://dev.perl.org/licenses/',
		},
	},
);
