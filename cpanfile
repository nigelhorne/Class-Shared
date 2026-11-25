# Generated from Makefile.PL using makefilepl2cpanfile

requires 'perl', '5.026';

requires 'Digest::SHA';
requires 'Fcntl';
requires 'File::Basename';
requires 'File::Spec';
requires 'Getopt::Long';
requires 'IO::Socket::UNIX';
requires 'POSIX';
requires 'Socket';
requires 'Storable';
requires 'Time::HiRes';
recommends 'IO::Socket::SSL', '2.0';

on 'configure' => sub {
	requires 'ExtUtils::MakeMaker', '6.64';
};

on 'test' => sub {
	requires 'File::Temp';
	requires 'IO::Socket::SSL';
	requires 'Lingua::Conjunction';
	requires 'Test::DescribeMe';
	requires 'Test::More', '0.98';
	requires 'Test::Permissions';
};

on 'develop' => sub {
	requires 'Devel::Cover';
	requires 'Perl::Critic';
	requires 'Pod::Github', '0.04';
	requires 'Test::Pod';
	requires 'Test::Pod::Coverage';
};
