use strict;
use warnings;

use ExtUtils::MakeMaker;
use FindBin ();

# The distribution installs anywhere on purpose.  Class::Shared::Protocol is
# pure Perl and can talk to a backend from a machine that cannot run one, so
# refusing here would take away the half that works -- and would leave a
# platform like Windows with nothing to report but a failed install.  What
# cannot work refuses when it is used; say so here too, so the first
# Class::Shared::Frontend->new is not the surprise.
my $has_unix_sockets = eval {
	require File::Spec;

	my $module = File::Spec->catfile($FindBin::Bin, 'lib', 'Class', 'Shared.pm');
	require $module;

	Class::Shared::_has_unix_sockets();
};

if (defined $has_unix_sockets && !$has_unix_sockets) {
	print STDERR <<'NOTICE';
Class::Shared: this perl has no unix domain sockets, so Class::Shared::Backend,
Class::Shared::Frontend and bin/class-shared will refuse to run on it (see
PLATFORMS).  Installing anyway: Class::Shared::Protocol is pure Perl and can
talk to a backend running elsewhere.
NOTICE
}

WriteMakefile(
	NAME             => 'Class::Shared',
	VERSION_FROM     => 'lib/Class/Shared.pm',
	ABSTRACT         => 'Share one instance of a class between processes over a socket',
	AUTHOR           => 'Nigel Horne',
	LICENSE          => 'perl_5',
	MIN_PERL_VERSION => '5.010',
	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker' => '6.64',
	},
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
		'Time::HiRes'      => 0,
	},
	TEST_REQUIRES    => {
		'File::Temp'          => 0,
		'IO::Socket::SSL'     => 0,
		'Lingua::Conjunction' => 0,
		'Test::More'          => '0.98',
	},
	META_MERGE       => {
		'meta-spec' => {
			version => 2,
		},
		prereqs => {
			runtime => {
				# Loaded only when a TCP listener or client is used;
				# a unix socket never needs it.
				recommends => {
					'IO::Socket::SSL' => '2.0',
				},
			},
			develop => {
				requires => {
					# Needed only to regenerate README.md from the POD.
					'Pod::Github' => '0.04',
				},
			},
		},
		resources => {
			license => 'https://dev.perl.org/licenses/',
		},
	},
);

# README.md is generated from the POD by Pod::Github's pod2github: it is the
# converter that reproduces the committed style.  Never edit README.md by hand
# -- change the POD in lib/Class/Shared.pm and run "make readme".
sub MY::postamble {
	return <<'MAKE_FRAG';

.PHONY: readme

readme:
	$(SHELL) maint/regen-readme
MAKE_FRAG
}
