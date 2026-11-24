package Shared::Counter;

# A small target class used by the test suite.  It remembers which process
# constructed it so that tests can prove there really is only one object.

use strict;
use warnings;

our $CONSTRUCTED = 0;

sub new {
	my ($class, %opt) = @_;

	$CONSTRUCTED++;

	return bless {
		value     => defined $opt{start} ? $opt{start} : 0,
		tag       => $opt{tag},
		pid       => $$,
	}, $class;
}

sub value     { $_[0]->{value} }
sub tag       { $_[0]->{tag} }
sub pid       { $_[0]->{pid} }
sub constructed { $CONSTRUCTED }

sub inc {
	my $self = shift;
	$self->{value} += @_ ? shift : 1;
	return $self->{value};
}

sub add {
	my $self = shift;
	my $total = 0;
	$total += $_ for @_;
	$self->{value} += $total;
	return $self->{value};
}

sub triple     { return (1, 2, 3) }
sub empty_list { return () }
sub one        { return 'one' }

sub echo_list {
	my $self = shift;
	return @_;
}

sub maybe_undef { return undef }

sub boom {
	my $self = shift;
	die "kaboom: @_";
}

1;
