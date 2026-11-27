package LateWrite;

# Makes every Class::Shared write wait first, so that a backend which closes
# without waiting for its client has done so before the client writes.  Loading
# this changes nothing until $LateWrite::DELAY, or LATE_WRITE in the
# environment, gives the seconds to wait.

use strict;
use warnings;

use Class::Shared::Protocol ();

our $DELAY = $ENV{LATE_WRITE} || 0;

my $write_all = \&Class::Shared::Protocol::write_all;

{
	no warnings 'redefine';

	*Class::Shared::Protocol::write_all = sub {
		select(undef, undef, undef, $DELAY) if $DELAY;
		return $write_all->(@_);
	};
}

1;
