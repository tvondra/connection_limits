connection_limits
=================

This PostgreSQL extension allows you to set connection quotas based on
database, user, IP (or a combination of those values).

Note that the superusers are not restricted by this module - the
connections are counted, but the connection is not denied (just a
WARNING is printed). So for example if there's a database with a limit
of 5 connections, there may be 10 superusers connected to it (and no
connections from regular users will be allowed until at least 6 of
those superusers disconnect).

PostgreSQL itself provides built-in support for basic per-user and
per-database connection quotas - see the `CONNECTION LIMIT` option
available for corresponding commands:

* http://www.postgresql.org/docs/devel/static/sql-createdatabase.html
* http://www.postgresql.org/docs/devel/static/sql-createuser.html

Use this extension only if you need more sophisticated rules, either
combining rules on both fields, or based on IP address / hostname
(which is not available in the core).


Limitations
-----------

The extension evaluates the quotas using the user/database name supplied
at connection time, and stores them internally. If you rename the user
or a database, the extension has no idea about this change.

Renaming a database is not a big issue, though, because that requires
closing all connections, but it may be a problem when renaming users.

This limination is however a natural consequence of storing the rules
in a static file, using the user/database names (and not OID). Whenever
you rename a user, you need to modify the file and restart the database.

It's possible to implement the reloading without a cluster restart (let
me know if you're interested in the functionality).

If we ever get even triggers for the `ALTER USER` command, it might be
possible to handle the renames automatically, but it's rather tricky
(think of race conditions that could happen).

If you need to rename users frequently, this extension is probably not
the extension you're looking for - the built-in `CONNECTION LIMIT`
option might be a better solution for you.


Installation
------------

The easiest way is to install this extension from PGXN, which is as
simple as this

    $ pgxnclient load -d mydb connection_limits

Now you need to update `postgresql.conf` so that the shared library is
loaded when the cluster starts (so that it can request space in shared
memory segment, etc.).

    shared_preload_libraries = 'connection_limits'

This change requires a restart of the cluster (the library needs to
request space in shared memory, and that can only happen when starting
the cluster). You need to define the quota rules first, however.

Instead of using the PGXN client, you may also install the extension
from sources, which is almost as simple as using `pgxnclient`. First
obtain the sources somehow (e.g. by cloning the github repository),
and then do is this:

    $ make install

which installs a library to $libdir (pg_config --pkglibdir). Then just
update the `shared_preload_libraries` as explained.


GUC variables
-------------

There are three GUC variables that allow you to specify default rules

    connection_limits.per_database
    connection_limits.per_user
    connection_limits.per_ip

This allows you to set default per-database, per-user and per-IP limits.
For example with this configuration

    connection_limits.per_user = 5

all users (except superusers - see above) will be allowed to open at
most 5 connections at the same time. Similarly for databases and IPs.

By default those values are 0 (which means there is no default quota).

The rules in the configuration file (explained in the next section)
take precendence over the defaults. So you may define a default using
a GUC variable, and then define some exceptions (e.g. higher values for
some databases or users) using a targetted rule.


Configuration
-------------

The quota rules are read from a configuration file `pg_limits.conf`,
placed in the data directory. You may create it using like this:

    $ touch data/pg_limits.conf

The format is very simple, resembling `pg_hba.conf` a bit, with either
four or five columns (the `mask` column is optional):

    database     username    IP    [mask]    limit

A special value 'all' means 'do not check this field' so for example

    all          foouser     all             10

means user 'foouser' can create up to 10 connections in total. He may
open 10 connections to one database or 10 different databases, it does
not matter - he's allowed to create 10 connections in total. This rule

    foodb         all        all             10

means there will be at most 10 connection to the 'foodb' database,
irrespectedly what user opens it, what is the source IP address etc.

You may of course combine those fields, so a rule like this

    foodb         foouser    all             10

means the user 'foouser' can create at most 10 connections to 'foodb'.
Other users are not limited at all, and even 'foouser' may create
unlimited number of connections to other databases. (Well, it's not
exactly unlimited, there can't be more than `maxconnections` connections
in total, but it's not limited by this extension.)

So far none of the rules specified an IP address. There are two ways to
do that - the mask may be specified as part of the IP, or separately.
For example, these two rules are exactly the same:

    all    all    all    192.168.1.0/24                    10
    all    all    all    192.168.1.0      255.255.255.0    10

It's possible to specify a hostname too, which is useful when the IP
may change etc. Again, this is exactly like `pg_hba.conf`.


Combining GUC variables and rules
---------------------------------
Whenever a GUC variable and a rule collide, the rule takes precedence.
I.e. if you set per_user=4 and then define this rule

    all          foouser     all             10

then all the users except 'foouser' will have 4 connections at most,
and 'foouser' will be allowed to create 10.

The same holds for per_database and rules like this

    foodb        all         all             10

and per_ip and rules like this

    all          all         127.0.0.1/32    10

So to override the default limit, there needs to be a single field
specified - user, database or IP.


Current state of limits
-----------------------
If you want to see the current state of the rules (how many connections
match each rule), use 'connection_limits' view. Just do this:

    db=# select * from conneection_limits;

and you'll see which quotas are almost reached, etc.
