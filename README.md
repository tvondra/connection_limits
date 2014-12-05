Setting connection quotas
=========================
This PostgreSQL extension allows you to set connection quotas for each
database, user, IP (or a combination of those values).

Note that the superusers are not restricted by this module - the
connections are counted, but the connection is not denied (just a
WARNING is printed).

PostgreSQL itself provides support for basic per-user and per-database
connection limits:

* http://www.postgresql.org/docs/devel/static/sql-createdatabase.html
* http://www.postgresql.org/docs/devel/static/sql-createuser.html

Use this extension only if you need more sophisticated rules, either
combining rules on both fields, or using additional information (IP
address or hostname).


Install
-------
Installing the extension is quite simple. First you need to do is this:

   $ make install

which installs a library to $libdir (pg_config --pkglibdir).

Now you need to update postgresql.conf so that the shared library is
loaded when the cluster starts.

   shared_preload_libraries = 'connection_limits'

Restart the database (so that the shared library is loaded).


GUC variables
-------------
There are three GUC variables that set basic connection limits

  connection_limits.per_database
  connection_limits.per_user
  connection_limits.per_ip

This allows you to set default per-database, per-user and per-IP limits.
For example by this

  connection_limits.per_user = 5

all users (except superusers - see above) will be allowed to open at
most 5 connections at the same time. The same holds for databases
and IPs.

By default those values are 0 (disabled).

If you need to define some exceptions (e.g. higher values for some of
the users), you can do that quite easily using a rule.


Config
------
The last thing you need to do is to create the configuration file with
rules, defining the connection quotas. The file should be placed in the
data directory, the expected filename is pg_limits.conf.

   $ touch data/pg_limits.conf

and the format is very simple, with four or five columns:

    database     username    IP    [mask]    limit

A special value 'all' means 'do not check' so for example this rule

    all          foouser     all             10

means user 'foouser' can create up to 10 connections in total. He may
be connected to one database or 10 different databases, it does not
matter - he's allowed to create 10 connections in total. This rules

    foodb         all        all             10

means there will be at most 10 connection to the 'foodb' database. You
may of course combine those rules, so this

    foodb         foouser    all             10

means the user 'foouser' can create at most 10 connections to 'foodb'.
Other users are not limited at all, and even 'foouser' may create
unlimited number of connections to other databases.

There are two ways to specify an IP address - the mask may be specified
as part of the IP, or separately. The following two rules are equal

    all    all    all    192.168.1.0/24                    10
    all    all    all    192.168.1.0      255.255.255.0    10

So basically it's just like in pg_hba.conf.


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
If you want to see the current status of limits, use 'connection_limits'
view. Just do this:

  db=# select * from conneection_limits;

and you'll see which limits are almost exhausted etc.