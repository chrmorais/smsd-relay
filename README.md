smsd-relay
==========

This is SMS relaying from Gammu-SMSD into web services,
and injecting SMS from web services into Gammu-SMSD spool.

### install

It is copied from a Linux server environment where an MC55iT device is used for SMS receiving.
You probably need to adjust settings, like udev symlinks for connected devices, and feed URLs.

Feed configuration is done via an embedded database.

### requirements

It requires to have installed SMSD daemon of Gammu software package, with SQLite3, for SMS taking,
and Python for the actual relaying into and injecting from web services.

