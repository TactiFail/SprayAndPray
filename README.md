# SprayAndPray

Multi-protocol password-spraying utility.  Very alpha currently.

## Setup

You will need to install a few Python libraries:

```
pip install requests pexpect pysmb
```

## Usage

```
./sprayandpray.py -h

 ~~~~~~~~~~~~~~~~~~~~~~~~~
/   SprayAndPray v0.2.0   \
\      by @TactiFail      /
 +++++++++++++++++++++++++

usage: ./sprayandpray.py -s <servers> -u <user> [-t <protocols>] [-p <password>]

Multi-protocol password-spraying tool

Required arguments:
  -s SERVERS     Comma-separated list of IPs or hostnames to spray against
  -u USERNAME    Username to spray

Optional arguments:
  -p [PASSWORD]  Password to spray (will be prompted if missing or empty)
  -t PROTOCOLS   Comma-separated list of protocols to test (defaults to all)
                 Supported options: all,smb,ssh,ftp,http,https
  -b             Display bad passwords as well as good

Example: ./sprayandpray.py -s 192.168.1.100 -u root -t smb,ssh -p Winter2017
```

## Examples

Single target, all protocols:

```
./sprayandpray.py -s 10.0.0.150 -u root

 ~~~~~~~~~~~~~~~~~~~~~~~~~
/   SprayAndPray v0.2.0   \
\      by @TactiFail      /
 +++++++++++++++++++++++++

Enter the password to spray:

  Servers:   10.0.0.150
  User:      root
  Pass:      toor
  Protocols: all

Spraying against all protocols...

Attempting SMB login -  root:toor@10.0.0.150
  SMB login succeeded!
Attempting SSH login -  root:toor@10.0.0.150
  SSH login failed...
Attempting FTP login - root:toor@10.0.0.150
  FTP login failed...
Attempting HTTPS login - root:toor@10.0.0.150
  HTTP appears to be in use, trying that instead...
  HTTP login failed...
Attempting HTTP login - root:toor@10.0.0.150
  HTTP login failed...

Summary of working credentials (protocol, hostname, username, password):

('SMB', '10.0.0.150', 'root', 'toor')
```

Multiple targets, one protocol, showing bad creds:

```
./sprayandpray.py -s 10.0.0.100,10.0.0.150 -u root -t ssh -b

 ~~~~~~~~~~~~~~~~~~~~~~~~~
/   SprayAndPray v0.2.0   \
\      by @TactiFail      /
 +++++++++++++++++++++++++

Enter the password to spray:

  Servers:   10.0.0.150, 10.0.0.100
  User:      root
  Pass:      toor
  Protocols: ssh

Spraying against ssh.

Attempting SSH login -  root:toor@10.0.0.150
  SSH login failed...
Attempting SSH login -  root:toor@10.0.0.100
  SSH login failed...

No credentials worked  :(

Summary of failing credentials (protocol, hostname, username, password):

('SSH', '10.0.0.150', 'root', 'toor')
('SSH', '10.0.0.100', 'root', 'toor')
```

## Known Issues

* These are very naive checks, so expect false positives/negatives and please report any bugs you find.
* Telnet spraying is not currently available.  I am not aware of a standardized way to check for failed logins.
* SMB checks do not allow for a domain to be specified (it's on the [TODO list](https://github.com/TactiFail/SprayAndPray/blob/master/TODO.md)).
* Ports are not checked to see if they are open before trying to auth, which may cause a timeout - use `Ctrl-C` to break a hanged check.  A reasonable 10-second timeout has been added to checks as-needed. ([Issue #3](https://github.com/TactiFail/SprayAndPray/issues/3))
