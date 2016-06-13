# bruteforce-wallet

The purpose of this program is to try to find the password of an encrypted
Peercoin (or Bitcoin, Litecoin, etc...) wallet file (i.e. wallet.dat).

It can be used in two ways:

 - try all the possible passwords given a charset
 - try all the passwords in a file

There is a command line option to specify the  number of threads to use.

Sending a USR1 signal to a running bruteforce-wallet process makes it print
progress and continue.


## Exhaustive mode

The program tries to decrypt one of the encrypted addresses in the wallet by
trying all the possible passwords. It is especially useful if you know
something about the password (i.e. you forgot a part of your password but still
remember most of it). Finding the password of a wallet without knowing
anything about it would take way too much time (unless the password is really
short and/or weak).

There are command line options to specify:

 - the minimum password length to try
 - the maximum password length to try
 - the beginning of the password
 - the end of the password
 - the character set to use (among the characters of the current locale)


## Dictionary mode

The program tries to decrypt one of the encrypted addresses in the wallet by
trying all the passwords contained in a file. The file must have one password
per line.


## Dependencies

The program requires the OpenSSL and BerkeleyDB libraries.


## Limitations

The program currently only works on unix-like POSIX systems (e.g. GNU/Linux).

Different versions of BerkeleyDB are usually not compatible with each other.
Therefore, for the program to work, you will have to check that the BerkeleyDB
version you are using can read the databases created by the BerkeleyDB version
your wallet was created with.


## Examples

Try to find the password of an encrypted wallet file using 4 threads, trying
only passwords with 5 characters:

    bruteforce-wallet -t 4 -l 5 -m 5 wallet.dat


Try to find the password of an encrypted wallet file using 8 threads, trying
only passwords with 5 to 10 characters beginning with "W4l" and ending with "z":

    bruteforce-wallet -t 8 -l 5 -m 10 -b "W4l" -e "z" wallet.dat


Try to find the password of an encrypted wallet file using 8 threads, trying
only passwords with 10 characters using the character set "P情8ŭ":

    bruteforce-wallet -t 8 -l 10 -m 10 -s "P情8ŭ" wallet.dat


Try to find the password of an encrypted wallet file using 6 threads, trying
the passwords contained in a dictionary file:

    bruteforce-wallet -t 6 -f dictionary.txt wallet.dat


Print progress info:

    pkill -USR1 -f bruteforce-wallet


## Donations

If you find this program useful and want to make a donation, you can send coins
to one of the following addresses:

 - Peercoin: PWFNV1Cvq7nQBRyRueuYzwmDNXUGpgNkBC
 - Bitcoin: 1F1ZfM7XtggHsShK4vwuy9zv98a9wt7nXx
