To install, run:
```
make install TREE=<name>
```

For the permissions of each part of the tree, I decided to create a group called "mailer" which would have the ability to handle the writing of mail within the tree. As such, I made the group of everything within the tree "mailer", and adjusted the permissions such that mail-in and mail-out had sufficient permissions for reading, verifying, and distributing mail.

mail-in is privileged as its setgid bit is set. By setting its setgid bit, mail-in is able to call mail-out, another privileged program. While similarly privileged, mail-out, unlike mail-in, is not executable by other.

Below are the permissions I set for the various aspects of the tree.

tree:		root mailer: 	rwxr-xr-x	u=rwx,g=rx,o=rx

bin:		root mailer: 	rwxr-xr-x	u=rwx,g=rx,o=rx
- mail-in:	root mailer: 	rwx--s--x	u=rwx,g=sx,o=x
- mail-out:	root mailer: 	rwx--x---	u=rwx,g=x,o=
mail:		root mailer: 	rwxr-xr-x	u=rwx,g=rx,o=rx
- mailboxes:	<owner> mailer: rwx-wx---	u=rwx,g=wx,o=
tmp:		root mailer: 	rwxr-xr-x	u=rwx,g=rx,o=rx

My solution requires the additional group: mailer.
