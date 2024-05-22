%%%
title = "access 1"
area = "Access Control Lists"
workgroup = "ACL File Utilities"
date = 2023-12-18
%%%

# NAME

access - explain how a user has access to a file taking access control lists into account

# SYNOPSIS

**access** **USERNAME** [*FILE...*]

# DESCRIPTION

**Access** will print what access **USERNAME** has on each *FILE*. If Access Control Lists (ACLs) are
set on the file they are taken into account. If no *FILE* is given the current directory is used.
**Access** will always follow symlinks and report on the target.

For each *FILE* given it outputs a line:

    -rw- miek file # ACL_USER_OBJ (owner)

Which states:

`-rw-`

: the first character is 'd' for directories, '-' for files, 'l' for symbolic links, like ls(1). The
next 3 are the *effective* permissions (from the ACL mask) for this user (`r` read, `w` write, `x` execute).

`miek`

: the **USERNAME** given as parameter.

`file`

: the *FILE* currently being printed.

`# ACL_....`

: explanation on why this user access. If this ends `with -rw-` (or any other permissions) it lists
the actual, unmasked permission.

**Access** can output the following:

    -r-- user file # ACL_GROUP (via "xxxxx" with -rw-)
    -r-- user file # ACL_GROUP_OBJ (via "xxxxxx" with -rw-)
    -r-- user file # ACL_USER_OBJ (owner)
    -r-- user file # ACL_USER  (with -rw-)
    -r-- user file # ACL_OTHER

# EXAMPLES

Show the access the *grafana* user has on `file` the masked permissions are equal to the permissions
as expressed in the group ACL.

    % access grafana file
    -rw- grafana file # ACL_GROUP (via "grafana" with -rw-)

# ALSO SEE

acl(5) explains the algorithm of `access`. Use getfacl(1) to lists the ACLs directly.
