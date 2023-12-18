%%%
title = "why 1"
area = "Access Control Lists"
workgroup = "ACL File Utilities"
date = 2023-12-18
%%%

# NAME

why - explain why a user has access to a file taking access control lists into account

# SYNOPSIS

**why** **USERNAME** [*FILE...*]

# DESCRIPTION

**Why** will print what access **USERNAME** has on each *FILE*. If Access Control Lists (ACLs) are
set on the file they are taking into account. If no *FILE* is given the current directory is used.
For each *FILE* given it outputs a line:

    -rw- miek file # ACL_USER_OBJ (owner)

Which states:

`-rw-`

: the first character is 'd' for directories and '-' for files. Like ls(1). The next 3 are the
effective permissions (from the mask) for this user (read, write, execute).

`miek`

: the **USERNAME** given as parameter.

`file`

: the *FILE* currently being printed.

`# ACL_....`

: explanation on why this user access. If this ends `with -rw-` (or any other permissions) it lists
the actual (unmasked) permission.

**Why** can output the following:

    -r-- user file # ACL_GROUP (via "xxxxx" with -rw-)
    -r-- user file # ACL_GROUP_OBJ (via "xxxxxx" with -rw-)
    -r-- user file # ACL_USER_OBJ (owner)
    -r-- user file # ACL_USER  (with -rw-)
    -r-- user file # ACL_OTHER

# EXAMPLES

Show the access the *grafana* user has on `file` the masked permissions are equal to the permission
as expressed in the group ACL.

    % why grafana file
    -rw- grafana file # ACL_GROUP (via "grafana" with -rw-)

# ALSO SEE

acl(5) explains the algorithm of `why`.
