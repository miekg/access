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

# EXAMPLES

examples

# ALSO SEE

acl(5) explains the algorithm of `why`.

# TODO

The text output of **why** will like change significantly.
