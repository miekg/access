package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/joshlf/go-acl"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s USERNAME [FILE]...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Show why USERNAME can or cannot access FILEs (the current directory by default)\n")

		flag.PrintDefaults()
	}

	cmd := filepath.Base(os.Args[0])

	flag.Parse()
	username := flag.Arg(0)
	path := flag.Arg(1)

	if username == "" {
		log.Fatalf("%s: missing user", cmd)
	}
	u, err := user.Lookup(username)
	if err != nil {
		log.Fatalf("%s: no such user: %q: %s", cmd, username, err)
	}

	groupids, err := u.GroupIds()
	if err != nil {
		log.Fatalf("%s: cannot get group IDs for %q: %s", cmd, username, err)
	}

	if path == "" {
		log.Fatalf("%s: missing path", cmd)
	}

	a, err := acl.Get(path)
	if err != nil {
		log.Fatalf("%s: cannot get acl: %q: %s", cmd, path, err)
	}

	m, err := aclToMap(a, path)
	if err != nil {
		log.Fatalf("%s: %s", cmd, err)
	}
	// First check ACL_USER_OBJ
	if x := m[acl.TagUserObj][0]; x.Qualifier == u.Uid {
		fmt.Printf("%s for %q on %q\tvia ACL_USER_OBJ (%s is owner)\n", toString(x.Perms), username, path, username)
		return
	}
	// Next ACL_USER (specific users that may have access)
	for _, e := range m[acl.TagUser] {
		if e.Qualifier == u.Uid {
			fmt.Printf("%s for %q on %q\tvia ACL_USER (%s is in user ACL list)\n", toString(e.Perms), username, path, username)
			mask := m[acl.TagMask]
			if len(mask) > 0 {
				fmt.Printf("%s effective via mask\n", toString(mask[0].Perms))
			}
			return
		}
	}

	// If still here we are checking the groups, this depends on the MASK setting
	mask := m[acl.TagMask]
	if len(mask) > 0 {
		// mask
		for _, g := range groupids {
			if x := m[acl.TagGroupObj][0]; x.Qualifier == g {
				fmt.Printf("%s for %q on %q\tvia ACL_GROUP_OBJ (%s is group-owner)\n", toString(x.Perms), username, path, username)
				fmt.Printf("%s effective via mask\n", toString(mask[0].Perms))
				return
			}
		}
		// if still here, we check the ACL groups (is this quadratic??)
		for _, g := range groupids {
			for _, e := range m[acl.TagGroup] {
				if e.Qualifier == g {
					// print ACL mask
					group, _ := user.LookupGroupId(g)
					fmt.Printf("%s for %q on %q\tvia ACL_GROUP (%s is in group ACL list via %s)\n", toString(e.Perms), username, path, username, group.Name)
					fmt.Printf("%s effective via mask\n", toString(mask[0].Perms))
					return
				}
			}
		}
	} else {
		for _, g := range groupids {
			if x := m[acl.TagGroupObj][0]; x.Qualifier == g {
				fmt.Printf("%s for %q on %q\tvia ACL_GROUP_OBJ (%s is group-owner)\n", toString(x.Perms), username, path, username)
				return
			}
		}
	}

	// still here, then other applies
	other := m[acl.TagOther][0]
	fmt.Printf("%s for %q on %q\tvia ACL_OTHER\n", toString(other.Perms), username, path)
}

// aclToMap maps an ACL to map for easier access. It also stats path to get owner and group info.
func aclToMap(a acl.ACL, path string) (map[acl.Tag]acl.ACL, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot stat %q", path)
	}

	// default tag as well? get default acl's ionly of path is dir?

	m := map[acl.Tag]acl.ACL{}
	for i := range a {
		m[a[i].Tag] = a
	}

	m[acl.TagUserObj][0].Qualifier = strconv.FormatUint(uint64(sys.Uid), 10)
	m[acl.TagGroupObj][0].Qualifier = strconv.FormatUint(uint64(sys.Gid), 10)

	return m, nil
}

// toString make a string of f only showing the last 3 permission bits (rwx).
func toString(f os.FileMode) string {
	return f.String()[7:]
}
