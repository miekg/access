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

	paths := flag.Args()
	if len(paths) == 1 {
		paths = []string{"."}
	} else {
		paths = paths[1:]
	}
	length := 0
	for _, path := range paths {
		if x := len(path); x > length {
			length = x
		}
	}
	for _, path := range paths {
		a, err := acl.Get(path)
		if err != nil {
			log.Fatalf("%s: cannot get acl: %q: %s", cmd, path, err)
		}

		m, err := aclToMap(a, path)
		if err != nil {
			log.Fatalf("%s: %s", cmd, err)
		}
		// TODO(miek): we stat again
		dir := "d"
		stat, _ := os.Stat(path)
		if !stat.IsDir() {
			dir = "-"
		}

		mask := m[acl.TagMask]
		prefix := func(p os.FileMode) string {
			return fmt.Sprintf("%s%s %s %-*s", dir, toString(p), username, length, path)
		}

		// First check ACL_USER_OBJ
		if x := m[acl.TagUserObj][0]; x.Qualifier == u.Uid {
			fmt.Printf("%s # ACL_USER_OBJ (owner)\n", prefix(x.Perms))
			continue
		}

		// Next ACL_USER (specific users that may have access)
		for _, e := range m[acl.TagUser] {
			if e.Qualifier == u.Uid {
				if len(mask) > 0 {
					fmt.Printf("%s # ACL_USER (with %s%s)\n", prefix(mask[0].Perms), dir, toString(e.Perms))
					continue
				}
				fmt.Printf("%s # ACL_USER (%s)\n", prefix(e.Perms), username)
				continue
			}
		}

		// If still here we are checking the groups, this depends on the MASK setting
		if len(mask) > 0 {
			// mask
			for _, g := range groupids {
				if x := m[acl.TagGroupObj][0]; x.Qualifier == g {
					fmt.Printf("%s # ACL_GROUP_OBJ (via group %q with %s%s)\n", prefix(mask[0].Perms), g, dir, toString(x.Perms))
					continue
				}
			}
			// if still here, we check the ACL groups (is this quadratic??)
			for _, g := range groupids {
				for _, e := range m[acl.TagGroup] {
					if e.Qualifier == g {
						group, _ := user.LookupGroupId(g)
						fmt.Printf("%s # ACL_GROUP (via group %q with %s%s)\n", prefix(mask[0].Perms), group.Name, dir, toString(e.Perms))
						continue
					}
				}
			}
		} else {
			for _, g := range groupids {
				if x := m[acl.TagGroupObj][0]; x.Qualifier == g {
					fmt.Printf("%s # ACL_GROUP_OBJ (via group %q)\n", prefix(x.Perms), g)
					continue
				}
			}
		}

		// still here, then other applies
		other := m[acl.TagOther][0]
		fmt.Printf("%s # ACL_OTHER\n", prefix(other.Perms))
	}
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

	// TODO(miek): default tag as well? get default acl's or only of path is dir?
	m := map[acl.Tag]acl.ACL{}
	for i := range a {
		m[a[i].Tag] = append(m[a[i].Tag], a[i])
	}

	m[acl.TagUserObj][0].Qualifier = strconv.FormatUint(uint64(sys.Uid), 10)
	m[acl.TagGroupObj][0].Qualifier = strconv.FormatUint(uint64(sys.Gid), 10)

	return m, nil
}

// toString make a string of f only showing the last 3 permission bits (rwx).
func toString(f os.FileMode) string {
	return f.String()[7:]
}
