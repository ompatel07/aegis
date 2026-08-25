package p

func single(c bool) {
	// ruleid: aegis-bug-identical-if-else-branches-go
	if c {
		a()
	} else {
		a()
	}
	// ok: aegis-bug-identical-if-else-branches-go
	if c {
		a()
	} else {
		b()
	}
}

func multi(c bool) {
	// ruleid: aegis-bug-identical-if-else-branches-go
	if c {
		a()
		b()
	} else {
		a()
		b()
	}
}
