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

func nilDerefBad() {
	// ruleid: aegis-bug-go-nil-deref-before-err-check
	resp, err := doRequest()
	defer resp.Body.Close()
	if err != nil {
		return
	}
	_ = resp
}

func nilDerefGood() {
	// ok: aegis-bug-go-nil-deref-before-err-check
	resp, err := doRequest()
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_ = resp
}

func wgAddBad() {
	// ruleid: aegis-bug-go-waitgroup-add-in-goroutine
	go func() {
		wg.Add(1)
		work()
	}()
}

func wgAddGood() {
	// ok: aegis-bug-go-waitgroup-add-in-goroutine
	wg.Add(1)
	go func() {
		work()
	}()
}
