package didcomauth

import "errors"

// cache_test is just a cache_mem with a flag which returns error if needed

type cTest struct {
	mem
	shouldError bool
}

var ctError = errors.New("error!")

// newMem returns a new instance of mem with an in-memory map as backing store, typically used for testing.
func newCTest(shouldError bool) cache {
	return cache(
		cTest{
			mem{store: make(map[string]Challenge)},
			shouldError,
		},
	)
}

// Set implements the cache interface for redis.
func (m cTest) Set(c Challenge) error {
	if m.shouldError {
		return ctError
	}

	m.store[getKey(c.DID)] = c
	return nil
}

// Get implements the cache interface for redis.
func (m cTest) Get(did string) (Challenge, error) {
	if m.shouldError {
		return Challenge{}, ctError
	}
	return m.store[getKey(did)], nil
}

func (m cTest) Delete(did string) {
	delete(m.store, did)
}
