package didcomauth

type mem struct {
	store map[string]Challenge
}

// newMem returns a new instance of mem with an in-memory map as backing store, typically used for testing.
func newMem() cache {
	return cache(mem{store: make(map[string]Challenge)})
}

// Set implements the cache interface for redis.
func (m mem) Set(c Challenge) error {
	m.store[getKey(c.DID)] = c
	return nil
}

// Get implements the cache interface for redis.
func (m mem) Get(did string) (Challenge, error) {
	return m.store[getKey(did)], nil
}

func (m mem) Delete(did string) {
	delete(m.store, did)
}
