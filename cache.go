package didcomauth

// cache represents an object capable of setting and getting data from a backing storage (redis, a map...).
type cache interface {
	Set(c Challenge) error
	Get(did string) (Challenge, error)
	Delete(did string)
}
