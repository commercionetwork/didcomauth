package didcomauth

import (
	"encoding/json"
	"fmt"
	"time"

	redisClient "github.com/go-redis/redis"
)

const (
	keyFmt              = "challenge-%s"
	challengeExpiryTime = 30 * time.Second // time in which we assume a Challenge is valid
)

type redis struct {
	rc *redisClient.Client
}

// newRedis returns a new instance of redis with ru as redis host address.
func newRedis(ru string) cache {
	rc := redisClient.NewClient(&redisClient.Options{
		Addr: ru,
	})

	return cache(redis{rc})
}

func getKey(did string) string {
	return fmt.Sprintf(keyFmt, did)
}

// Set implements the cache interface for redis.
func (r redis) Set(c Challenge) error {
	return r.rc.Set(getKey(c.DID), c, challengeExpiryTime).Err()
}

// Get implements the cache interface for redis.
func (r redis) Get(did string) (Challenge, error) {
	b, err := r.rc.Get(getKey(did)).Bytes()
	if err != nil {
		return Challenge{}, err
	}

	var c Challenge
	return c, json.Unmarshal(b, &c)
}

func (r redis) Delete(did string) {
	_ = r.rc.Del(did).Err()
}
