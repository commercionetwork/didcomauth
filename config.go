package didcomauth

import (
	"errors"
	"net/http"
)

type CacheType int

const (
	CacheTypeRedis CacheType = iota
	CacheTypeMemory
)

const (
	defaultRedisHost     = "localhost:6379"
	defaultAuthPath      = "/auth"
	defaultChallengePath = "/challenge"
	defaultProtectedPath = "/protected"
	defaultCommercioLCD  = "http://localhost:1317"
)

// ProtectedMapping represents a URI resource handled under the DID-authenticated protected path.
type ProtectedMapping struct {
	Methods []string
	Path    string
	Handler http.HandlerFunc
}

// Config holds data regarding the didcomauth module configuration, such as redis host, Challenge and protected base
// URL path.
type Config struct {
	RedisHost         string
	ProtectedBasePath string
	ProtectedPaths    []ProtectedMapping
	JWTSecret         string
	CommercioLCD      string
	CacheType         CacheType
	CacheProvider     cache
}

func (c *Config) Validate() error {
	if c.RedisHost == "" {
		c.RedisHost = defaultRedisHost
	}

	if c.ProtectedBasePath == "" {
		c.ProtectedBasePath = defaultProtectedPath
	}

	if c.CommercioLCD == "" {
		c.CommercioLCD = defaultCommercioLCD
	}

	if c.ProtectedPaths == nil {
		return errors.New("no protected paths specificed")
	}

	if c.JWTSecret == "" {
		return errors.New("jwt secret is empty")
	}

	switch c.CacheType {
	case CacheTypeMemory:
		c.CacheProvider = newMem()
	case CacheTypeRedis:
		c.CacheProvider = newRedis(c.RedisHost)
	default:
		return errors.New("cache type not recognized")
	}

	return nil
}
