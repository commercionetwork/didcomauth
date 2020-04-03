package didcomauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_setCosmosConfig(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			"calling twice doesn't panic",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setCosmosConfig()

			require.NotPanics(t, func() {
				setCosmosConfig()
			})
		})
	}
}
