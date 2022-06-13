package srt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	err := DefaultConfig.Validate()

	if err != nil {
		require.NoError(t, err, "Failed to verify the default configuration: %s", err)
	}
}
