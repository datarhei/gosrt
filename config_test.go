// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

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
