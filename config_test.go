// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	err := DefaultConfig.Validate()

	if err != nil {
		t.Fatalf("Failed to verify the default configuration: %s", err)
	}
}
