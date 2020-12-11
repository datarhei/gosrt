// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func log(format string, args ...interface{}) {
	_, fn, line, _ := runtime.Caller(1)

	logline := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s:%d %s", filepath.Base(fn), line, logline)
}
