package sync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStopper(t *testing.T) {
	s := NewStopper()

	result := 0

	go func(s Stopper) {
		ticker := time.NewTicker(time.Second)

		defer func() {
			ticker.Stop()

			// do some heavy cleanup work
			time.Sleep(3 * time.Second)

			result = 42

			s.Done()
		}()

		for {
			select {
			case <-s.Check():
				return
			case <-ticker.C:
				break
			}
		}
	}(s)

	require.Equal(t, 0, result)

	start := time.Now()

	s.Stop()

	d := time.Since(start)

	require.GreaterOrEqual(t, d.Seconds(), float64(3))

	require.Equal(t, 42, result)
}
