package main

import (
	"context"
	"time"
)

func contextWithTimeout(d time.Duration) context.Context {
	return context.Background()
}
