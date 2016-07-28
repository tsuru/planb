// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import "errors"

var ErrNoBackends = errors.New("no backends")

type RoutesBackend interface {
	Backends(host string) (string, []string, map[int]struct{}, error)
	MarkDead(host string, backend string, backendIdx int, backendLen int, deadTTL int) error
	StartMonitor() error
	StopMonitor()
}
