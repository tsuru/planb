package main

import (
	"testing"

	"launchpad.net/gocheck"
)

type S struct{}

var _ = gocheck.Suite(&S{})

func Test(t *testing.T) {
	gocheck.TestingT(t)
}

func (s *S) TestExtractDomain(c *gocheck.C) {
	tests := [][]string{
		{"a.something.com", "something.com"},
		{"a.b.something.com", "something.com"},
		{"something.com", "something.com"},
		{"awesometld", "awesometld"},
	}
	for _, pair := range tests {
		c.Assert(extractDomain(pair[0]), gocheck.Equals, pair[1])
	}

}
