package backend

type RoutesBackend interface {
	Backends(host string) (string, []string, map[int]struct{}, error)
	MarkDead(host string, backend string, backendIdx int, backendLen int, deadTTL int) error
}
