package badmap

import "github.com/sagernet/sing/common/x/constraints"

const (
	DeleteThreshold = 1 << 15
)

func GetCleanMap[K constraints.Ordered, V any](dirty map[K]V) map[K]V {
	nMap := make(map[K]V)
	for key, val := range dirty {
		nMap[key] = val
	}
	return nMap
}
