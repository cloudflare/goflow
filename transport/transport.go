package transport

import (
	"strings"
)

type registerFlagsFunc func()

var registerFlagsFuncs = []registerFlagsFunc{
	registerKafkaFlags,
	registerNatsFlags,
}

func RegisterFlags() {
	for _, f := range registerFlagsFuncs {
		f()
	}
}

type stringSliceFlag []string

// String - implements flag.Value
func (ssf stringSliceFlag) String() string {
	return strings.Join(ssf, ",")
}

// Set - implements flag.Value.  If the flag is passed multiple times on the command line,
// each value appends to flags.  It also looks for comma separated values, and interprets
// those as individual items as well.
func (ssf *stringSliceFlag) Set(val string) error {
	vals := strings.Split(val, ",")
	*ssf = append(*ssf, vals...)
	return nil
}
