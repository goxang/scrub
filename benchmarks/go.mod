// Comparison benchmarks live in their own module so the library keeps its
// zero dependencies. The libraries compared here need Go 1.26.
module github.com/goxang/scrub/benchmarks

go 1.26.6

require (
	github.com/docker/portcullis v1.0.0
	github.com/goxang/scrub v0.0.0
	github.com/lastpersonlabs/goredact v0.1.0
)

replace github.com/goxang/scrub => ../
