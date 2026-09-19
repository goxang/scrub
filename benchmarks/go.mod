// Comparison benchmarks live in their own module so the library keeps its
// zero dependencies. The libraries compared here need Go 1.26.
module github.com/goxang/scrub/benchmarks

go 1.26.5

require (
	github.com/deadpoets/secmem v0.6.0
	github.com/docker/portcullis v1.0.0
	github.com/goxang/scrub v0.0.0
)

replace github.com/goxang/scrub => ../
