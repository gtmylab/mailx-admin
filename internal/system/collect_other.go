//go:build !linux

package system

// collectInfo is a stub for non-Linux builds (the developer checkout). The panel
// only ever runs on Linux, where collect_linux.go supplies the real reader.
func collectInfo(prev cpuCounters) (Info, cpuCounters) {
	return Info{}, cpuCounters{}
}
