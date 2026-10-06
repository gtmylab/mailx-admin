//go:build linux

package system

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// collectInfo reads one snapshot of host state from /proc and friends, using
// prev (the previous /proc/stat reading) to compute CPU utilisation since then.
func collectInfo(prev cpuCounters) (Info, cpuCounters) {
	info := Info{
		Hostname:  hostname(),
		IP:        primaryIP(),
		OS:        osRelease(),
		Kernel:    kernel(),
		UptimeSec: uptime(),
		Processes: processCount(),
	}
	info.CPUModel, info.CPUCores = cpuInfo()
	info.Load1, info.Load5, info.Load15 = loadAvg()

	memTotal, memAvail, cached, swapTotal, swapFree := meminfo()
	info.MemTotal = memTotal
	info.MemUsed = max0(memTotal - memAvail)
	info.MemCached = cached
	info.SwapTotal = swapTotal
	info.SwapUsed = max0(swapTotal - swapFree)
	info.MemUsedPct = pct(info.MemUsed, memTotal)

	info.DiskTotal, info.DiskFree = diskUsage("/")
	info.DiskUsed = max0(info.DiskTotal - info.DiskFree)
	info.DiskUsedPct = pct(info.DiskUsed, info.DiskTotal)

	cur := readCPU()
	if prev.total > 0 && cur.total > prev.total {
		dt := cur.total - prev.total
		di := cur.idle - prev.idle
		info.CPUUsedPct = clamp(100*float64(dt-di)/float64(dt), 0, 100)
	}
	return info, cur
}

func max0(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}

// primaryIP returns the first global unicast IPv4 address, skipping loopback
// and link-local addresses.
func primaryIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func osRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func kernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func uptime() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// processCount counts the numeric entries in /proc, i.e. running processes.
func processCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && isNumeric(e.Name()) {
			n++
		}
	}
	return n
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cpuInfo() (model string, cores int) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "processor"):
			cores++
		case model == "" && strings.HasPrefix(line, "model name"):
			if i := strings.IndexByte(line, ':'); i >= 0 {
				model = strings.TrimSpace(line[i+1:])
			}
		}
	}
	return model, cores
}

func loadAvg() (l1, l5, l15 float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	l1, _ = strconv.ParseFloat(fields[0], 64)
	l5, _ = strconv.ParseFloat(fields[1], 64)
	l15, _ = strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15
}

// meminfo returns total, available, cached, swap total and swap free, in bytes.
func meminfo() (total, avail, cached, swapTotal, swapFree int64) {
	vals := readProcKV("/proc/meminfo")
	total = vals["MemTotal"] * 1024
	avail = vals["MemAvailable"] * 1024
	cached = vals["Cached"] * 1024
	swapTotal = vals["SwapTotal"] * 1024
	swapFree = vals["SwapFree"] * 1024
	return
}

// readProcKV reads a "Key: value unit" file such as /proc/meminfo into a map.
func readProcKV(path string) map[string]int64 {
	m := map[string]int64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		v, _ := strconv.ParseInt(fields[0], 10, 64)
		m[strings.TrimSpace(parts[0])] = v
	}
	return m
}

func diskUsage(path string) (total, free int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = int64(st.Blocks) * int64(st.Bsize)
	free = int64(st.Bavail) * int64(st.Bsize) // available to unprivileged users
	return total, free
}

// readCPU parses the aggregate "cpu" line of /proc/stat.
func readCPU() cpuCounters {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuCounters{}
	}
	first := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(first) // "cpu user nice system idle iowait irq softirq steal ..."
	if len(fields) < 5 {
		return cpuCounters{}
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 { // idle, iowait
			idle += v
		}
	}
	return cpuCounters{total: total, idle: idle}
}
