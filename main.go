package main

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type GeoEntry struct {
	IP        net.IP
	PrefixLen int
	GeoID     uint32
}

func parseCIDR(cidr string) (net.IP, int, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}
	ones, _ := ipNet.Mask.Size()
	return ip.To4(), ones, nil
}

func ipToUint32BE(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func loadCSV(path string) ([]GeoEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var entries []GeoEntry

	for i, record := range records {
		if i == 0 && strings.ToLower(record[0]) == "network" {
			continue
		}
		if len(record) < 2 || record[0] == "" || record[1] == "" {
			continue
		}

		ip, prefix, err := parseCIDR(record[0])
		if err != nil {
			log.Printf("Skipping invalid CIDR %q: %v", record[0], err)
			continue
		}

		geoID, err := strconv.Atoi(record[1])
		if err != nil {
			log.Printf("Skipping invalid geoname_id %q: %v", record[1], err)
			continue
		}

		entries = append(entries, GeoEntry{
			IP:        ip,
			PrefixLen: prefix,
			GeoID:     uint32(geoID),
		})
	}

	return entries, nil
}

func insertToGeoMap(entry GeoEntry, mapName string) error {
	ipBE := ipToUint32BE(entry.IP)
	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key[:4], uint32(entry.PrefixLen))
	binary.BigEndian.PutUint32(key[4:], ipBE)

	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, entry.GeoID)

	keyArgs := make([]string, 0, 8)
	for _, b := range key {
		keyArgs = append(keyArgs, fmt.Sprintf("0x%02x", b))
	}

	valArgs := make([]string, 0, 4)
	for _, b := range val {
		valArgs = append(valArgs, fmt.Sprintf("0x%02x", b))
	}

	args := append([]string{"map", "update", "name", mapName, "key"}, keyArgs...)
	args = append(args, "value")
	args = append(args, valArgs...)

	cmd := exec.Command("bpftool", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bpftool error: %v — %s", err, out)
	}
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <geo.csv> <geo_map>")
		os.Exit(1)
	}

	csvPath := os.Args[1]
	mapName := os.Args[2]

	entries, err := loadCSV(csvPath)
	if err != nil {
		log.Fatalf("Failed to load CSV: %v", err)
	}

	for _, entry := range entries {
		err := insertToGeoMap(entry, mapName)
		if err != nil {
			log.Printf("Failed to insert %s/%d: %v", entry.IP, entry.PrefixLen, err)
		}
	}
}