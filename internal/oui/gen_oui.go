//go:build ignore

// Command gen converts the IEEE registration authority CSV exports into the
// compact, gzip-compressed table embedded by package oui.
//
//	curl -O https://standards-oui.ieee.org/oui/oui.csv
//	curl -O https://standards-oui.ieee.org/oui28/mam.csv
//	curl -O https://standards-oui.ieee.org/oui36/oui36.csv
//	go run gen_oui.go oui.csv mam.csv oui36.csv   (from internal/oui)
//
// Output format (one record per line, sorted by prefix length then prefix):
//
//	<hex prefix, 6, 7 or 9 nibbles>\t<organisation name>
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run gen.go oui.csv [mam.csv oui36.csv]")
		os.Exit(2)
	}
	recs := map[string]string{}
	for _, path := range os.Args[1:] {
		f, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		r := csv.NewReader(f)
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		first := true
		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(fmt.Errorf("%s: %w", path, err))
			}
			if first {
				first = false
				continue
			}
			if len(row) < 3 {
				continue
			}
			p := strings.ToUpper(strings.TrimSpace(row[1]))
			name := strings.Join(strings.Fields(row[2]), " ")
			if (len(p) != 6 && len(p) != 7 && len(p) != 9) || name == "" || strings.EqualFold(name, "IEEE Registration Authority") {
				continue
			}
			recs[p] = name
		}
		f.Close()
	}
	keys := make([]string, 0, len(recs))
	for k := range recs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	for _, k := range keys {
		fmt.Fprintf(zw, "%s\t%s\n", k, strings.ReplaceAll(recs[k], "\t", " "))
	}
	zw.Close()
	if err := os.WriteFile("oui.tsv.gz", buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d prefixes (%d bytes)\n", len(keys), buf.Len())
}
