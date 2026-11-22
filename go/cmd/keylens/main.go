package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/acciv/keylens/go/internal/scanner"
)

const version = "0.1.0"

func usage() {
	fmt.Fprintln(os.Stderr, `keylens — поиск утекших API-ключей и токенов

Использование:
  keylens scan [путь] [--json] [--exclude DIR] [--max-size MB] [--quiet]

Флаги:
  --json              вывод в формате JSON
  --exclude DIR       исключить каталог (можно повторять)
  --max-size MB       максимальный размер файла (по умолчанию 2)
  --quiet             только код возврата
  --version           версия`)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	if args[0] == "--version" || args[0] == "-v" {
		fmt.Println("keylens " + version)
		return 0
	}
	if args[0] != "scan" {
		usage()
		return 2
	}

	path := "."
	jsonOut, quiet := false, false
	excludes := []string{}
	maxMB := 2

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--quiet":
			quiet = true
		case "-h", "--help":
			usage()
			return 0
		case "--exclude":
			if i+1 >= len(args) {
				usage()
				return 2
			}
			i++
			excludes = append(excludes, args[i])
		case "--max-size":
			if i+1 >= len(args) {
				usage()
				return 2
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				fmt.Fprintln(os.Stderr, "keylens: неверный --max-size")
				return 2
			}
			maxMB = n
		default:
			if strings.HasPrefix(args[i], "-") || path != "." {
				usage()
				return 2
			}
			path = args[i]
		}
	}

	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "keylens: путь не найден: %s\n", path)
		return 2
	}

	findings, scanned, err := scanner.ScanPath(path, excludes, int64(maxMB)*1024*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keylens: %v\n", err)
		return 2
	}

	if jsonOut {
		out, err := scanner.MarshalJSONArray(findings)
		if err != nil {
			return 2
		}
		fmt.Println(out)
	} else if !quiet {
		fmt.Printf("🔍 keylens: просмотрено файлов: %d\n", scanned)
		if len(findings) > 0 {
			fmt.Printf("⚠️  Найдено потенциальных секретов: %d\n\n", len(findings))
			for _, f := range findings {
				fmt.Printf("  [%s] %-28s %s:%d — %s\n", f.Severity, f.Match, f.File, f.Line, f.Pattern)
			}
		} else {
			fmt.Println("✅ Секретов не найдено")
		}
	}

	if len(findings) > 0 {
		return 1
	}
	return 0
}
