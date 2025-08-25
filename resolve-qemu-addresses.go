package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type FunctionInfo struct {
	Name string
	Size uint64
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <functions.csv> <qemu.log>\n", os.Args[0])
		os.Exit(1)
	}
	functions := loadFunctions(os.Args[1])
	processQemuLog(os.Args[2], functions)
}

func findFunction(address uint64, functions map[uint64]FunctionInfo) (string, uint64) {
	for funcAddress, funcInfo := range functions {
		if funcAddress <= address && address < funcAddress+funcInfo.Size {
			return funcInfo.Name, funcAddress
		}
	}
	return "", 0
}

func processQemuLog(logFile string, functions map[uint64]FunctionInfo) {
	outFile := strings.Split(logFile, ".")[0] + "-resolved." + strings.Split(logFile, ".")[1]

	inF, err := os.Open(logFile)
	check(err)
	defer inF.Close()

	scanner := bufio.NewScanner(inF)

	outF, err := os.Create(outFile)
	check(err)
	defer outF.Close()

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "IN:" {
			if scanner.Scan() {
				nextLine := scanner.Text()
				if strings.HasPrefix(nextLine, "0x") {
					addressStr := strings.Split(nextLine, ":")[0]
					address, _ := strconv.ParseUint(addressStr, 0, 64)
					function, functionAddress := findFunction(address, functions)
					if function != "" {
						if address == functionAddress {
							fmt.Fprintf(outF, "IN: %v (JMP)\n", function)
						} else {
							fmt.Fprintf(outF, "IN: %v\n", function)
						}
					} else {
						fmt.Fprintln(outF, "IN:")
					}
					fmt.Fprintln(outF, nextLine)
				} else {
					fmt.Fprintln(outF, line)
					fmt.Fprintln(outF, nextLine)
				}
			}
		} else {
			fmt.Fprintln(outF, line)
		}
	}

	if err := scanner.Err(); err != nil {
		check(err)
	}

	fmt.Printf("Output written to %v\n", outFile)
}

func loadFunctions(file string) map[uint64]FunctionInfo {
	f, err := os.Open(file)
	check(err)
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	check(err)

	functions := make(map[uint64]FunctionInfo)

	/*
		"Name","Location","Function Size"
		"_rt0_arm_linux","0007fbdc","16"
		"_rt0_arm_linux1","0007fbf4","20"
	*/

	for i := 1; i < len(records); i++ {
		record := records[i]
		name := record[0]
		address, _ := strconv.ParseUint(record[1], 16, 64)
		size, _ := strconv.ParseUint(record[2], 10, 64)

		functions[address] = FunctionInfo{
			Name: name,
			Size: size,
		}
	}

	return functions
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
