package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type FunctionInfo struct {
	Name string
	Size uint64
}

type InstrInfo struct {
	Mnemonic string
	Operand  string
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <functions.csv> <qemu.log> <listing.txt>\n", os.Args[0])
		os.Exit(1)
	}
	functions := loadFunctions(os.Args[1])
	instrs := loadInstructions(os.Args[3])
	processQemuLog(os.Args[2], functions, instrs)
}

func loadInstructions(file string) map[uint64]InstrInfo {
	f, err := os.Open(file)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	//var lines []string
	/*
									;undefined main.main()
				;local_10      undefined8         -10                      ;XREF[1,0]:   000910d0
				;local_18      undefined8         -18                      ;XREF[2,0]:   000910b8,000910c4
				;local_50      undefined8         -50                      ;XREF[2,0]:   000910ac,000910f4
				;local_58      undefined8         -58                      ;XREF[2,0]:   000910b0,000910f4
																;XREF[3,0]:   00045678,00091108,000c2288
		.text:000910a0  900b40f9        ldr         x16,[x28, #0x10]
		.text:000910a4  ff6330eb        cmp         sp,x16
		.text:000910a8  c9020054        b.ls        LAB_00091100
	*/
	re := regexp.MustCompile(`\.text:(\w+)\s+\w+\s+([a-zA-Z0-9.]+)\s+([^;]*)`)
	instrs := make(map[uint64]InstrInfo)
	for scanner.Scan() {
		// lines = append(lines, scanner.Text())
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			addressStr := matches[1]
			mnemonic := matches[2]
			operand := matches[3]
			operand = strings.TrimSpace(operand)
			InstrInfo := InstrInfo{mnemonic, operand}
			address, _ := strconv.ParseUint(addressStr, 16, 64)
			instrs[address] = InstrInfo
		}
	}
	return instrs
}

func findFunction(address uint64, functions map[uint64]FunctionInfo) (string, uint64) {
	for funcAddress, funcInfo := range functions {
		if funcAddress <= address && address < funcAddress+funcInfo.Size {
			return funcInfo.Name, funcAddress
		}
	}
	return "", 0
}

func processQemuLog(logFile string, functions map[uint64]FunctionInfo, instrs map[uint64]InstrInfo) {
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
						instrInfo := instrs[address]
						if address == functionAddress {
							fmt.Fprintf(outF, "IN: %v - %v %v (ENTER)\n", function, instrInfo.Mnemonic, instrInfo.Operand)
						} else {
							if instrInfo.Mnemonic == "ret" {
								fmt.Fprintf(outF, "IN: %v - %v %v (LEAVE)\n", function, instrInfo.Mnemonic, instrInfo.Operand)
							} else {
								fmt.Fprintf(outF, "IN: %v - %v %v\n", function, instrInfo.Mnemonic, instrInfo.Operand)
							}
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
