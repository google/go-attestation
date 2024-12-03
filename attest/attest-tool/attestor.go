// Binary attest-tool performs attestation operations on the local system.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
)

func main() {
	filePath := flag.String("file", "", "Path to the binary file to parse")
	flag.Parse()

	if *filePath == "" {
		fmt.Println("Please provide a file path using the -file flag")
		os.Exit(1)
	}

	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		os.Exit(1)
	}

	/*

			            else if((cbSipaLen == sizeof(UINT64)) &
		                    ((sipaType == SIPAEVENT_IMAGESIZE) ||
		                     (sipaType == SIPAEVENT_IMAGEBASE) ||
		                     (sipaType == SIPAEVENT_HYPERVISOR_LAUNCH_TYPE) ||
		                     (sipaType == SIPAEVENT_HYPERVISOR_IOMMU_POLICY) ||
		                     (sipaType == SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY) ||
		                     (sipaType == SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY) ||
		                     (sipaType == SIPAEVENT_VSM_LAUNCH_TYPE) ||
		                     (sipaType == SIPAEVENT_VBS_HVCI_POLICY) ||
		                     (sipaType == SIPAEVENT_DATAEXECUTIONPREVENTION) ||
		                     (sipaType == SIPAEVENT_PHYSICALADDRESSEXTENSION) ||
		                     (sipaType == SIPAEVENT_BOOTCOUNTER) ||
		                     (sipaType == SIPAEVENT_EVENTCOUNTER) ||
		                     (sipaType == SIPAEVENT_COUNTERID)))


							             else if((cbSipaLen == sizeof(BYTE)) &
		                    ((sipaType == SIPAEVENT_BOOTDEBUGGING) ||
		                     (sipaType == SIPAEVENT_OSKERNELDEBUG) ||
		                     (sipaType == SIPAEVENT_CODEINTEGRITY) ||
		                     (sipaType == SIPAEVENT_TESTSIGNING) ||
		                     (sipaType == SIPAEVENT_WINPE) ||
		                     (sipaType == SIPAEVENT_SAFEMODE) ||
		                     (sipaType == SIPAEVENT_IMAGEVALIDATED) ||
		                     (sipaType == SIPAEVENT_VBS_VSM_REQUIRED) ||
		                     (sipaType == SIPAEVENT_VBS_SECUREBOOT_REQUIRED) ||
		                     (sipaType == SIPAEVENT_VBS_IOMMU_REQUIRED) ||
		                     (sipaType == SIPAEVENT_VBS_MMIO_NX_REQUIRED) ||
		                     (sipaType == SIPAEVENT_VBS_MSR_FILTERING_REQUIRED) ||
		                     (sipaType == SIPAEVENT_VBS_MANDATORY_ENFORCEMENT) ||
		                     (sipaType == SIPAEVENT_NOAUTHORITY)))
		            {


	*/
	eventLog, err := attest.ParseEventLog(fileData)
	if err != nil {
		fmt.Printf("Failed to parse event log: %v\n", err)
		os.Exit(1)
	}

	evts := eventLog.Events(attest.HashSHA256)

	winState, err := attest.ParseWinEvents(evts)
	if err != nil {
		fmt.Printf("Failed to parse windows event log: %v\n", err)

	}

	// Serialize to JSON
	jsonData, err := json.Marshal(winState)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}

	// Print JSON string
	fmt.Println(string(jsonData))

	//fmt.Printf("Parsed event log: %+v\n", winState)
}
