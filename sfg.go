package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"strings"
)

const (
	VENDOR_FINISAR     = "02"
	VENDOR_FINISAR_KEY = "8DDAE6A46EC9DEF6100BF185059C3DAB"
	//VENDOR_AVAGO       = "06"
	//VENDOR_AVAGO_KEY   = "175258FEE9B4F0D9EAB6006F7C65A8CB"

	CISCO_A0_FC16G_HEADER = "0304070000000040400C70068C0A00000301000A"
	CISCO_A0_FC16G_MID1   = "0000176A414642522D35374635505A2D4353312042322020035200"
	// CS1
	CISCO_A0_FC16G_MID2 = "003A0000"
	CISCO_A0_FC16G_MID3 = "313530383135202068FA05"
	// CS2
)

func main() {
	// parsing input params
	var vendorArg = flag.String("v", "", "`<vendor>` name (string 16 bytes max)")
	var serialArg = flag.String("s", "", "`<serial>` number (string 16 bytes max)")
	flag.Parse()

	if len(*vendorArg) == 0 || len(*vendorArg) > 16 || len(*serialArg) == 0 || len(*serialArg) > 16 {
		flag.Usage()
		os.Exit(0)
	}

	// fill buffer with spaces 0x20
	spaces := strings.Repeat(" ", 16)

	vendor := make([]byte, 16)
	copy(vendor, spaces)
	copy(vendor, *vendorArg)

	serial := make([]byte, 16)
	copy(serial, spaces)
	copy(serial, *serialArg)

	//fmt.Println(string(vendor))
	//fmt.Println(string(serial))

	// data must contains: HEADER + VENDOR + MID1 + CS1 + MID2 + SERIAL + MID3 + CS2
	decodeString := hexDecode(CISCO_A0_FC16G_HEADER + hex.EncodeToString(vendor) + CISCO_A0_FC16G_MID1)
	data1 := append(decodeString, checksum8mod256(decodeString))

	decodeString = hexDecode(CISCO_A0_FC16G_MID2 + hex.EncodeToString(serial) + CISCO_A0_FC16G_MID3)
	data2 := append(decodeString, checksum8mod256(decodeString))

	fulldata := append(data1, data2...)
	// calculating cisco checksum:
	// 0x0000 + VENDOR_ID + md5(vendor id + vendor name + serial + vendor key) + 0x000000000000000000 + crc32 of this data
	ciscoChecksum := VENDOR_FINISAR + hex.EncodeToString(vendor) + hex.EncodeToString(serial) + VENDOR_FINISAR_KEY
	decodeString = hexDecode(ciscoChecksum)

	ciscoChecksumMD5 := fmt.Sprintf("%x", md5.Sum(decodeString))
	ciscoChecksumMD5 = "0000" + VENDOR_FINISAR + ciscoChecksumMD5 + "000000000000000000"
	decodeString = hexDecode(ciscoChecksumMD5)

	ciscoCrc32 := make([]byte, 4)
	binary.LittleEndian.PutUint32(ciscoCrc32, crc32.ChecksumIEEE(decodeString))
	ciscoChecksumData := append(decodeString, ciscoCrc32...)
	fulldata = append(fulldata, ciscoChecksumData...)

	// write firmware
	file := fmt.Sprintf("%s_%s.bin", *vendorArg, *serialArg)
	fmt.Printf("[*] Writing firmware to file '%s'... ", file)

	err := os.WriteFile(file, fulldata, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OK\n")
}

func hexDecode(str string) (ret []byte) {
	decodeString, err := hex.DecodeString(str)
	if err != nil {
		log.Fatalf("Can't decode '%s'\n", str)
	}

	return decodeString
}

func checksum8mod256(arr []byte) (ret byte) {
	for _, v := range arr {
		ret += v
	}

	return ret
}
