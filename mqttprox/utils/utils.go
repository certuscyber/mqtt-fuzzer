package utils

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func Send(conn net.Conn, data string) {

	msg, _ := hex.DecodeString(data)

	bin_buf := bytes.NewBuffer(msg)

	_, err := conn.Write(bin_buf.Bytes())
	if err != nil {

	} else {
		fmt.Println("Error writing bytes: ", err)
	}

}

//Sanitize the string to get rid of 00000000
func SanitizeString(data string) []string {
	tmpString := strings.Split(data, " ")
	var newTmpString []string

	for _, hexVal := range tmpString {
		if len(hexVal) == 2 {
			newTmpString = append(newTmpString, hexVal)
		}

	}

	return newTmpString
}

func FindUnique(incomingSlice []string) []string {
	keys := make(map[string]bool)
	var uniqueSlice []string

	for _, entry := range incomingSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			uniqueSlice = append(uniqueSlice, entry)
		}
	}
	return uniqueSlice
}

func CleanLogs() {

	re := regexp.MustCompile(`(?sm)^\d{4}\/\d{2}\/\d{2}\s\d{2}[:]\d{2}[:]\d{2}\s(Response number: )[A-Za-z0-9]{25}`)

	var respNumbers, tmpRespNumbers, reqNumbers, tmpReqNumbers, sliceIntersect []string

	data, err := ioutil.ReadFile("./logs/responses.log")
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}

	strData := string(data)

	tmpRespNumbers = re.FindAllString(strData, -1)

	for _, respNumMatch := range tmpRespNumbers {
		respNumbers = append(respNumbers, respNumMatch[len(respNumMatch)-25:])
	}

	if respNumbers != nil {
		fmt.Println(respNumbers)
	} else {
		respNumbers = FindUnique(respNumbers)
	}

	re = regexp.MustCompile(`(?sm)^\d{4}\/\d{2}\/\d{2}\s\d{2}[:]\d{2}[:]\d{2}\s(Request number: )[A-Za-z0-9]{25}`)
	data, err = ioutil.ReadFile("./logs/requests.log")
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}
	strData = string(data)

	tmpReqNumbers = re.FindAllString(strData, -1)

	for _, tmpReqVal := range tmpReqNumbers {
		reqNumbers = append(reqNumbers, tmpReqVal[len(tmpReqVal)-25:])
	}

	if reqNumbers != nil {
		fmt.Println(reqNumbers)
	} else {
		reqNumbers = FindUnique(reqNumbers)
	}

	for _, num1 := range respNumbers {
		for _, num2 := range reqNumbers {
			if strings.Compare(num1, num2) == 0 {
				sliceIntersect = append(sliceIntersect, num1)
			}
		}
	}

	rn := ``
	extRegex := `(?m)^\d{4}[\/]\d{2}[\/]\d{2}.*((` + rn + `)[\r\n\s])([abcdef1234567890]{8}.*[\r\n\s])*`

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))
	const charset = "abcdef0123456789"
	logFileName := String(10, charset, seededRand)

	if sliceIntersect != nil {

		file, err := os.Create("./output/" + logFileName + "requests.log")
		if err != nil {
			log.Fatal(err)
		}
		writer := bufio.NewWriter(file)

		var writtenBytes int
		var copiedReq []string

		for _, stringInSI := range sliceIntersect {
			rn = stringInSI
			extRegex = `(?m)^\d{4}[\/]\d{2}[\/]\d{2}.*((` + rn + `)[\r\n\s])([abcdef1234567890]{8}.*[\r\n\s])*`
			re = regexp.MustCompile(extRegex)
			copiedReq = re.FindAllString(strData, -1)
			for _, reqStr := range copiedReq {
				writtenBytes, err = writer.WriteString(reqStr + "\n\n")
				if err != nil {
					log.Fatalf("Got an err: ", err)
					fmt.Println("Got an error: ", err)
				}
				fmt.Println(writtenBytes, " bytes logged")
			}
		}
		writer.Flush()
	}

	cp, _ := exec.LookPath("cp")

	cpStats, _ := os.Stat("./logs/responses.log")

	if cpStats.Size() > 0 {

		fName := "./output/" + logFileName + "responses.log"
		cpCmd := &exec.Cmd{Path: cp,
			Args:   []string{cp, "./logs/responses.log", fName},
			Stdout: os.Stdout,
			Stderr: os.Stderr}

		cpCmdRun := cpCmd.Run()

		if cpCmdRun != nil {
			log.Fatal(err)
			fmt.Println("Issue copying the response log file")
		}
	}

	// delete the parent log files
	rm, _ := exec.LookPath("rm")

	rmStats, _ := os.Stat("./logs/responses.log")
	rmStats2, _ := os.Stat("./logs/requests.log")

	rmCmd := &exec.Cmd{Path: rm,
		Args:   []string{rm, "./logs/responses.log"},
		Stdout: os.Stdout,
		Stderr: os.Stderr}
	var rmCmdRun error

	if rmStats.Size() > 0 {

		rmCmdRun = rmCmd.Run()

		if rmCmdRun != nil {
			log.Fatal(err)
			fmt.Println("Issue deleting responses.log")
		}
	}
	if rmStats2.Size() > 0 {
		rmCmdRun = nil
		rmCmd = &exec.Cmd{Path: rm,
			Args:   []string{rm, "./logs/requests.log"},
			Stdout: os.Stdout,
			Stderr: os.Stderr}

		rmCmdRun = rmCmd.Run()

		if rmCmdRun != nil {
			log.Fatal(err)
			fmt.Println("Issue deleting requests.log")
		}
	}
}

func StringWithCharset(length int, charset string, seededRand *rand.Rand) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int, charset string, seededRand *rand.Rand) string {
	return StringWithCharset(length, charset, seededRand)
}

func SliceToHex(data []byte) string {
	hexVal := ""
	for _, value := range data {

		fmt.Println(hexVal)
		hexVal = hexVal + strconv.FormatInt(int64(value), 16)
	}

	return hexVal
}
