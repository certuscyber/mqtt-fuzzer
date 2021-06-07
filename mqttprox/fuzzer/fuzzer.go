package fuzzer

import (
	"fmt"
	"log"
	"math/rand"
	"mqttprox/utils"
	"net"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	ID   string
	Data string
}

//fields have to be exportable for gofuzz
type Connect_struct struct {
	Fixed_header_1 string

	Remaining_length string

	Payload_length string

	//reference payload_length while generating random payloads
	Payload string

	Protocol_version string
	Properties       string
}

//check the incoming data to map to the packet type
func identify_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {

	fixed_flags := data[1:2]

	switch packet_type := data[:1]; packet_type {
	case "0":
		switch fixed_flags {
		case "0":
			log.Println("Forbidden reserved")
		default:
			log.Println("Invalid packet of type 0")

		}
	//CONNECT packet
	case "1":
		switch fixed_flags {
		case "0":
			log.Println("CONNECT packet")
			Connect_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid CONNECT packet")
		}
	//CONNACK packet
	case "2":
		if fixed_flags == "0" {
			log.Println("CONNACK packet")
			Connack_packet(data, fuzzPayloadLen, fuzzingDelay)
		} else {
			log.Println("Invalid CONNACK packet")
		}
	//PUBLISH packet
	case "3":
		switch fixed_flags {
		//Vanilla PUBLISH packet
		case "0":
			log.Println("PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "1":
			log.Println("RETAIN flag is set for the PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "6":
			log.Println("QoS set in PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "8":
			log.Println("DUP flag set in PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "13":
			log.Println("DUP, QoS flag set in PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "9":
			log.Println("DUP, RETAIN flag set in PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		case "7":
			log.Println("QoS, RETAIN flag set in PUBLISH packet")
			Publish_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PUBLISH packet")
		}
	//PUBACK packet
	case "4":
		switch fixed_flags {
		case "0":
			log.Println("PUBACK packet")
			Puback_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PUBACK packet")
		}
	//PUBREC packet
	case "5":
		switch fixed_flags {
		case "0":
			log.Println("PUBREC packet")
			Pubrec_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PUBREC packet")
		}
	//PUBREL packet
	case "6":
		switch fixed_flags {
		case "2":
			log.Println("PUBREL packet")
			Pubrel_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PUBREL packet")
		}
	//PUBCOMP packet
	case "7":
		switch fixed_flags {
		case "0":
			log.Println("PUBCOMP packet")
			Pubcomp_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PUBCOMP packet")
		}
	//SUBSCRIBE packet
	case "8":
		switch fixed_flags {
		case "2":
			log.Println("SUBSCRIBE packet")
			Subscribe_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid SUBSCRIBE packet")
		}
	//SUBACK packet
	case "9":
		switch fixed_flags {
		case "0":
			log.Println("SUBACK packet")
			Suback_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid SUBACK packet")
		}
	//UNSUBSCRIBE packet
	case "a":
		switch fixed_flags {
		case "2":
			log.Println("UNSUBSCRIBE packet")
			Unsubscribe_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid UNSUBSCRIBE packet")
		}
	//UNSUBACK packet
	case "b":
		switch fixed_flags {
		case "0":
			log.Println("UNSUBACK packet")
			Unsuback_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid UNSUBACK packet")
		}
	//PINGREQ packet
	case "c":
		switch fixed_flags {
		case "0":
			log.Println("PINGREQ packet")
			Pingreq_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("INvalid PINGREQ packet")
		}
	//PINGRESP packet
	case "d":
		switch fixed_flags {
		case "0":
			log.Println("PINGRESP packet")
			Pingresp_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid PINGRESP packet")
		}
	//DISCONNECT packet
	case "e":
		switch fixed_flags {
		case "0":
			log.Println("DISCONNECT packet")
			Disconnect_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid DISCONNECT packet")
		}
	//AUTH packet
	case "f":
		switch fixed_flags {
		case "0":
			log.Println("AUTH packet")
			Auth_packet(data, fuzzPayloadLen, fuzzingDelay)
		default:
			log.Println("Invalid AUTH packet")
		}
	//Packet not in specification
	default:
		log.Println("Unidentified packet")

	}
}

func StartFuzz(data string, fuzzPayloadLen int, fuzzingDelay int) {

	tmpData := data

	if len(tmpData) > 0 {

		sanitizedString := strings.Join(utils.SanitizeString(tmpData), "")

		identify_packet(sanitizedString, fuzzPayloadLen, fuzzingDelay)

	} else {
		fmt.Println("The incoming data packet is empty and cannot be used to start a fuzz test")
	}

}

func fuzzit(packet Mqtt_packet, source string, bounds []int, fuzzPayloadLen int, fuzzingDelay int) {

	const charset = "abcdef0123456789"
	var fuzzPayloadLenHex string

	remLenBytes := 1
	switchVal := 2

	var tmp string
	fuzzPort := "127.0.0.1:1989"

	fmt.Println("The fuzzpayload length is: ", fuzzPayloadLen)

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))

	for {
		fuzzed_data := packet

		if fuzzPayloadLen != 0 && switchVal != 0 {

			fuzzPayloadLenHex = fmt.Sprintf("%x", fuzzPayloadLen)
			if (len(fuzzPayloadLenHex) % 2) != 0 {
				fuzzPayloadLenHex = "0" + fuzzPayloadLenHex
			}

			//stays constant because user supplied
			fuzzed_data.Remaining_length = fuzzPayloadLenHex

			fuzzed_data.Varupay_header = utils.String(2*fuzzPayloadLen, charset, seededRand)

			tmp = fuzzed_data.Packet_type + fuzzed_data.Fixed_flags + fuzzed_data.Remaining_length + fuzzed_data.Varupay_header

			conn2, err2 := net.Dial("tcp", fuzzPort)
			if err2 != nil {
				fmt.Printf("[x] Couldn't connect: %v", err2)
				return
			}

			utils.Send(conn2, "100c00044d5154540402003c0000")
			utils.Send(conn2, tmp)
			defer conn2.Close()

			fuzzed_data.Fixed_flags = utils.String(1, charset, seededRand)
			switchVal++
		}

		if fuzzPayloadLen == 0 && switchVal == 2 {

			//alternates between 1-4 bytes of the remaining length field
			if remLenBytes <= 4 {
				fuzzed_data.Remaining_length = utils.String(2*remLenBytes, charset, seededRand)
				intVal, _ := strconv.ParseInt(fuzzed_data.Remaining_length, 16, 64)
				fuzzed_data.Varupay_header = utils.String(int(intVal), charset, seededRand)

				tmp = fuzzed_data.Packet_type + fuzzed_data.Fixed_flags + fuzzed_data.Remaining_length + fuzzed_data.Varupay_header

				conn2, err2 := net.Dial("tcp", fuzzPort)
				if err2 != nil {
					fmt.Printf("[x] Couldn't connect: %v", err2)
					return
				}
				utils.Send(conn2, "100c00044d5154540402003c0000")
				utils.Send(conn2, tmp)
				defer conn2.Close()

				fuzzed_data.Fixed_flags = utils.String(1, charset, seededRand)
				remLenBytes++
			} else {
				remLenBytes = 1
			}
			switchVal = 2

		}

		if fuzzPayloadLen != 0 && switchVal == 4 {

			//alternates between 1-4 bytes of the remaining length field
			if remLenBytes <= 4 {
				fuzzed_data.Remaining_length = utils.String(2*remLenBytes, charset, seededRand)
				intVal, _ := strconv.ParseInt(fuzzed_data.Remaining_length, 16, 64)
				fuzzed_data.Varupay_header = utils.String(int(intVal), charset, seededRand)

				tmp = fuzzed_data.Packet_type + fuzzed_data.Fixed_flags + fuzzed_data.Remaining_length + fuzzed_data.Varupay_header

				conn2, err2 := net.Dial("tcp", fuzzPort)
				if err2 != nil {
					fmt.Printf("[x] Couldn't connect: %v", err2)
					return
				}
				utils.Send(conn2, "100c00044d5154540402003c0000")
				utils.Send(conn2, tmp)
				defer conn2.Close()

				fuzzed_data.Fixed_flags = utils.String(1, charset, seededRand)
				remLenBytes++
			} else {
				remLenBytes = 1
			}
			switchVal = 2

		}

		if fuzzingDelay == 0 {
			time.Sleep(0)
		} else {
			time.Sleep(time.Duration(fuzzingDelay) * time.Millisecond)
		}
		utils.CleanLogs()
	}
}
