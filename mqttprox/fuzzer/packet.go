package fuzzer

import (
	"fmt"
	"sort"
	"strconv"
)

type Mqtt_packet struct {

	//indicates the
	Packet_type string

	//fixed flags are specific to each mqtt packet
	Fixed_flags string

	//length includes the variable header and payload
	Remaining_length string

	//variable header and payload
	Varupay_header string
}

//byte 1:MSB, byte 2:LSB, byte 3-6 :(MQTT), byte 7: Protocol version, byte 8: connect flags, byte 9: keep alive MSB, byte 10: keep alive LSB
func Connect_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {

	bounds := calc_remaining_length(data)

	fmt.Println("Length: ", len(data))
	fmt.Println("Bounds ", bounds)

	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[2:4],
			Varupay_header:   data[4:],
		}

		source := "connect"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
	}
}

//The Variable Header of the CONNACK Packet contains the following fields in the order: Connect Acknowledge Flags, Connect Reason Code, and Properties
func Connack_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {

	bounds := calc_remaining_length(data)

	fmt.Println("Length: ", len(data))
	fmt.Println("Bounds ", bounds)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[2:4],
			Varupay_header:   data[4:],
		}

		source := "connack"

		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
	}

}

func Publish_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {

	bounds := calc_remaining_length(data)

	fmt.Println("Length: ", len(data))
	fmt.Println("Bounds ", bounds)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type: data[:1],
			Fixed_flags: data[1:2],
			//could be anywhere between 1 - 4 bytes long
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		topic_length := data[bounds[1]:(bounds[1] + 4)]
		topic_length_int, _ := strconv.ParseInt(topic_length, 16, 32)

		source := "publish"

		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		remaining_length := data[bounds[0]:bounds[1]]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[bounds[1]:]

		//converting lengths to int in order to derive
		packet_length_int, _ := strconv.ParseInt(remaining_length, 16, 32)

		message_length := packet_length_int - topic_length_int

		fmt.Println(pack1.Packet_type, fixed_flags, remaining_length, variable_header, topic_length, message_length)
	}

}

//variable header = byte1 :MSB, byte2: LSB, byte 3:Puback reason,m byte 4:Property length
func Puback_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type: data[:1],
			Fixed_flags: data[1:2],

			//since the remaining length can be of 1 -4 bytes, we'll have to figure the exact number
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "puback"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
	}
}

func calc_remaining_length(data string) []int {
	//this func returns a valid remaining length value
	dLen := len(data)
	var (
		pos1, pos2, pos3, pos4             string
		posLen1, posLen2, posLen3, posLen4 int64
		len1, len2, len3, len4             int
	)

	if dLen > 4 {
		pos1 = data[2:4]
		posLen1, _ = strconv.ParseInt(pos1, 16, 32)
		len1 = len(data[4:]) / 2

	} else if dLen > 6 {
		pos2 = data[2:6]
		posLen2, _ = strconv.ParseInt(pos2, 16, 32)
		len2 = len(data[6:]) / 2

	} else if dLen > 8 {
		pos3 = data[2:8]
		posLen3, _ = strconv.ParseInt(pos3, 16, 32)
		len3 = len(data[8:]) / 2

	} else if dLen > 10 {
		pos4 = data[2:10]
		posLen4, _ = strconv.ParseInt(pos4, 16, 32)
		len4 = len(data[10:]) / 2
	}

	myMap := map[int]int{
		(int(posLen1) - len1): 1,
		(int(posLen2) - len2): 2,
		(int(posLen3) - len3): 3,
		(int(posLen4) - len4): 4,
	}

	diffArray := []int{}

	diffArray = append(diffArray, (int(posLen1) - len1))
	diffArray = append(diffArray, (int(posLen2) - len2))
	diffArray = append(diffArray, (int(posLen3) - len3))
	diffArray = append(diffArray, (int(posLen4) - len4))

	sort.Slice(diffArray, func(i, j int) bool {
		return diffArray[i] > diffArray[j]
	})

	//this is the closest value. So we can guess with a high degree of probability an accurate value of remaining length
	finalArray := []int{}
	finalArray = append(finalArray, 2)
	switch myMap[diffArray[3]] {
	case 1:
		finalArray = append(finalArray, 4)
		fmt.Println("case 1")
		return finalArray
	case 2:
		finalArray = append(finalArray, 6)
		fmt.Println("case 2")
		return finalArray
	case 3:
		finalArray = append(finalArray, 8)
		fmt.Println("case 3")
		return finalArray
	case 4:
		finalArray = append(finalArray, 10)
		fmt.Println("case 4")
		return finalArray
	default:
		finalArray = append(finalArray, 4)
		return finalArray
	}
}

//variable header = byte1 :MSB, byte2: LSB, byte 3:Pubrec reason,m byte 4:Property length
func Pubrec_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "pubrec"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		packet_length := data[2:4]

		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

//variable header = byte1 :MSB, byte2: LSB, byte 3:Pubrel reason,m byte 4:Property length
func Pubrel_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)
	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "pubrel"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

//variable header = byte1 :MSB, byte2: LSB, byte 3:Pubcomp reason,m byte 4:Property length
func Pubcomp_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "pubcomp"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

//variable header: byte 1:MSB, byte 2:LSB, byte 3..N Topic filter, Byte N+1:Subscription options
//more subscription topics continue from here
func Subscribe_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)
	//ignore errs when the packet is fragmented
	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "subscribe"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

func Suback_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)
	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "suback"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

func Unsubscribe_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)
	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "unsubscribe"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

func Unsuback_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "unsuback"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

func Pingreq_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "pingreq"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		fmt.Println(fixed_flags, packet_length)
	}
}

func Pingresp_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "pingresp"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		fmt.Println(fixed_flags, packet_length)
	}
}

func Disconnect_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)
	fmt.Println(bounds)

	if bounds[1] < len(data) {
		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "disconnect"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}

func Auth_packet(data string, fuzzPayloadLen int, fuzzingDelay int) {
	bounds := calc_remaining_length(data)

	if bounds[1] < len(data) {

		pack1 := Mqtt_packet{
			Packet_type:      data[:1],
			Fixed_flags:      data[1:2],
			Remaining_length: data[bounds[0]:bounds[1]],
			Varupay_header:   data[bounds[1]:],
		}

		source := "auth"
		fuzzit(pack1, source, bounds, fuzzPayloadLen, fuzzingDelay)
		fixed_flags := data[1:2]

		//Length includes variable header and payload
		packet_length := data[2:4]

		//in hex. Topic Name, Packet Identifier, and Properties
		variable_header := data[4:]

		fmt.Println(fixed_flags, packet_length, variable_header)
	}
}
