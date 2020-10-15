package trojan

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type NetworkCard string

//Inter-|   Receive                                                |  Transmit
// face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
//  eth0: 78714048  127367    0    0    0     0          0         0 59538874   87452    0    0    0     0       0          0
//    lo: 4425820   48568    0    0    0     0          0         0  4425820   48568    0    0    0     0       0          0
func (n NetworkCard) GetUsage() (n1 uint64, n2 uint64, err error) {
	netStatsFile, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer netStatsFile.Close()

	reader := bufio.NewReader(netStatsFile)

	reader.ReadString('\n')
	reader.ReadString('\n')

	for {
		s, er := reader.ReadString('\n')
		if er != nil {
			if errors.Is(err, io.EOF) {
				err = fmt.Errorf("nic name: %v not found", string(n))
			} else {
				err = fmt.Errorf("read new line error: %w", er)
			}
			break
		}
		if s == "" {
			continue
		}

		name, recv, tran := func(s string) (name, recv, tran string) {
			fields := strings.Fields(s)
			name = fields[0]
			recv = fields[1]
			tran = fields[9]
			return
		}(s)
		if !strings.HasPrefix(name, string(n)) {
			continue
		}

		n1, err = strconv.ParseUint(recv, 10, 64)
		if err != nil {
			err = fmt.Errorf("parse recv error: %w", err)
			break
		}
		n2, err = strconv.ParseUint(tran, 10, 64)
		if err != nil {
			err = fmt.Errorf("parse tran error: %w", err)
		}
		break
	}
	return
}
