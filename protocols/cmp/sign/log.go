package sign

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func GetOutputPrinter(address common.Address) (io.Writer, error) {
	filename := fmt.Sprintf("/opt/app/%s.log", strings.ToLower(address.Hex()))
	f, err := os.OpenFile(filename, os.O_CREATE, 0666)

	if err != nil {
		return nil, err
	}

	return f, nil
}
