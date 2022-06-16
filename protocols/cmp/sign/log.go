package sign

import (
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func GetOutputPrinter(address common.Address) (*os.File, error) {
	filename := fmt.Sprintf("/opt/app/%s.log", strings.ToLower(address.Hex()))
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.ModeAppend)

	if err != nil {
		return nil, err
	}

	println("Logging to", filename)

	return f, nil
}
