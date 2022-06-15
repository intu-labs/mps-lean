package sign

import (
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/k0kubun/pp/v3"
)

func GetOutputPrinter(address common.Address) (*pp.PrettyPrinter, error) {
	printer := pp.New()

	// Create a struct describing your scheme
	scheme := pp.ColorScheme{
		Integer:         pp.Green | pp.Bold,
		Float:           pp.Black | pp.BackgroundWhite | pp.Bold,
		String:          pp.Red,
		EscapedChar:     pp.Magenta,
		StringQuotation: pp.Red | pp.Bold,
	}
	f, err := os.Open(fmt.Sprintf("/opt/app/%s.log", strings.ToLower(address.Hex())))

	if err != nil {
		return nil, err
	}

	printer.SetColorScheme(scheme)
	printer.SetOutput(f)

	return printer, nil
}
