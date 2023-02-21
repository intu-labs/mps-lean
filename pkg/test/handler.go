package test

import (
	"fmt"

	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				fmt.Print("\n CLOSE", id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			go network.Send(msg)
			fmt.Print("\n OPEN", id)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)
			fmt.Print("\n Incoming", id)
		}
	}
}
