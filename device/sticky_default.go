//go:build !linux

package device

import (
	"github.com/limbo127/wireguard-go/conn"
	"github.com/limbo127/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
