// Copyright (C) 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpp_client

import (
	"fmt"
	"net"

	vppapi "git.fd.io/govpp.git/api"
	"github.com/calico-vpp/vpp-manager/vpp_client/vpp-1908-api/interfaces"
	vppip "github.com/calico-vpp/vpp-manager/vpp_client/vpp-1908-api/ip"
	"github.com/calico-vpp/vpp-manager/vpp_client/vpp-1908-api/tapv2"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

func CreateTapV2(ch vppapi.Channel, name string, tag string, macAddress [6]byte, hostMacAddr [6]byte) (swIfIndex uint32, err error) {
	// Tap interface setup
	response := &tapv2.TapCreateV2Reply{}
	request := &tapv2.TapCreateV2{
		ID:               ^uint32(0),
		HostNamespaceSet: 0,
		HostIfName:       []byte(name),
		HostIfNameSet:    1,
		Tag:              []byte(tag),
		MacAddress:       macAddress[:],
		HostMacAddr:      hostMacAddr[:],
		HostMacAddrSet:   1,
	}
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(0), errors.Wrap(err, "error creating tap in vpp")
	} else if response.Retval != 0 {
		return ^uint32(0), fmt.Errorf("error creating tap: retval %d", response.Retval)
	}
	if response.Retval != 0 {
		return ^uint32(0), errors.Wrapf(err, "vpp tap creation failed with code %d. Request: %+v", response.Retval, request)
	}
	return response.SwIfIndex, nil
}

func SetIntUp(ch vppapi.Channel, swIfIndex uint32) error {
	AdminUpRequest := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   swIfIndex,
		AdminUpDown: 1,
	}
	AdminUpResponse := &interfaces.SwInterfaceSetFlagsReply{}
	err := ch.SendRequest(AdminUpRequest).ReceiveReply(AdminUpResponse)
	if err != nil || AdminUpResponse.Retval != 0 {
		return fmt.Errorf("setting interface %d up failed: %d %v", swIfIndex, AdminUpResponse.Retval, err)
	}
	return nil
}

func AddrAdd(ch vppapi.Channel, swIfIndex uint32, addr netlink.Addr) error {
	prefLen, _ := addr.Mask.Size()
	addrAddRequest := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex:     swIfIndex,
		IsAdd:         1,
		AddressLength: uint8(prefLen),
		Address:       addr.IP.To4(),
	}
	addrAddResponse := &interfaces.SwInterfaceAddDelAddressReply{}
	err := ch.SendRequest(addrAddRequest).ReceiveReply(addrAddResponse)
	if err != nil || addrAddResponse.Retval != 0 {
		return fmt.Errorf("cannot add address %v to interface %d in VPP: %v %d",
			addr, swIfIndex, err, addrAddResponse.Retval)
	}
	return nil
}

func toVppAddress(addr net.IP) vppip.Address {
	a := vppip.Address{}
	if addr.To4() == nil {
		a.Af = vppip.ADDRESS_IP6
		ip := [16]uint8{}
		copy(ip[:], addr)
		a.Un = vppip.AddressUnionIP6(ip)
	} else {
		a.Af = vppip.ADDRESS_IP4
		ip := [4]uint8{}
		copy(ip[:], addr.To4())
		a.Un = vppip.AddressUnionIP4(ip)
	}
	return a
}

func NeighAdd(ch vppapi.Channel, swIfIndex uint32, mac [6]byte, addr net.IP) error {
	neighAddRequest := &vppip.IPNeighborAddDel{
		IsAdd: 1,
		Neighbor: vppip.IPNeighbor{
			SwIfIndex:  swIfIndex,
			Flags:      vppip.IP_API_NEIGHBOR_FLAG_STATIC,
			MacAddress: mac,
			IPAddress:  toVppAddress(addr),
		},
	}
	neighAddReply := &vppip.IPNeighborAddDelReply{}
	err := ch.SendRequest(neighAddRequest).ReceiveReply(neighAddReply)
	if err != nil || neighAddReply.Retval != 0 {
		return fmt.Errorf("cannot add neighbor in VPP: %v %d", err, neighAddReply.Retval)
	}
	return nil
}

func PuntRedirect(ch vppapi.Channel, sourceSwIfIndex, destSwIfIndex uint32, nh net.IP) error {
	puntRequest := &vppip.IPPuntRedirect{
		Punt: vppip.PuntRedirect{
			RxSwIfIndex: sourceSwIfIndex,
			TxSwIfIndex: destSwIfIndex,
			Nh:          toVppAddress(nh),
		},
		IsAdd: 1,
	}
	puntResponse := &vppip.IPPuntRedirectReply{}
	err := ch.SendRequest(puntRequest).ReceiveReply(puntResponse)
	if err != nil || puntResponse.Retval != 0 {
		return fmt.Errorf("cannot set punt in VPP: %v %d", err, puntResponse.Retval)
	}
	return nil
}

func RouteAdd(ch vppapi.Channel, swIfIndex uint32, dst net.IPNet, gw net.IP) error {
	prefixLen, _ := dst.Mask.Size()
	a := toVppAddress(gw)
	request := &vppip.IPRouteAddDel{
		IsAdd:       1,
		IsMultipath: 0,
		Route: vppip.IPRoute{
			TableID: 0,
			Prefix: vppip.Prefix{
				Len:     uint8(prefixLen),
				Address: toVppAddress(dst.IP),
			},
			Paths: []vppip.FibPath{
				{
					SwIfIndex:  swIfIndex,
					TableID:    0,
					RpfID:      0,
					Weight:     1,
					Preference: 0,
					Type:       vppip.FIB_API_PATH_TYPE_NORMAL,
					Flags:      vppip.FIB_API_PATH_FLAG_NONE,
					Proto:      vppip.FIB_API_PATH_NH_PROTO_IP4,
					Nh: vppip.FibPathNh{
						Address: a.Un,
					},
				},
			},
		},
	}
	response := &vppip.IPRouteAddDelReply{}
	err := ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("cannot add route %s via %s in VPP: %v %d", dst, gw, err, response.Retval)
	}
	return nil
}
