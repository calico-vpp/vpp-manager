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

package main

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/calico-vpp/vpplink"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type interfaceConfig struct {
	PciID     string
	Driver    string
	IsUp      bool
	Addresses []netlink.Addr
	Routes    []netlink.Route
}

func getInterfaceConfig() (conf interfaceConfig, err error) {
	conf, err = getLinuxConfig()
	if err == nil {
		err = saveConfig(conf)
		if err != nil {
			log.Warnf("Could not save interface config: %v", err)
		}
		return conf, nil
	}
	// Loading config failed, try loading from save file
	log.Warnf("Could not load config from linux, trying save file...")
	conf, err2 := loadSavedConfig()
	if err2 != nil {
		log.Warnf("Could not load saved config: %v", err2)
		// Return original error
		return conf, err
	}
	log.Infof("Loaded config. Interface marked as down since loading config from linux failed.")
	// This ensures we don't try to set the interface down in runVpp()
	conf.IsUp = false
	return conf, nil
}

func getLinuxConfig() (initialConfig interfaceConfig, err error) {
	link, err := netlink.LinkByName(params.mainInterface)
	if err != nil {
		return initialConfig, errors.Wrapf(err, "cannot find interface named %s", params.mainInterface)
	}
	initialConfig.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if initialConfig.IsUp {
		// Grab addresses and routes
		initialConfig.Addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return initialConfig, errors.Wrapf(err, "cannot list %s addresses", params.mainInterface)
		}
		initialConfig.Routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return initialConfig, errors.Wrapf(err, "cannot list %s routes", params.mainInterface)
		}
	}
	params.nodeIP4 = getNodeAddress(initialConfig, false)
	params.nodeIP6 = getNodeAddress(initialConfig, true)
	params.hasv4 = (params.nodeIP4 != "")
	params.hasv6 = (params.nodeIP6 != "")
	if !params.hasv4 && !params.hasv6 {
		return initialConfig, errors.Errorf("no address found for node")
	}
	log.Infof("Node IP4 %s , Node IP6 %s", params.nodeIP4, params.nodeIP6)

	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", params.mainInterface)
	devicePath, err := os.Readlink(deviceLinkPath)
	if err != nil {
		log.Warnf("cannot find pci device for %s : %s", params.mainInterface, err)
		return initialConfig, nil
	}
	initialConfig.PciID = strings.TrimLeft(devicePath, "./")
	// Grab Driver id
	driverLinkPath := fmt.Sprintf("/sys/class/net/%s/device/driver", params.mainInterface)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		log.Warnf("cannot find driver for %s : %s", params.mainInterface, err)
		return initialConfig, nil
	}
	initialConfig.Driver = driverPath[strings.LastIndex(driverPath, "/")+1:]
	log.Infof("Initial device config: %+v", initialConfig)
	return initialConfig, nil
}

func getNodeAddress(conf interfaceConfig, isV6 bool) string {
	for _, addr := range conf.Addresses {
		if vpplink.IsIP6(addr.IP) == isV6 {
			return addr.IPNet.String()
		}
	}
	return ""
}

func clearSavedConfig() {
	if params.ifConfigSavePath == "" {
		return
	}
	err := os.Remove(params.ifConfigSavePath)
	if err != nil {
		log.Warnf("could not delete saved interface config: %v", err)
	}
}

func saveConfig(conf interfaceConfig) error {
	if params.ifConfigSavePath == "" {
		return nil
	}
	file, err := os.Create(params.ifConfigSavePath)
	if err != nil {
		return errors.Wrap(err, "error opening save file")
	}
	enc := gob.NewEncoder(file)
	err = enc.Encode(conf)
	if err != nil {
		file.Close()
		clearSavedConfig()
		return errors.Wrap(err, "error encoding data")
	}
	err = file.Close()
	if err != nil {
		return errors.Wrap(err, "error closing file")
	}
	return nil
}

func loadSavedConfig() (conf interfaceConfig, err error) {
	if params.ifConfigSavePath == "" {
		return conf, fmt.Errorf("interface config save file not configured")
	}
	file, err := os.Open(params.ifConfigSavePath)
	if err != nil {
		return conf, errors.Wrap(err, "error opening save file")
	}
	dec := gob.NewDecoder(file)
	err = dec.Decode(&conf)
	if err != nil {
		return conf, errors.Wrap(err, "decode error")
	}
	file.Close()
	return conf, nil
}
