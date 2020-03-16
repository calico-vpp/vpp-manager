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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoopts "github.com/projectcalico/libcalico-go/lib/options"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	DataInterfaceSwIfIndex        = uint32(1) // Assumption: the VPP config ensures this is true
	VppConfigFile                 = "/etc/vpp/startup.conf"
	VppConfigExecFile             = "/etc/vpp/startup.exec"
	VppManagerStatusFile          = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile          = "/var/run/vpp/vppmanagertap0"
	VppApiSocket                  = "/var/run/vpp/vpp-api.sock"
	VppPath                       = "/usr/bin/vpp"
	IpConfigEnvVar                = "CALICOVPP_IP_CONFIG"
	InterfaceEnvVar               = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar          = "CALICOVPP_CONFIG_TEMPLATE"
	ConfigExecTemplateEnvVar      = "CALICOVPP_CONFIG_EXEC_TEMPLATE"
	VppStartupSleepEnvVar         = "CALICOVPP_VPP_STARTUP_SLEEP"
	ServicePrefixEnvVar           = "SERVICE_PREFIX"
	HostIfName                    = "vpptap0"
	HostIfTag                     = "hosttap"
	VppTapAddrPrefixLen           = 30
	vppSideMacAddressString       = "02:00:00:00:00:02"
	containerSideMacAddressString = "02:00:00:00:00:01"
	vppFakeNextHopAddrString      = "169.254.254.254"
	vppTapAddrString              = "169.254.254.253"
	vppFakeNextHopIP6String       = "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	vppTapIP6String               = "fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
)

var (
	vppProcess    *os.Process
	runningCond   *sync.Cond
	initialConfig interfaceConfig
	params        vppManagerParams
	vpp           *vpplink.VppLink
)

type interfaceConfig struct {
	pciId     string
	driver    string
	isUp      bool
	addresses []netlink.Addr
	routes    []netlink.Route
}

type vppManagerParams struct {
	vppStartupSleepSeconds  int
	mainInterface           string
	configExecTemplate      string
	configTemplate          string
	nodeName                string
	serviceNet              *net.IPNet
	vppIpConfSource         string
	vppSideMacAddress       net.HardwareAddr
	containerSideMacAddress net.HardwareAddr
	vppFakeNextHopAddr      net.IP
	vppTapAddr              net.IP
	vppFakeNextHopIP6       net.IP
	vppTapIP6               net.IP
}

func parseEnvVariables() (err error) {
	vppStartupSleep := os.Getenv(VppStartupSleepEnvVar)
	if vppStartupSleep == "" {
		params.vppStartupSleepSeconds = 0
	} else {
		i, err := strconv.ParseInt(vppStartupSleep, 10, 32)
		params.vppStartupSleepSeconds = int(i)
		if err != nil {
			return errors.Wrapf(err, "Error Parsing %s", VppStartupSleepEnvVar)
		}
	}

	params.mainInterface = os.Getenv(InterfaceEnvVar)
	if params.mainInterface == "" {
		return errors.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
	}

	params.configExecTemplate = os.Getenv(ConfigExecTemplateEnvVar)

	params.configTemplate = os.Getenv(ConfigTemplateEnvVar)
	if params.configTemplate == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}

	params.nodeName = os.Getenv("NODENAME")
	if params.nodeName == "" {
		return errors.Errorf("No node name specified. Specify the NODENAME environment variable")
	}

	servicePrefixStr := os.Getenv(ServicePrefixEnvVar)
	_, params.serviceNet, err = net.ParseCIDR(servicePrefixStr)
	if err != nil {
		return errors.Errorf("invalid service prefix configuration: %s %s", servicePrefixStr, err)
	}

	params.vppIpConfSource = os.Getenv(IpConfigEnvVar)
	if params.vppIpConfSource != "linux" { // TODO add other sources
		return errors.Errorf("No ip configuration source specified. Specify one of linux, [[calico or dhcp]] through the %s environment variable", IpConfigEnvVar)
	}

	params.vppSideMacAddress, err = net.ParseMAC(vppSideMacAddressString)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse mac: %s", vppSideMacAddressString)
	}
	params.containerSideMacAddress, err = net.ParseMAC(containerSideMacAddressString)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse mac: %s", containerSideMacAddressString)
	}
	params.vppFakeNextHopAddr = net.ParseIP(vppFakeNextHopAddrString)
	if params.vppFakeNextHopAddr == nil {
		return errors.Errorf("Unable to parse IP: %s", vppFakeNextHopAddrString)
	}
	params.vppTapAddr = net.ParseIP(vppTapAddrString)
	if params.vppTapAddr == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapAddrString)
	}
	params.vppFakeNextHopIP6 = net.ParseIP(vppFakeNextHopIP6String)
	if params.vppFakeNextHopIP6 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppFakeNextHopIP6String)
	}
	params.vppTapIP6 = net.ParseIP(vppTapIP6String)
	if params.vppTapIP6 == nil {
		return errors.Errorf("Unable to parse IP: %s", vppTapIP6String)
	}
	return nil
}

func handleSignals() {
	signals := make(chan os.Signal, 10)
	signal.Notify(signals)
	for {
		s := <-signals
		if vppProcess == nil {
			runningCond.L.Lock()
			for vppProcess == nil {
				runningCond.Wait()
			}
			runningCond.L.Unlock()
		}
		// Just forward all signals to VPP
		vppProcess.Signal(s)
	}
}

func getLinuxConfig() error {
	link, err := netlink.LinkByName(params.mainInterface)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", params.mainInterface)
	}
	initialConfig.isUp = (link.Attrs().Flags & net.FlagUp) != 0
	if initialConfig.isUp {
		// Grab addresses and routes
		initialConfig.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s addresses", params.mainInterface)
		}
		initialConfig.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s routes", params.mainInterface)
		}
	}
	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", params.mainInterface)
	devicePath, err := os.Readlink(deviceLinkPath)
	if err != nil {
		log.Warnf("cannot find pci device for %s : %s", params.mainInterface, err)
		return nil
	}
	initialConfig.pciId = strings.TrimLeft(devicePath, "./")
	// Grab Driver id
	driverLinkPath := fmt.Sprintf("/sys/class/net/%s/device/driver", params.mainInterface)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		log.Warnf("cannot find driver for %s : %s", params.mainInterface, err)
		return nil
	}
	initialConfig.driver = driverPath[strings.LastIndex(driverPath, "/")+1:]
	log.Infof("Initial device config: %+v", initialConfig)
	return nil
}

func isDriverLoaded(driver string) (bool, error) {
	_, err := os.Stat("/sys/bus/pci/drivers/" + driver)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func checkDrivers() {
	vfioLoaded, err := isDriverLoaded("vfio-pci")
	if err != nil {
		log.Warnf("error determining whether vfio-pci is loaded")
	}
	uioLoaded, err := isDriverLoaded("uio_pci_generic")
	if err != nil {
		log.Warnf("error determining whether vfio-pci is loaded")
	}
	if !vfioLoaded && !uioLoaded {
		log.Warnf("did not find vfio-pci or uio_pci_generic driver")
		log.Warnf("VPP may fail to grab its interface")
	}
}

func swapDriver(pciDevice, newDriver string) error {
	unbindPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver/unbind", pciDevice)
	err := ioutil.WriteFile(unbindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "error unbinding %s", pciDevice)
	}
	bindPath := fmt.Sprintf("/sys/bus/pci/drivers/%s/bind", newDriver)
	err = ioutil.WriteFile(bindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "error binding %s to %s", pciDevice, newDriver)
	}
	return nil
}

func writeFile(state string, path string) error {
	err := ioutil.WriteFile(path, []byte(state+"\n"), 0400)
	if err != nil {
		return errors.Errorf("Failed to write state to %s", path)
	}
	return nil
}

// Set interface down if it is up, bind it to a VPP-friendly driver
func prepareInterface() error {
	if initialConfig.isUp {
		link, err := netlink.LinkByName(params.mainInterface)
		if err != nil {
			return errors.Wrapf(err, "error finding link %s", params.mainInterface)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			return errors.Wrapf(err, "error setting link %s down", params.mainInterface)
		}
	}
	return nil
}

func restoreLinuxConfig() (err error) {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	if initialConfig.pciId != "" && initialConfig.driver != "" {
		err := swapDriver(initialConfig.pciId, initialConfig.driver)
		if err != nil {
			return errors.Wrapf(err, "error swapping back driver to %s for %s", initialConfig.driver, initialConfig.pciId)
		}
	}
	if initialConfig.isUp {
		// This assumes the link has kept the same name after the rebind.
		// It should be always true on systemd based distros
		retries := 0
		var link netlink.Link
		for {
			link, err = netlink.LinkByName(params.mainInterface)
			if err != nil {
				retries += 1
				if retries >= 10 {
					return errors.Wrapf(err, "error finding link %s after %d tries", params.mainInterface, retries)
				}
				time.Sleep(500 * time.Millisecond)
			} else {
				log.Infof("found links %s after %d tries", params.mainInterface, retries)
				break
			}
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrapf(err, "error setting link %s back up", params.mainInterface)
		}
		// Re-add all adresses and routes
		failed := false
		for _, addr := range initialConfig.addresses {
			log.Infof("restoring address %s", addr.String())
			err := netlink.AddrAdd(link, &addr)
			if err != nil {
				log.Errorf("cannot add address %+v back to %s : %+v", addr, link.Attrs().Name, err)
				failed = true
				// Keep going for the rest of the config
			}
		}
		for _, route := range initialConfig.routes {
			log.Infof("restoring RouteList %s", route.String())
			err := netlink.RouteAdd(&route)
			if err != nil {
				log.Errorf("cannot add route %+v back to %s : %+v", route, link.Attrs().Name, err)
				failed = true
				// Keep going for the rest of the config
			}
		}
		if failed {
			return fmt.Errorf("reconfiguration of some addresses or routes failed for %s", link.Attrs().Name)
		}
	}
	return nil
}

func generateVppConfigExecFile() error {
	if params.configExecTemplate == "" {
		return nil
	}
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configExecTemplate, "__VPP_DATAPLANE_IF__", params.mainInterface)
	return errors.Wrapf(
		ioutil.WriteFile(VppConfigExecFile, []byte(template), 0644),
		"error writing VPP Exec configuration to %s",
		VppConfigFile,
	)
}

func generateVppConfigFile() error {
	// Trivial rendering for the moment...
	template := strings.ReplaceAll(params.configTemplate, "__PCI_DEVICE_ID__", initialConfig.pciId)
	return errors.Wrapf(
		ioutil.WriteFile(VppConfigFile, []byte(template), 0644),
		"error writing VPP configuration to %s",
		VppConfigFile,
	)
}

func removeInitialRoutes(link netlink.Link) {
	for _, route := range initialConfig.routes {
		log.Infof("deleting Route %s", route.String())
		err := netlink.RouteDel(&route)
		if err != nil {
			log.Errorf("cannot delete route %+v: %+v", route, err)
			// Keep going for the rest of the config
		}
	}
	for _, addr := range initialConfig.addresses {
		err := netlink.AddrDel(link, &addr)
		if err != nil {
			log.Errorf("error adding address %s to tap interface : %+v", addr, err)
		}
	}
}

func configureVpp() error {
	// Get an API connection, with a few retries to accomodate VPP startup time
	var err error
	for i := 0; i < 10; i++ {
		vpp, err = vpplink.NewVppLink(VppApiSocket, log.WithFields(log.Fields{"component": "vpp-api"}))
		if err != nil {
			log.Warnf("Cannot connect to VPP on socket %s try %d/10: %v", VppApiSocket, i, err)
			err = nil
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}
	defer vpp.Close()

	// Do the actual VPP and Linux configuration

	// Data interface configuration
	err = vpp.Retry(2*time.Second, 10, vpp.InterfaceAdminUp, DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting data interface up")
	}
	for _, addr := range initialConfig.addresses {
		log.Infof("Adding address %s to data interface", addr.String())
		err = vpp.AddInterfaceAddress(DataInterfaceSwIfIndex, addr.IPNet)
		if err != nil {
			return errors.Wrap(err, "error adding address to data interface")
		}
	}
	for _, route := range initialConfig.routes {
		// Only add routes with a next hop, assume the others come from interface addresses
		if route.Gw == nil || route.Dst == nil {
			continue
		}
		err = vpp.RouteAdd(&types.Route{
			SwIfIndex: DataInterfaceSwIfIndex,
			Dst:       route.Dst,
			Gw:        route.Gw,
		})
		if err != nil {
			return errors.Wrap(err, "cannot add route in vpp")
		}
	}

	log.Infof("Creating Linux side interface")
	tapSwIfIndex, err := vpp.CreateTapV2(&types.TapV2{
		ContNS:         HostIfName,
		ContIfName:     HostIfTag,
		MacAddress:     params.vppSideMacAddress,
		HostMacAddress: params.containerSideMacAddress,
	})
	if err != nil {
		return errors.Wrap(err, "error creating tap")
	}
	err = writeFile(strconv.FormatInt(int64(tapSwIfIndex), 10), VppManagerTapIdxFile)
	if err != nil {
		return errors.Wrap(err, "error writing tap idx")
	}

	err = vpp.InterfaceAdminUp(tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting tap up")
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   params.vppTapAddr,
			Mask: net.CIDRMask(VppTapAddrPrefixLen, 32),
		},
	}
	err = vpp.AddInterfaceAddress(tapSwIfIndex, addr.IPNet)
	if err != nil {
		return errors.Wrap(err, "error adding address to tap")
	}
	err = vpp.AddNeighbor(&types.Neighbor{
		SwIfIndex:    tapSwIfIndex,
		IP:           params.vppFakeNextHopAddr,
		HardwareAddr: params.containerSideMacAddress,
	})
	if err != nil {
		return errors.Wrap(err, "error adding neighbor to tap")
	}
	err = vpp.PuntRedirect(vpplink.INVALID_SW_IF_INDEX, tapSwIfIndex, params.vppFakeNextHopAddr)
	if err != nil {
		return errors.Wrap(err, "error adding redirect to tap")
	}

	// If main interface flush its routes or they'll conflict with $HostIfName
	link, err := netlink.LinkByName(params.mainInterface)
	if err == nil {
		isUp := (link.Attrs().Flags & net.FlagUp) != 0
		if isUp {
			removeInitialRoutes(link)
		}
	}

	// Linux side tap setup
	link, err = netlink.LinkByName(HostIfName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", HostIfName)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return errors.Wrapf(err, "error setting tap %s up", HostIfName)
	}
	// Add /32 for each address configured on VPP side
	for _, addr := range initialConfig.addresses {
		if addr.IP.To4() == nil {
			continue // TODO
		}
		singleAddr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   addr.IP,
				Mask: net.CIDRMask(32, 32),
			},
			Label: HostIfName,
		}
		log.Infof("Adding address %+v to tap interface", singleAddr)
		err = netlink.AddrAdd(link, &singleAddr)
		if err != nil {
			return errors.Wrapf(err, "error adding address %s to tap interface", singleAddr)
		}
	}
	// "dummy" next-hop directly connected on the tap interface (route + neighbor)
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   params.vppTapAddr,
			Mask: net.CIDRMask(32, 32),
		},
		Scope: netlink.SCOPE_LINK,
	})
	if err != nil {
		return errors.Wrap(err, "cannot add connected route to tap")
	}
	err = netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           params.vppTapAddr,
		HardwareAddr: params.vppSideMacAddress[:],
	})
	if err != nil {
		return errors.Wrap(err, "cannot add neighbor to tap")
	}
	// Add a route for the service prefix through VPP
	log.Infof("adding route to service prefix %s through VPP", params.serviceNet.String())
	err = netlink.RouteAdd(&netlink.Route{
		Dst:       params.serviceNet,
		LinkIndex: link.Attrs().Index,
		Gw:        params.vppTapAddr,
	})
	if err != nil {
		return errors.Wrap(err, "cannot add service route to tap")
	}

	// All routes that were on this interface now go through VPP
	for _, route := range initialConfig.routes {
		if route.Dst == nil || route.Dst.IP.To4() == nil {
			continue //TODO
		}
		newRoute := netlink.Route{
			Dst:       route.Dst,
			LinkIndex: link.Attrs().Index,
			Gw:        params.vppTapAddr,
		}
		log.Infof("Adding route %+v via VPP", newRoute)
		err = netlink.RouteAdd(&newRoute)
		if err == syscall.EEXIST {
			log.Warnf("cannot add route %+v via vpp, %+v", newRoute, err)
		} else if err != nil {
			return errors.Wrapf(err, "cannot add route %+v via vpp", newRoute)
		}
	}

	// TODO should watch for service prefix and ip pools to always route them through VPP
	// Service prefix is needed even if kube-proxy is running on the host to ensure correct source address selection
	return nil
}

func updateCalicoNode() error {
	client, err := calicocli.NewFromEnv()
	if err != nil {
		return errors.Wrap(err, "error creating calico client")
	}
	node, err := client.Nodes().Get(context.Background(), params.nodeName, calicoopts.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "cannot get current node from Calico")
		// TODO create if doesn't exist? need to be careful to do it atomically... and everyone else must as well.
	}
	var currentConf string
	if node.Spec.BGP == nil {
		log.Infof("node currently has no BGP config")
		currentConf = ""
	} else {
		currentConf = node.Spec.BGP.IPv4Address
		log.Infof("current node IP configuration: %s", currentConf)
	}
	var nodeIP string
	for _, a := range initialConfig.addresses {
		if a.IP.To4() == nil {
			continue // TODO handle IPv6
		}
		nodeIP = a.IPNet.String()
		break
	}
	if nodeIP == "" {
		return fmt.Errorf("no address found for node")
	}
	log.Infof("using %s as node IP for Calico", nodeIP)
	if nodeIP == currentConf {
		return nil // Nothing to do
	}
	// Update node with address
	if node.Spec.BGP == nil {
		node.Spec.BGP = &calicoapi.NodeBGPSpec{
			IPv4Address: nodeIP,
		}
	} else {
		node.Spec.BGP.IPv4Address = nodeIP
	}
	updated, err := client.Nodes().Update(context.Background(), node, calicoopts.SetOptions{})
	// TODO handle update error / retry if object changed in the meantime
	log.Infof("updated node: %+v", updated)
	return errors.Wrapf(err, "error updating node %s", params.nodeName)
}

// Returns VPP exit code
func runVpp() (int, error) {
	err := prepareInterface()
	// From this point it is very important that every exit path calls restoreLinuxConfig after vpp exits
	if err != nil {
		restoreLinuxConfig()
		return 0, errors.Wrap(err, "Error preparing interface for VPP")
	}

	vppCmd := exec.Command(VppPath, "-c", VppConfigFile)
	vppCmd.Stdout = os.Stdout
	vppCmd.Stderr = os.Stderr
	err = vppCmd.Start()
	if err != nil {
		restoreLinuxConfig()
		return 0, errors.Wrap(err, "error starting vpp process")
	}
	vppProcess = vppCmd.Process
	log.Infof("VPP started. PID: %d", vppProcess.Pid)
	runningCond.Broadcast()

	// If needed, wait some time that vpp boots up
	time.Sleep(time.Duration(params.vppStartupSleepSeconds) * time.Second)

	// Configure VPP
	err = configureVpp()
	if err != nil {
		// Send a SIGINT to VPP to stop it
		log.Errorf("Error configuring VPP: %v", err)
		vppProcess.Signal(syscall.SIGINT)
	}

	// Update the Calico node with the IP address actually configured on VPP
	err = updateCalicoNode()
	if err != nil {
		log.Errorf("Error updating Calico node: %v", err)
		vppProcess.Signal(syscall.SIGINT)
	}

	go syncPools()

	writeFile("1", VppManagerStatusFile)
	vppErr := vppCmd.Wait()
	log.Infof("VPP Exited: status %v", err)
	err = clearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing vpp manager files: %v", err)
	}
	err = restoreLinuxConfig()
	if err != nil {
		log.Errorf("Error restoring linux config: %v", err)
	}
	switch e := vppErr.(type) {
	case *exec.ExitError:
		return e.ExitCode(), nil
	case nil: // k8 cni removal
		return 0, nil
	default:
		log.Errorf("Error handling vpp process: %v", vppErr)
		return 0, nil
	}
}

func configureContainer() error {
	lim := syscall.Rlimit{
		Cur: ^uint64(0),
		Max: ^uint64(0),
	}
	err := syscall.Setrlimit(8, &lim) // 8 - RLIMIT_MEMLOCK
	return errors.Wrap(err, "Error raising memlock limit, VPP may fail to start")
}

func clearVppManagerFiles() error {
	err := writeFile("0", VppManagerStatusFile)
	if err != nil {
		return err
	}
	return writeFile("-1", VppManagerTapIdxFile)
}

func main() {
	err := clearVppManagerFiles()
	if err != nil {
		log.Errorf("Error clearing config files: %+v", err)
		return
	}
	err = parseEnvVariables()
	if err != nil {
		log.Errorf("Error parsing env varibales: %+v", err)
		return
	}

	err = configureContainer()
	if err != nil {
		log.Errorf("Error during initial config:")
	}

	checkDrivers()

	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()

	err = getLinuxConfig()
	if err != nil {
		log.Errorf("Error getting initial interface configuration: %s", err)
		return
	}

	err = generateVppConfigExecFile()
	if err != nil {
		log.Errorf("Error generating VPP config Exec: %s", err)
		return
	}
	err = generateVppConfigFile()
	if err != nil {
		log.Errorf("Error generating VPP config: %s", err)
		return
	}
	exitCode, err := runVpp()
	if err != nil {
		log.Errorf("Error running VPP: %v", err)
	}
	os.Exit(exitCode)
}
