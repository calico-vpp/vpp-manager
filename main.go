package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.fd.io/govpp.git"
	vppapi "git.fd.io/govpp.git/api"
	vppcore "git.fd.io/govpp.git/core"
	"github.com/calico-vpp/vpp-manager/vpp-1908-api/interfaces"
	vppip "github.com/calico-vpp/vpp-manager/vpp-1908-api/ip"
	"github.com/calico-vpp/vpp-manager/vpp-1908-api/tapv2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	VppConfigFile        = "/etc/vpp/startup.conf"
	VppApiSocket         = "/var/run/vpp/vpp-api.sock"
	VppPath              = "/usr/bin/vpp"
	IpConfigEnvVar       = "CALICOVPP_IP_CONFIG"
	InterfaceEnvVar      = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar = "CALICOVPP_CONFIG_TEMPLATE"
	HostIfName           = "vpptap0"
	HostIfTag            = "hosttap"
	VppTapAddrPrefixLen  = 30
)

var (
	vppProcess              *os.Process
	runningCond             *sync.Cond
	initialConfig           interfaceConfig
	vppSideMacAddress       = [6]byte{2, 0, 0, 0, 0, 2}
	containerSideMacAddress = [6]byte{2, 0, 0, 0, 0, 1}
	vppFakeNextHopAddr      = net.IPv4(169, 254, 254, 254).To4()
	vppTapAddr              = net.IPv4(169, 254, 254, 253).To4()
)

type interfaceConfig struct {
	name      string
	pciId     string
	driver    string
	isUp      bool
	addresses []netlink.Addr
	routes    []netlink.Route
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

func getLinuxConfig(linkName string) error {
	initialConfig.name = linkName
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return errors.Wrapf(err, "cannot find interface named %s", linkName)
	}
	// Grab PCI id and driver ID
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", linkName)
	devicePath, err := os.Readlink(deviceLinkPath)
	if err != nil {
		return errors.Wrapf(err, "cannot find pci device for %s", linkName)
	}
	initialConfig.pciId = strings.TrimLeft(devicePath, "./")
	driverLinkPath := fmt.Sprintf("/sys/class/net/%s/device/driver", linkName)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		return errors.Wrapf(err, "cannot find driver for %s", linkName)
	}
	initialConfig.driver = driverPath[strings.LastIndex(driverPath, "/")+1:]
	initialConfig.isUp = (link.Attrs().Flags & net.FlagUp) != 0
	if initialConfig.isUp {
		// Grab addresses and routes
		initialConfig.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s addresses", linkName)
		}
		initialConfig.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s routes", linkName)
		}
	}
	log.Infof("Initial device config: %+v", initialConfig)
	return nil
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

// Set interface down if it is up, bind it to a VPP-friendly driver
func prepareInterface() error {
	if initialConfig.isUp {
		link, err := netlink.LinkByName(initialConfig.name)
		if err != nil {
			return errors.Wrapf(err, "error finding link %s", initialConfig.name)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			return errors.Wrapf(err, "error setting link %s down", initialConfig.name)
		}
	}
	return nil
}

func restoreLinuxConfig() error {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	err := swapDriver(initialConfig.pciId, initialConfig.driver)
	if err != nil {
		return errors.Wrapf(err, "error swapping back driver to %s for %s", initialConfig.driver, initialConfig.pciId)
	}
	if initialConfig.isUp {
		// This assumes the link has kept the same name after the rebind. Is it always true?
		link, err := netlink.LinkByName(initialConfig.name)
		if err != nil {
			return errors.Wrapf(err, "error finding link %s", initialConfig.name)
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrapf(err, "error setting link %s back up", initialConfig.name)
		}
		// Re-add all adresses and routes
		failed := false
		for _, addr := range initialConfig.addresses {
			err := netlink.AddrAdd(link, &addr)
			if err != nil {
				log.Errorf("cannot add address %+v back to %s", addr, link.Attrs().Name)
				failed = true
				// Keep going for the rest of the config
			}
		}
		for _, route := range initialConfig.routes {
			err := netlink.RouteAdd(&route)
			if err != nil {
				log.Errorf("cannot add route %+v back to %s", route, link.Attrs().Name)
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

func generateVppConfigFile() error {
	template := os.Getenv(ConfigTemplateEnvVar)
	if template == "" {
		return fmt.Errorf("empty VPP configuration template, set a template in the %s environment variable", ConfigTemplateEnvVar)
	}
	// Trivial rendering for the moment...
	template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", initialConfig.pciId)

	return errors.Wrapf(
		ioutil.WriteFile(VppConfigFile, []byte(template), 0644),
		"error writing VPP configuration to %s",
		VppConfigFile,
	)
}

func setIntUp(ch vppapi.Channel, swIfIndex uint32) error {
	AdminUpRequest := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   swIfIndex,
		AdminUpDown: 1,
	}
	AdminUpResponse := &interfaces.SwInterfaceSetFlagsReply{}
	err := ch.SendRequest(AdminUpRequest).ReceiveReply(AdminUpResponse)
	return errors.Wrapf(err, "setting interface %d up failed", swIfIndex)
}

func addrAdd(ch vppapi.Channel, swIfIndex uint32, addr netlink.Addr) error {
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

func neighAdd(ch vppapi.Channel, swIfIndex uint32, mac [6]byte, addr net.IP) error {
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

func puntRedirect(ch vppapi.Channel, sourceSwIfIndex, destSwIfIndex uint32, nh net.IP) error {
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

func routeAdd(ch vppapi.Channel, swIfIndex uint32, dst net.IPNet, gw net.IP) error {
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
		return fmt.Errorf("cannot add route %s vis %s in VPP: %v %d", dst, gw, err, response.Retval)
	}
	return nil
}

func configureVpp() error {
	// Get an API connection, with a few retries to accomodate VPP startup time
	var conn *vppcore.Connection
	var err error
	for i := 0; i < 10; i++ {
		conn, err = govpp.Connect(VppApiSocket)
		if err != nil {
			log.Warnf("Cannot connect to VPP on socket %s try %d/10: %v", VppApiSocket, i, err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}
	if conn == nil {
		return fmt.Errorf("cannot connect to VPP after 10 tries")
	}
	defer conn.Disconnect()

	ch, err := conn.NewAPIChannel()
	if err != nil {
		log.Errorf("VPP API channel creation failed")
		return fmt.Errorf("channel creation failed")
	}
	defer ch.Close()

	// Do the actual VPP and Linux configuration

	// Data interface configuration
	dataIfIndex := uint32(1)
	err = setIntUp(ch, dataIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting data interface up")
	}
	for _, addr := range initialConfig.addresses {
		if addr.IP.To4() == nil {
			continue
		}
		log.Infof("Adding address %s to data interface", addr.String())
		err = addrAdd(ch, dataIfIndex, addr)
		if err != nil {
			return errors.Wrap(err, "error adding address to data interface")
		}
	}
	for _, route := range initialConfig.routes {
		// Only add routes with a next hop, assume the others come from interface addresses
		if route.Gw == nil {
			continue
		}
		if route.Dst.IP.To4() == nil {
			continue //TODO
		}
		err = routeAdd(ch, dataIfIndex, *route.Dst, route.Gw)
		if err != nil {
			return errors.Wrap(err, "cannot add route in vpp")
		}
	}

	// Tap interface setup
	response := &tapv2.TapCreateV2Reply{}
	request := &tapv2.TapCreateV2{
		ID:               ^uint32(0),
		HostNamespaceSet: 0,
		HostIfName:       []byte(HostIfName),
		HostIfNameSet:    1,
		Tag:              []byte(HostIfTag),
		MacAddress:       vppSideMacAddress[:],
		HostMacAddr:      containerSideMacAddress[:],
		HostMacAddrSet:   1,
	}
	log.Infof("Creating Linux side interface")
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "error creating tap in vpp")
	}
	if response.Retval != 0 {
		return errors.Wrapf(err, "vpp tap creation failed with code %d. Request: %+v", response.Retval, request)
	}
	tapSwIfIndex := response.SwIfIndex
	err = setIntUp(ch, tapSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error setting tap up")
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   vppTapAddr,
			Mask: net.CIDRMask(VppTapAddrPrefixLen, 32),
		},
	}
	err = addrAdd(ch, tapSwIfIndex, *addr)
	if err != nil {
		return errors.Wrap(err, "error adding address to tap")
	}
	err = neighAdd(ch, tapSwIfIndex, containerSideMacAddress, vppFakeNextHopAddr)
	if err != nil {
		return errors.Wrap(err, "error adding neighbor to tap")
	}
	err = puntRedirect(ch, dataIfIndex, tapSwIfIndex, vppFakeNextHopAddr)
	if err != nil {
		return errors.Wrap(err, "error adding redirect to tap")
	}

	// Linux side tap setup
	link, err := netlink.LinkByName(HostIfName)
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
		singleAddr := addr
		singleAddr.Mask = net.CIDRMask(32, 32)
		singleAddr.Label = HostIfName
		singleAddr.Broadcast = nil
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
			IP:   vppTapAddr,
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
		IP:           vppTapAddr,
		HardwareAddr: vppSideMacAddress[:],
	})
	if err != nil {
		return errors.Wrap(err, "cannot add neighbor to tap")
	}

	for _, route := range initialConfig.routes {
		if route.Dst.IP.To4() == nil {
			continue //TODO
		}
		newRoute := netlink.Route{
			Dst:       route.Dst,
			LinkIndex: link.Attrs().Index,
			Gw:        vppTapAddr,
		}
		log.Infof("Adding route %+v via VPP", newRoute)
		err = netlink.RouteAdd(&newRoute)
		if err != nil {
			return errors.Wrapf(err, "cannot add route %+v via vpp", newRoute)
		}
	}

	// TODO should watch for service prefix and ip pools to always route them through VPP
	// Service prefix is needed even if kube-proxy is running on the host to ensure correct source address selection
	return nil
}

func updateCalicoNode() error {
	return nil
}

// Returns VPP exit code
func runVpp(confSource string) (int, error) {
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

	// TODO add something that can be checked by k8s health check when VPP is up
	// or a flag to this program that checks both vpp status and the configuration status

	err = vppCmd.Wait()
	exitCode := 0
	log.Infof("VPP Exited: status %v", err)
	switch e := err.(type) {
	case *exec.ExitError:
		exitCode = e.ExitCode()
	default:
		log.Errorf("Error handling vpp process: %v", err)
	}

	return exitCode, errors.Wrap(restoreLinuxConfig(), "Error restoring linux config")
}

func main() {
	runningCond = sync.NewCond(&sync.Mutex{})
	go handleSignals()
	intf := os.Getenv(InterfaceEnvVar)
	if intf == "" {
		log.Errorf("No interface specified. Specify an interface through the %s environment variable", InterfaceEnvVar)
		return
	}
	vppIpConfSource := os.Getenv(IpConfigEnvVar)
	if vppIpConfSource != "linux" { // TODO add other sources
		log.Errorf("No ip configuration source specified. Specify one of linux, [[calico or dhcp]] through the %s environment variable", IpConfigEnvVar)
		return
	}
	err := getLinuxConfig(intf)
	if err != nil {
		log.Errorf("Error getting initial interface configuration: %s", err)
		return
	}
	err = generateVppConfigFile()
	if err != nil {
		log.Errorf("Error generating VPP config: %s", err)
		return
	}
	exitCode, err := runVpp(vppIpConfSource)
	if err != nil {
		log.Errorf("Error running VPP: %v", err)
	}
	os.Exit(exitCode)
}
