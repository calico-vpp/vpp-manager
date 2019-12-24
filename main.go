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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	VppConfigFile        = "/etc/vpp/startup.conf"
	VppPath              = "/usr/bin/vpp"
	IpConfigEnvVar       = "CALICOVPP_IP_CONFIG"
	InterfaceEnvVar      = "CALICOVPP_INTERFACE"
	ConfigTemplateEnvVar = "CALICOVPP_CONFIG_TEMPLATE"
)

var (
	vppProcess    *os.Process
	runningCond   *sync.Cond
	initialConfig interfaceConfig
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
		return errors.Wrapf(err, "Cannot find interface named %s", linkName)
	}
	// Grab PCI id and driver ID
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", linkName)
	devicePath, err := os.Readlink(deviceLinkPath)
	if err != nil {
		return errors.Wrapf(err, "Cannot find pci device for %s. Is the device available in Linux? If not, specify the PCI id directly.")
	}
	initialConfig.pciId = strings.TrimLeft(devicePath, "./")
	driverLinkPath := fmt.Sprintf("/sys/class/net/%s/device/driver", linkName)
	driverPath, err := os.Readlink(driverLinkPath)
	if err != nil {
		return errors.Wrapf(err, "Cannot find driver for %s. Is the device available in Linux? If not, specify the PCI id directly.")
	}
	initialConfig.driver = strings.TrimLeft(driverPath, "./")
	initialConfig.isUp = (link.Attrs().Flags & net.FlagUp) != 0
	if initialConfig.isUp {
		// Grab addresses and routes
		initialConfig.addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "Cannot list %s addresses", linkName)
		}
		initialConfig.routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "Cannot list %s routes", linkName)
		}
	}
	log.Infof("Initial device config: %+v", initialConfig)
	return nil
}

func swapDriver(pciDevice, newDriver string) error {
	unbindPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver/unbind", pciDevice)
	err := ioutil.WriteFile(unbindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "Error unbinding %s", pciDevice)
	}
	bindPath := fmt.Sprintf("/sys/bus/pci/drivers/%s/bind", newDriver)
	err = ioutil.WriteFile(bindPath, []byte(pciDevice), 0200)
	if err != nil {
		return errors.Wrapf(err, "Error binding %s to %s", pciDevice, newDriver)
	}
	return nil
}

// Set interface down if it is up, bind it to a VPP-friendly driver
func prepareInterface() error {
	if initialConfig.isUp {
		link, err := netlink.LinkByName(initialConfig.name)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", initialConfig.name)
		}
		err = netlink.LinkSetDown(link)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s down", initialConfig.name)
		}
	}
	return nil
}

func restoreLinuxConfig() error {
	// No need to delete the tap we created with VPP since it should disappear with all its configuration
	// when VPP dies
	err := swapDriver(initialConfig.pciId, initialConfig.driver)
	if err != nil {
		return errors.Wrapf(err, "Error swapping back driver to %s for %s", initialConfig.driver, initialConfig.pciId)
	}
	if initialConfig.isUp {
		// This assumes the link has kept the same name after the rebind. Is it always true?
		link, err := netlink.LinkByName(initialConfig.name)
		if err != nil {
			return errors.Wrapf(err, "Error finding link %s", initialConfig.name)
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrapf(err, "Error setting link %s back up", initialConfig.name)
		}
		// Re-add all adresses and routes
		failed := false
		for _, addr := range initialConfig.addresses {
			err := netlink.AddrAdd(link, &addr)
			if err != nil {
				log.Errorf("Cannot add address %+v back to %s", addr, link.Attrs().Name)
				failed = true
				// Keep going for the rest of the config
			}
		}
		for _, route := range initialConfig.routes {
			err := netlink.RouteAdd(&route)
			if err != nil {
				log.Errorf("Cannot add route %+v back to %s", route, link.Attrs().Name)
				failed = true
				// Keep going for the rest of the config
			}
		}
		if failed {
			return fmt.Errorf("Reconfiguration of some addresses or routes failed for %s", link.Attrs().Name)
		}
	}
	return nil
}

func generateVppConfigFile() error {
	template := os.Getenv(ConfigTemplateEnvVar)
	if template == "" {
		return fmt.Errorf("Empty VPP configuration template. Set a template in the %s environment variable.", ConfigTemplateEnvVar)
	}
	// Trivial rendering for the moment...
	template = strings.ReplaceAll(template, "__PCI_DEVICE_ID__", initialConfig.pciId)

	return errors.Wrapf(
		ioutil.WriteFile(VppConfigFile, []byte(template), 0644),
		"Error writing VPP configuration to %s",
		VppConfigFile,
	)
}

func configureVpp() error {
	// Get an API connection, with a few retries to accomodate VPP startup time

	// Do the actual VPP and Linux configuration
	return nil
}

func updateCalicoNode() error {
	return nil
}

// Returns VPP exit code
func runVpp(confSource string) (int, error) {
	err := prepareInterface()
	if err != nil {
		return 0, errors.Wrap(err, "Error preparing interface for VPP")
	}

	vppCmd := exec.Command(VppPath, "-c", VppConfigFile)
	vppCmd.Stdout = os.Stdout
	vppCmd.Stderr = os.Stderr
	err = vppCmd.Start()
	// From this point it is very important that every exit path calls restoreLinuxConfig after vpp exits
	vppProcess = vppCmd.Process
	log.Infof("VPP started. PID: %d", vppCmd.ProcessState.Pid())
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
	switch err.(type) {
	case *exec.ExitError:
		exitCode = err.(*exec.ExitError).ExitCode()
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
