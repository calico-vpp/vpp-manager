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
	"net"
	"syscall"

	"github.com/calico-vpp/vpplink"
	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func getNetworkRoute(network string) (route *netlink.Route, err error) {
	var gw net.IP
	log.Infof("ip pool %s added", network)
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}

	link, err := netlink.LinkByName(HostIfName)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find interface named %s", HostIfName)
	}

	if vpplink.IsIP4(cidr.IP) {
		gw = params.vppTapIP4
	} else {
		gw = params.vppTapIP6
	}

	return &netlink.Route{
		Dst:       cidr,
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
	}, nil
}

func poolAdded(network string) error {
	route, err := getNetworkRoute(network)
	if err != nil {
		return errors.Wrap(err, "Error adding net")
	}
	err = netlink.RouteReplace(route)
	return errors.Wrapf(err, "cannot add pool route %s through vpp tap", network)
}

func poolDeleted(network string) error {
	route, err := getNetworkRoute(network)
	if err != nil {
		return errors.Wrap(err, "Error deleting net")
	}
	err = netlink.RouteDel(route)
	return errors.Wrapf(err, "cannot delete pool route %s through vpp tap", network)
}

func poolSyncError(err error) error {
	log.Errorf("Pool synchronisation error: %v", err)
	// Tell VPP to exit so this program stops
	signalVpp(syscall.SIGINT)
	return err
}

func syncPools() error {
	pools := make(map[string]interface{})
	client, err := calicocli.NewFromEnv()
	if err != nil {
		return poolSyncError(errors.Wrap(err, "error creating calico client"))
	}

	log.Info("starting pools watcher...")
	for {
		poolsList, err := client.IPPools().List(context.Background(), options.ListOptions{})
		if err != nil {
			return poolSyncError(errors.Wrap(err, "error listing pools"))
		}
		sweepMap := make(map[string]interface{})
		for _, pool := range poolsList.Items {
			key := pool.Spec.CIDR
			sweepMap[key] = nil
			_, exists := pools[key]
			if !exists {
				pools[key] = nil
				err = poolAdded(key)
				if err != nil {
					return poolSyncError(errors.Wrap(err, "error adding pool %s"))
				}
			}
		}
		// Sweep phase
		for key, _ := range pools {
			_, found := sweepMap[key]
			if !found {
				err = poolDeleted(key)
				if err != nil {
					return poolSyncError(errors.Wrap(err, "error deleting pool %s"))
				}
				delete(pools, key)
			}
		}

		poolsWatcher, err := client.IPPools().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: poolsList.ResourceVersion},
		)
		if err != nil {
			return poolSyncError(errors.Wrap(err, "error watching pools"))
		}
	watch:
		for update := range poolsWatcher.ResultChan() {
			switch update.Type {
			case watch.Error:
				switch update.Error.(type) {
				case calicoerr.ErrorWatchTerminated:
					break watch
				default:
					return poolSyncError(errors.Wrap(update.Error, "error while watching IPPools"))
				}
			case watch.Added, watch.Modified:
				pool := update.Object.(*calicoapi.IPPool)
				key := pool.Spec.CIDR
				err = poolAdded(key)
				if err != nil {
					return poolSyncError(errors.Wrap(err, "error deleting pool %s"))
				}
				pools[key] = nil
			case watch.Deleted:
				pool := update.Previous.(*calicoapi.IPPool)
				key := pool.Spec.CIDR
				err = poolDeleted(key)
				if err != nil {
					return poolSyncError(errors.Wrap(err, "error deleting pool %s"))
				}
				delete(pools, key)
			}

		}
		log.Info("restarting pools watcher...")
	}
	return poolSyncError(nil)
}
