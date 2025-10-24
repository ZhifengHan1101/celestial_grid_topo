/*
* This file is part of Celestial (https://github.com/OpenFogStack/celestial).
* Copyright (c) 2024 Tobias Pfandzelter, The OpenFogStack Team.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, version 3.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
**/

package virt

import (
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/OpenFogStack/celestial/pkg/orchestrator"
)


// getPortNetwork 获取指定端口的目标网络
func (v *Virt) getPortNetwork(id orchestrator.MachineID, port int) (net.IPNet, error) {
	v.RLock()
	machine, exists := v.machines[id]
	v.RUnlock()

	if !exists {
		return net.IPNet{}, errors.Errorf("machine %s not found", id.String())
	}

	machine.Lock()
	defer machine.Unlock()

	if port < 0 || port >= NUM_PORTS {
		return net.IPNet{}, errors.Errorf("invalid port number: %d", port)
	}

	if !machine.networks[port].connected {
		return net.IPNet{}, errors.Errorf("port %d is not connected", port)
	}

	return machine.networks[port].linkNetwork, nil
}

// getTargetPortAndNetwork 找到连接到目标机器的端口及其网络
func (v *Virt) getTargetPortAndNetwork(source orchestrator.MachineID, target orchestrator.MachineID) (int, net.IPNet, error) {
	v.RLock()
	machine, exists := v.machines[source]
	v.RUnlock()

	if !exists {
		return -1, net.IPNet{}, errors.Errorf("source machine %s not found", source.String())
	}

	machine.Lock()
	defer machine.Unlock()

	// 查找连接到目标的端口
	for port := 0; port < NUM_PORTS; port++ {
		conn := machine.portConnections[port]
		if conn != nil && conn.peerMachineID == target {
			return port, machine.networks[port].linkNetwork, nil
		}
	}

	return -1, net.IPNet{}, errors.Errorf("no port connects %s to %s", source.String(), target.String())
}

// setBandwidthPort 设置指定端口的带宽
func (v *Virt) setBandwidthPort(source orchestrator.MachineID, port int, target orchestrator.MachineID, bandwidth uint64) error {
	n, err := v.getPortNetwork(source, port)
	if err != nil {
		return err
	}

	log.Tracef("Setting bandwidth on %s:%d to %s: %d kbps", source.String(), port, target.String(), bandwidth)
	return v.neb.SetBandwidthPort(source, port, n, bandwidth)
}

// setLatencyPort 设置指定端口的延迟
func (v *Virt) setLatencyPort(source orchestrator.MachineID, port int, target orchestrator.MachineID, latency uint32) error {
	n, err := v.getPortNetwork(source, port)
	if err != nil {
		return err
	}

	log.Tracef("Setting latency on %s:%d to %s: %d us", source.String(), port, target.String(), latency)
	return v.neb.SetLatencyPort(source, port, n, latency)
}

// unblockLinkPort 解除指定端口的链接阻塞
func (v *Virt) unblockLinkPort(source orchestrator.MachineID, port int, target orchestrator.MachineID) error {
	n, err := v.getPortNetwork(source, port)
	if err != nil {
		return err
	}

	log.Tracef("Unblocking link on %s:%d to %s", source.String(), port, target.String())
	return v.neb.UnblockLinkPort(source, port, n)
}

// blockLinkPort 阻塞指定端口的链接
func (v *Virt) blockLinkPort(source orchestrator.MachineID, port int, target orchestrator.MachineID) error {
	n, err := v.getPortNetwork(source, port)
	if err != nil {
		return err
	}

	log.Tracef("Blocking link on %s:%d to %s", source.String(), port, target.String())
	return v.neb.BlockLinkPort(source, port, n)
}