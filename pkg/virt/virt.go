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
	"fmt"
	"os/exec"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/OpenFogStack/celestial/pkg/orchestrator"
)

// func checkCommands() (err error) {
// 	IPTABLES_BIN, err = exec.LookPath("iptables")

// 	if err != nil {
// 		return err
// 	}

// 	IP_BIN, err = exec.LookPath("ip")

// 	if err != nil {
// 		return err
// 	}

// 	SYSCTL_BIN, err = exec.LookPath("sysctl")

// 	if err != nil {
// 		return err
// 	}

// 	DD_BIN, err = exec.LookPath("dd")

// 	if err != nil {
// 		return err
// 	}

// 	MKFS_BIN, err = exec.LookPath("mkfs.ext4")

// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

// // New creates a new virt backend.
// func New(hostInterface string, initDelay uint64, pb PeeringBackend, neb NetworkEmulationBackend) (*Virt, error) {

// 	err := checkCommands()

// 	if err != nil {
// 		return nil, err
// 	}

// 	v := &Virt{
// 		hostInterface: hostInterface,
// 		initDelay:     initDelay,
// 		pb:            pb,
// 		neb:           neb,
// 		machines:      make(map[orchestrator.MachineID]*machine),
// 	}

// 	err = v.initHost()

// 	if err != nil {
// 		return nil, err
// 	}

// 	return v, nil
// }

// // RegisterMachine registers a machine with the virt backend. If the machine is on a remote host, it will be routed there.
// func (v *Virt) RegisterMachine(id orchestrator.MachineID, name string, host orchestrator.Host, config orchestrator.MachineConfig) error {

// 	if name != "" {
// 		name = fmt.Sprintf("gst-%s", name)
// 	}

// 	if name == "" {
// 		name = fmt.Sprintf("%d-%d", id.Group, id.Id)
// 	}

// 	n, err := getNet(id)

// 	if err != nil {
// 		return err
// 	}

// 	m := &machine{
// 		name:    name,
// 		network: n,
// 	}

// 	// if the machine is on a remote host, we need to route there
// 	ownHost, err := v.pb.GetHostID()

// 	if err != nil {
// 		return err
// 	}

// 	if uint8(host) != ownHost {
// 		return v.route(m, host)
// 	}

// 	err = v.register(id, m, config)

// 	if err != nil {
// 		return err
// 	}

// 	v.Lock()
// 	v.machines[id] = m
// 	v.Unlock()

// 	return nil
// }

// // BlockLink blocks the link between two machines using the network emulation backend.
// func (v *Virt) BlockLink(source orchestrator.MachineID, target orchestrator.MachineID) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[source]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.blocklink(source, target)
// }

// // UnblockLink unblocks the link between two machines using the network emulation backend.
// func (v *Virt) UnblockLink(source orchestrator.MachineID, target orchestrator.MachineID) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[source]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.unblocklink(source, target)
// }

// // SetLatency sets the latency between two machines using the network emulation backend.
// func (v *Virt) SetLatency(source orchestrator.MachineID, target orchestrator.MachineID, latency uint32) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[source]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.setlatency(source, target, latency)
// }

// // SetBandwidth sets the bandwidth between two machines using the network emulation backend.
// func (v *Virt) SetBandwidth(source orchestrator.MachineID, target orchestrator.MachineID, bandwidth uint64) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[source]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.setbandwidth(source, target, bandwidth)
// }

// func (v *Virt) StopMachine(machine orchestrator.MachineID) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[machine]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.transition(machine, STOPPED)
// }

// func (v *Virt) StartMachine(machine orchestrator.MachineID) error {
// 	// check that the source machine is on this host, otherwise discard
// 	v.RLock()
// 	_, ok := v.machines[machine]
// 	defer v.RUnlock()
// 	if !ok {
// 		return nil
// 	}

// 	return v.transition(machine, STARTED)
// }

// func (v *Virt) Stop() error {
// 	log.Debugf("stopping %d machines", len(v.machines))
// 	var wg sync.WaitGroup
// 	for m := range v.machines {
// 		wg.Add(1)
// 		go func(id orchestrator.MachineID) {
// 			defer wg.Done()
// 			err := v.transition(id, KILLED)

// 			if err != nil {
// 				log.Error(err)
// 			}
// 		}(m)
// 	}
// 	wg.Wait()
// 	v.Lock()
// 	defer v.Unlock()

// 	log.Debug("stopping netem backend")
// 	err := v.neb.Stop()

// 	if err != nil {
// 		return err
// 	}

// 	log.Debug("stopping peering backend")
// 	err = v.pb.Stop()

// 	if err != nil {
// 		return err
// 	}

// 	log.Debug("removing network devices")

// 	for _, m := range v.machines {
// 		err := m.removeNetwork()

// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

func checkCommands() (err error) {
	IPTABLES_BIN, err = exec.LookPath("iptables")
	if err != nil {
		return err
	}
	IP_BIN, err = exec.LookPath("ip")
	if err != nil {
		return err
	}
	SYSCTL_BIN, err = exec.LookPath("sysctl")
	if err != nil {
		return err
	}
	DD_BIN, err = exec.LookPath("dd")
	if err != nil {
		return err
	}
	MKFS_BIN, err = exec.LookPath("mkfs.ext4")
	if err != nil {
		return err
	}
	return nil
}

// New creates a new virt backend.
func New(hostInterface string, initDelay uint64, pb PeeringBackend, neb NetworkEmulationBackend) (*Virt, error) {
	err := checkCommands()
	if err != nil {
		return nil, err
	}
	v := &Virt{
		hostInterface: hostInterface,
		initDelay:     initDelay,
		pb:            pb,
		neb:           neb,
		machines:      make(map[orchestrator.MachineID]*machine),
	}
	err = v.initHost()
	if err != nil {
		return nil, err
	}
	return v, nil
}

// RegisterMachine registers a machine with the virt backend.
func (v *Virt) RegisterMachine(id orchestrator.MachineID, name string, host orchestrator.Host, config orchestrator.MachineConfig) error {
	if name != "" {
		name = fmt.Sprintf("gst-%s", name)
	}
	if name == "" {
		name = fmt.Sprintf("%d-%d", id.Group, id.Id)
	}

	m := &machine{
		name: name,
	}

	// 初始化所有4个端口的网络结构
	for port := 0; port < NUM_PORTS; port++ {
		m.networks[port] = initPortNetwork(id, port)
		m.portConnections[port] = nil // 初始时所有端口未连接
	}

	// 检查是否在远程主机
	ownHost, err := v.pb.GetHostID()
	if err != nil {
		return err
	}

	if uint8(host) != ownHost {
		// 如果在远程主机，只需为每个端口设置路由
		for port := 0; port < NUM_PORTS; port++ {
			// 注意：此时端口还未连接，所以网络信息不完整
			// 实际的路由将在EstablishLink时设置
			log.Tracef("Machine %s port %d will be on remote host %d", name, port, host)
		}
		return nil
	}

	// 在本地主机上注册
	err = v.register(id, m, config)
	if err != nil {
		return err
	}

	v.Lock()
	v.machines[id] = m
	v.Unlock()

	return nil
}

// EstablishLink 在两个VM之间建立点对点链接
func (v *Virt) EstablishLink(source orchestrator.MachineID, sourcePort int,
	target orchestrator.MachineID, targetPort int, linkIdx uint32) error {

	log.Debugf("Establishing link: %s:%d <-> %s:%d (linkIdx=%d)",
		source.String(), sourcePort, target.String(), targetPort, linkIdx)

	// 验证端口号
	if sourcePort < 0 || sourcePort >= NUM_PORTS {
		return errors.Errorf("invalid source port: %d", sourcePort)
	}
	if targetPort < 0 || targetPort >= NUM_PORTS {
		return errors.Errorf("invalid target port: %d", targetPort)
	}

	v.Lock()
	defer v.Unlock()

	sourceMachine, sourceExists := v.machines[source]
	targetMachine, targetExists := v.machines[target]

	// 确定哪一端是"第一端"（用于IP分配）
	// 使用简单的规则：Group小的是第一端；Group相同时ID小的是第一端
	sourceIsFirst := source.Group < target.Group ||
		(source.Group == target.Group && source.Id < target.Id)

	// 配置源端口（如果在本地）
	if sourceExists {
		sourceMachine.Lock()
		defer sourceMachine.Unlock()

		if sourceMachine.portConnections[sourcePort] != nil {
			return errors.Errorf("source port %s:%d already connected", source.String(), sourcePort)
		}

		// 配置网络信息
		targetIP := getLinkIP(linkIdx, !sourceIsFirst) // 对端IP
		configurePortForLink(&sourceMachine.networks[sourcePort], linkIdx, sourceIsFirst, targetIP)

		// 记录连接信息
		sourceMachine.portConnections[sourcePort] = &PortConnection{
			peerMachineID: target,
			peerPort:      targetPort,
			linkIdx:       linkIdx,
			isFirstEnd:    sourceIsFirst,
		}

		// 如果VM已启动，立即配置端口IP
		if sourceMachine.state == STARTED {
			err := sourceMachine.configurePort(sourcePort)
			if err != nil {
				return errors.Wrapf(err, "failed to configure source port %s:%d", source.String(), sourcePort)
			}
		}

		// 注册到网络仿真后端
		err := v.neb.RegisterPort(source, sourcePort, sourceMachine.networks[sourcePort].tap)
		if err != nil {
			return errors.Wrapf(err, "failed to register source port with netem backend")
		}

		log.Debugf("Configured source %s:%d - IP=%s, peer=%s",
			source.String(), sourcePort,
			sourceMachine.networks[sourcePort].ip.IP.String(),
			sourceMachine.networks[sourcePort].peerIP.String())
	}

	// 配置目标端口（如果在本地）
	if targetExists {
		targetMachine.Lock()
		defer targetMachine.Unlock()

		if targetMachine.portConnections[targetPort] != nil {
			return errors.Errorf("target port %s:%d already connected", target.String(), targetPort)
		}

		// 配置网络信息
		sourceIP := getLinkIP(linkIdx, sourceIsFirst) // 对端IP
		configurePortForLink(&targetMachine.networks[targetPort], linkIdx, !sourceIsFirst, sourceIP)

		// 记录连接信息
		targetMachine.portConnections[targetPort] = &PortConnection{
			peerMachineID: source,
			peerPort:      sourcePort,
			linkIdx:       linkIdx,
			isFirstEnd:    !sourceIsFirst,
		}

		// 如果VM已启动，立即配置端口IP
		if targetMachine.state == STARTED {
			err := targetMachine.configurePort(targetPort)
			if err != nil {
				return errors.Wrapf(err, "failed to configure target port %s:%d", target.String(), targetPort)
			}
		}

		// 注册到网络仿真后端
		err := v.neb.RegisterPort(target, targetPort, targetMachine.networks[targetPort].tap)
		if err != nil {
			return errors.Wrapf(err, "failed to register target port with netem backend")
		}

		log.Debugf("Configured target %s:%d - IP=%s, peer=%s",
			target.String(), targetPort,
			targetMachine.networks[targetPort].ip.IP.String(),
			targetMachine.networks[targetPort].peerIP.String())
	}

	// 处理跨主机路由
	ownHost, _ := v.pb.GetHostID()
	if sourceExists && !targetExists {
		// 目标在远程主机，需要通过peering backend路由
		targetHost := uint8(0) // 需要从编排器获取目标主机信息
		// TODO: 这里需要一个方法从orchestrator获取机器所在的主机
		err := v.pb.RoutePort(sourceMachine.networks[sourcePort].linkNetwork, sourcePort, orchestrator.Host(targetHost))
		if err != nil {
			return errors.Wrapf(err, "failed to setup routing for remote target")
		}
	} else if !sourceExists && targetExists {
		// 源在远程主机
		sourceHost := uint8(0) // 需要从编排器获取源主机信息
		err := v.pb.RoutePort(targetMachine.networks[targetPort].linkNetwork, targetPort, orchestrator.Host(sourceHost))
		if err != nil {
			return errors.Wrapf(err, "failed to setup routing for remote source")
		}
	}

	log.Infof("Successfully established link: %s:%d <-> %s:%d",
		source.String(), sourcePort, target.String(), targetPort)

	return nil
}

// TeardownLink 拆除两个VM之间的链接
func (v *Virt) TeardownLink(source orchestrator.MachineID, sourcePort int) error {
	log.Debugf("Tearing down link from %s:%d", source.String(), sourcePort)

	if sourcePort < 0 || sourcePort >= NUM_PORTS {
		return errors.Errorf("invalid source port: %d", sourcePort)
	}

	v.Lock()
	defer v.Unlock()

	sourceMachine, exists := v.machines[source]
	if !exists {
		// 机器不在本地主机，忽略
		return nil
	}

	sourceMachine.Lock()
	defer sourceMachine.Unlock()

	if sourceMachine.portConnections[sourcePort] == nil {
		return errors.Errorf("port %s:%d is not connected", source.String(), sourcePort)
	}

	// 如果VM正在运行，移除IP配置
	if sourceMachine.state == STARTED {
		err := sourceMachine.deconfigurePort(sourcePort)
		if err != nil {
			log.Errorf("Failed to deconfigure port %s:%d: %v", source.String(), sourcePort, err)
		}
	}

	// 清除连接信息
	sourceMachine.portConnections[sourcePort] = nil
	sourceMachine.networks[sourcePort].connected = false
	sourceMachine.networks[sourcePort].peerIP = nil

	// 从网络仿真后端注销（如果需要的话）
	// 当前的netem/ebpf后端没有注销方法，可能需要添加

	log.Infof("Tore down link from %s:%d", source.String(), sourcePort)

	return nil
}

// GetPortInfo 获取端口信息（用于调试和监控）
func (v *Virt) GetPortInfo(id orchestrator.MachineID, port int) (*PortConnection, error) {
	if port < 0 || port >= NUM_PORTS {
		return nil, errors.Errorf("invalid port: %d", port)
	}

	v.RLock()
	defer v.RUnlock()

	machine, exists := v.machines[id]
	if !exists {
		return nil, errors.Errorf("machine %s not found on this host", id.String())
	}

	machine.Lock()
	defer machine.Unlock()

	if machine.portConnections[port] == nil {
		return nil, errors.Errorf("port %s:%d is not connected", id.String(), port)
	}

	// 返回拷贝以避免并发问题
	connCopy := *machine.portConnections[port]
	return &connCopy, nil
}

// BlockLink blocks the link between two machines using the network emulation backend.
func (v *Virt) BlockLink(source orchestrator.MachineID, target orchestrator.MachineID) error {
	v.RLock()
	sourceMachine, ok := v.machines[source]
	v.RUnlock()

	if !ok {
		return nil // 源不在本地主机
	}

	sourceMachine.Lock()
	defer sourceMachine.Unlock()

	// 找到连接到目标的端口
	for port := 0; port < NUM_PORTS; port++ {
		conn := sourceMachine.portConnections[port]
		if conn != nil && conn.peerMachineID == target {
			// 找到了连接到目标的端口，阻塞该链接
			return v.blockLinkPort(source, port, target)
		}
	}

	// 没有找到到目标的连接
	log.Tracef("No link found from %s to %s", source.String(), target.String())
	return nil
}

// UnblockLink unblocks the link between two machines using the network emulation backend.
func (v *Virt) UnblockLink(source orchestrator.MachineID, target orchestrator.MachineID) error {
	v.RLock()
	sourceMachine, ok := v.machines[source]
	v.RUnlock()

	if !ok {
		return nil
	}

	sourceMachine.Lock()
	defer sourceMachine.Unlock()

	for port := 0; port < NUM_PORTS; port++ {
		conn := sourceMachine.portConnections[port]
		if conn != nil && conn.peerMachineID == target {
			return v.unblockLinkPort(source, port, target)
		}
	}

	log.Tracef("No link found from %s to %s", source.String(), target.String())
	return nil
}

// SetLatency sets the latency between two machines using the network emulation backend.
func (v *Virt) SetLatency(source orchestrator.MachineID, target orchestrator.MachineID, latency uint32) error {
	v.RLock()
	sourceMachine, ok := v.machines[source]
	v.RUnlock()

	if !ok {
		return nil
	}

	sourceMachine.Lock()
	defer sourceMachine.Unlock()

	for port := 0; port < NUM_PORTS; port++ {
		conn := sourceMachine.portConnections[port]
		if conn != nil && conn.peerMachineID == target {
			return v.setLatencyPort(source, port, target, latency)
		}
	}

	log.Tracef("No link found from %s to %s", source.String(), target.String())
	return nil
}

// SetBandwidth sets the bandwidth between two machines using the network emulation backend.
func (v *Virt) SetBandwidth(source orchestrator.MachineID, target orchestrator.MachineID, bandwidth uint64) error {
	v.RLock()
	sourceMachine, ok := v.machines[source]
	v.RUnlock()

	if !ok {
		return nil
	}

	sourceMachine.Lock()
	defer sourceMachine.Unlock()

	for port := 0; port < NUM_PORTS; port++ {
		conn := sourceMachine.portConnections[port]
		if conn != nil && conn.peerMachineID == target {
			return v.setBandwidthPort(source, port, target, bandwidth)
		}
	}

	log.Tracef("No link found from %s to %s", source.String(), target.String())
	return nil
}

func (v *Virt) StopMachine(machine orchestrator.MachineID) error {
	v.RLock()
	_, ok := v.machines[machine]
	v.RUnlock()

	if !ok {
		return nil
	}
	return v.transition(machine, STOPPED)
}

func (v *Virt) StartMachine(machine orchestrator.MachineID) error {
	v.RLock()
	_, ok := v.machines[machine]
	v.RUnlock()

	if !ok {
		return nil
	}
	return v.transition(machine, STARTED)
}

func (v *Virt) Stop() error {
	log.Debugf("stopping %d machines", len(v.machines))
	var wg sync.WaitGroup
	for m := range v.machines {
		wg.Add(1)
		go func(id orchestrator.MachineID) {
			defer wg.Done()
			err := v.transition(id, KILLED)
			if err != nil {
				log.Error(err)
			}
		}(m)
	}
	wg.Wait()

	v.Lock()
	defer v.Unlock()

	log.Debug("stopping netem backend")
	err := v.neb.Stop()
	if err != nil {
		return err
	}

	log.Debug("stopping peering backend")
	err = v.pb.Stop()
	if err != nil {
		return err
	}

	log.Debug("removing network devices")
	for _, m := range v.machines {
		err := m.removeNetwork()
		if err != nil {
			return err
		}
	}

	return nil
}
