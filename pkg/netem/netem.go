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

package netem

import (
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/OpenFogStack/celestial/pkg/orchestrator"
)

type link struct {
	blocked       bool
	latencyUs     uint32
	bandwidthKbps uint64
	// tc specific
	tcIndex uint16
}

// vmPort 表示VM的一个端口
type vmPort struct {
	netIf string
	// no concurrent modifications allowed
	sync.Mutex
	// ipset specific configuration
	chainName  string
	ipBlockSet string
	// tc specific configuration
	handle uint16
	links  map[ipnet]*link
}

// vm 表示一个虚拟机及其所有端口
type vm struct {
	// 最多4个端口
	ports map[int]*vmPort
	sync.RWMutex
}

var (
	IPTABLES_BIN string
	IPSET_BIN    string
	TC_BIN       string
)

func checkCommands() (err error) {
	IPTABLES_BIN, err = exec.LookPath("iptables")
	if err != nil {
		return err
	}
	IPSET_BIN, err = exec.LookPath("ipset")
	if err != nil {
		return err
	}
	TC_BIN, err = exec.LookPath("tc")
	if err != nil {
		return err
	}
	return nil
}

type Netem struct {
	vms map[orchestrator.MachineID]*vm
	sync.RWMutex
}

func init() {
	err := checkCommands()
	if err != nil {
		panic(err)
	}
}

func New() *Netem {
	return &Netem{
		vms: make(map[orchestrator.MachineID]*vm),
	}
}

func (n *Netem) Stop() error {
	log.Debugf("Removing all netem stuff")

	n.RLock()
	defer n.RUnlock()

	wg := sync.WaitGroup{}
	var e error

	for _, v := range n.vms {
		v.RLock()
		for _, port := range v.ports {
			wg.Add(1)
			go func(p *vmPort) {
				defer wg.Done()
				// remove ipset
				err := p.removeIPSet()
				if err != nil {
					e = errors.WithStack(err)
				}
				// remove tc
				err = p.removeTC()
				if err != nil {
					e = errors.WithStack(err)
				}
			}(port)
		}
		v.RUnlock()
	}

	wg.Wait()
	if e != nil {
		return e
	}
	return nil
}

// Register 注册VM（创建VM结构，但不创建端口）
func (n *Netem) Register(id orchestrator.MachineID, netIf string) error {
	// 这是旧接口，保留用于向后兼容
	// 对于多端口系统，应该使用 RegisterPort
	return n.RegisterPort(id, 0, netIf)
}

// RegisterPort 注册VM的一个端口
func (n *Netem) RegisterPort(id orchestrator.MachineID, port int, netIf string) error {
	log.Tracef("registering machine %s port %d (interface %s)", id.String(), port, netIf)

	n.Lock()
	defer n.Unlock()

	// 获取或创建VM
	v, ok := n.vms[id]
	if !ok {
		v = &vm{
			ports: make(map[int]*vmPort),
		}
		n.vms[id] = v
	}

	v.Lock()
	defer v.Unlock()

	// 检查端口是否已存在
	if _, exists := v.ports[port]; exists {
		return errors.Errorf("port %d already registered for machine %s", port, id.String())
	}

	// 创建端口
	vp := &vmPort{
		netIf: netIf,
		links: make(map[ipnet]*link),
	}

	// 为端口配置ipset
	err := vp.configureIPSet(id, port)
	if err != nil {
		return err
	}

	// 为端口配置tc
	err = vp.configureTC()
	if err != nil {
		return err
	}

	v.ports[port] = vp
	log.Tracef("successfully registered machine %s port %d", id.String(), port)

	return nil
}

func (n *Netem) getPort(id orchestrator.MachineID, port int) (*vmPort, error) {
	n.RLock()
	v, ok := n.vms[id]
	n.RUnlock()

	if !ok {
		return nil, errors.Errorf("machine %s does not exist", id.String())
	}

	v.RLock()
	vp, ok := v.ports[port]
	v.RUnlock()

	if !ok {
		return nil, errors.Errorf("port %d does not exist for machine %s", port, id.String())
	}

	return vp, nil
}

func (n *Netem) checkLink(vp *vmPort, target net.IPNet) error {
	if _, ok := vp.links[fromIPNet(target)]; ok {
		return nil
	}

	index, err := vp.createQDisc(target)
	if err != nil {
		return err
	}

	vp.links[fromIPNet(target)] = &link{tcIndex: index}
	return nil
}

// SetBandwidth 旧接口（向后兼容）
func (n *Netem) SetBandwidth(source orchestrator.MachineID, target net.IPNet, bandwidthKbps uint64) error {
	// 尝试在所有端口上设置
	n.RLock()
	v, ok := n.vms[source]
	n.RUnlock()

	if !ok {
		return errors.Errorf("machine %s does not exist", source.String())
	}

	v.RLock()
	defer v.RUnlock()

	// 在第一个端口上设置（保持向后兼容）
	for _, vp := range v.ports {
		return n.SetBandwidthPort(source, 0, target, bandwidthKbps)
	}

	return errors.Errorf("machine %s has no ports", source.String())
}

// SetBandwidthPort 为指定端口设置带宽
func (n *Netem) SetBandwidthPort(source orchestrator.MachineID, port int, target net.IPNet, bandwidthKbps uint64) error {
	vp, err := n.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	err = n.checkLink(vp, target)
	if err != nil {
		return err
	}

	err = vp.updateBandwidth(target, bandwidthKbps)
	if err != nil {
		return err
	}

	vp.links[fromIPNet(target)].bandwidthKbps = bandwidthKbps
	return nil
}

// SetLatency 旧接口（向后兼容）
func (n *Netem) SetLatency(source orchestrator.MachineID, target net.IPNet, latencyUs uint32) error {
	n.RLock()
	v, ok := n.vms[source]
	n.RUnlock()

	if !ok {
		return errors.Errorf("machine %s does not exist", source.String())
	}

	v.RLock()
	defer v.RUnlock()

	for _, vp := range v.ports {
		return n.SetLatencyPort(source, 0, target, latencyUs)
	}

	return errors.Errorf("machine %s has no ports", source.String())
}

// SetLatencyPort 为指定端口设置延迟
func (n *Netem) SetLatencyPort(source orchestrator.MachineID, port int, target net.IPNet, latencyUs uint32) error {
	vp, err := n.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	err = n.checkLink(vp, target)
	if err != nil {
		return err
	}

	err = vp.updateDelay(target, latencyUs)
	if err != nil {
		return err
	}

	vp.links[fromIPNet(target)].latencyUs = latencyUs
	return nil
}

// UnblockLink 旧接口（向后兼容）
func (n *Netem) UnblockLink(source orchestrator.MachineID, target net.IPNet) error {
	n.RLock()
	v, ok := n.vms[source]
	n.RUnlock()

	if !ok {
		return errors.Errorf("machine %s does not exist", source.String())
	}

	v.RLock()
	defer v.RUnlock()

	for _, vp := range v.ports {
		return n.UnblockLinkPort(source, 0, target)
	}

	return errors.Errorf("machine %s has no ports", source.String())
}

// UnblockLinkPort 解除指定端口的链接阻塞
func (n *Netem) UnblockLinkPort(source orchestrator.MachineID, port int, target net.IPNet) error {
	vp, err := n.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	err = n.checkLink(vp, target)
	if err != nil {
		return err
	}

	err = vp.unblockNet(target)
	if err != nil {
		return err
	}

	vp.links[fromIPNet(target)].blocked = false
	return nil
}

// BlockLink 旧接口（向后兼容）
func (n *Netem) BlockLink(source orchestrator.MachineID, target net.IPNet) error {
	n.RLock()
	v, ok := n.vms[source]
	n.RUnlock()

	if !ok {
		return errors.Errorf("machine %s does not exist", source.String())
	}

	v.RLock()
	defer v.RUnlock()

	for _, vp := range v.ports {
		return n.BlockLinkPort(source, 0, target)
	}

	return errors.Errorf("machine %s has no ports", source.String())
}

// BlockLinkPort 阻塞指定端口的链接
func (n *Netem) BlockLinkPort(source orchestrator.MachineID, port int, target net.IPNet) error {
	vp, err := n.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	err = n.checkLink(vp, target)
	if err != nil {
		return err
	}

	err = vp.blockNet(target)
	if err != nil {
		return err
	}

	vp.links[fromIPNet(target)].blocked = true
	return nil
}
