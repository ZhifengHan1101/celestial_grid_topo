//go:build linux && amd64
// +build linux,amd64

/*
* This file is part of Celestial (https://github.com/OpenFogStack/celestial).
* Copyright (c) 2024 Soeren Becker, Nils Japke, Tobias Pfandzelter, The
* OpenFogStack Team.
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

package ebpfem

import (
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/OpenFogStack/celestial/pkg/orchestrator"
)

func New() *EBPFem {
	return &EBPFem{
		vms: make(map[orchestrator.MachineID]*vm),
	}
}

func (e *EBPFem) Stop() error {
	e.Lock()
	defer e.Unlock()

	for _, v := range e.vms {
		v.RLock()
		for _, port := range v.ports {
			err := port.objs.Close()
			if err != nil {
				v.RUnlock()
				return errors.WithStack(err)
			}
		}
		v.RUnlock()
	}

	return nil
}

// Register 旧接口（向后兼容）
func (e *EBPFem) Register(id orchestrator.MachineID, netIf string) error {
	return e.RegisterPort(id, 0, netIf)
}

// RegisterPort 注册VM的一个端口
func (e *EBPFem) RegisterPort(id orchestrator.MachineID, port int, netIf string) error {
	log.Tracef("registering eBPF for machine %s port %d on interface %s", id.String(), port, netIf)

	e.Lock()
	defer e.Unlock()

	// 获取或创建VM
	v, ok := e.vms[id]
	if !ok {
		v = &vm{
			ports: make(map[int]*vmPort),
		}
		e.vms[id] = v
	}

	v.Lock()
	defer v.Unlock()

	// 检查端口是否已存在
	if _, exists := v.ports[port]; exists {
		return errors.Errorf("port %d already registered for machine %s", port, id.String())
	}

	vp := &vmPort{
		netIf: netIf,
		objs:  &edtObjects{},
		hbd:   make(map[string]*handleKbpsDelay),
	}

	log.Tracef("loading ebpf objects for %s port %d", id.String(), port)
	if err := loadEdtObjects(vp.objs, nil); err != nil {
		return errors.WithStack(err)
	}

	progFd := vp.objs.edtPrograms.TcMain.FD()

	log.Tracef("getting interface %s", vp.netIf)
	iface, err := getIface(vp.netIf)
	if err != nil {
		log.Errorf("interface %s not found", vp.netIf)
		return errors.WithStack(err)
	}

	// Create clsact qdisc
	log.Tracef("creating clsact qdisc for %s", vp.netIf)
	_, err = createClsactQdisc(iface)
	if err != nil {
		log.Errorf("error creating clsact qdisc for %s", vp.netIf)
		return errors.WithStack(err)
	}

	// Create fq qdisc
	log.Tracef("creating fq qdisc for %s", vp.netIf)
	_, err = createFQdisc(iface)
	if err != nil {
		log.Tracef("error creating fq qdisc for %s", vp.netIf)
		return errors.WithStack(err)
	}

	// Attach bpf program
	log.Tracef("attaching bpf program for %s", vp.netIf)
	_, err = createTCBpfFilter(iface, progFd, netlink.HANDLE_MIN_EGRESS, "edt_bandwidth")
	if err != nil {
		log.Errorf("error attaching bpf program for %s", vp.netIf)
		return errors.WithStack(err)
	}

	v.ports[port] = vp
	log.Tracef("successfully registered eBPF for machine %s port %d", id.String(), port)

	return nil
}

func (e *EBPFem) getPort(id orchestrator.MachineID, port int) (*vmPort, error) {
	e.RLock()
	v, ok := e.vms[id]
	e.RUnlock()

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

func (vp *vmPort) getHBD(target net.IPNet) *handleKbpsDelay {
	hbd, ok := vp.hbd[target.String()]
	if ok {
		return hbd
	}

	hbd = &handleKbpsDelay{
		throttleRateKbps: DEFAULT_BANDWIDTH_KBPS,
		delayUs:          DEFAULT_LATENCY_US,
	}
	vp.hbd[target.String()] = hbd
	return hbd
}

// SetBandwidth 旧接口（向后兼容）
func (e *EBPFem) SetBandwidth(source orchestrator.MachineID, target net.IPNet, bandwidthKbits uint64) error {
	return e.SetBandwidthPort(source, 0, target, bandwidthKbits)
}

// SetBandwidthPort 为指定端口设置带宽
func (e *EBPFem) SetBandwidthPort(source orchestrator.MachineID, port int, target net.IPNet, bandwidthKbits uint64) error {
	vp, err := e.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	hbd := vp.getHBD(target)
	hbd.throttleRateKbps = uint32(bandwidthKbits)

	ips, err := parseNetToLongs(target)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, ip := range ips {
		log.Tracef("updating bandwidth for %d to %d", ip, bandwidthKbits)
		err = vp.objs.IP_HANDLE_KBPS_DELAY.Put(ip, hbd)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// SetLatency 旧接口（向后兼容）
func (e *EBPFem) SetLatency(source orchestrator.MachineID, target net.IPNet, latency uint32) error {
	return e.SetLatencyPort(source, 0, target, latency)
}

// SetLatencyPort 为指定端口设置延迟
func (e *EBPFem) SetLatencyPort(source orchestrator.MachineID, port int, target net.IPNet, latency uint32) error {
	vp, err := e.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	hbd := vp.getHBD(target)
	hbd.delayUs = uint32(latency)

	ips, err := parseNetToLongs(target)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, ip := range ips {
		log.Tracef("updating latency for %d to %d", ip, latency)
		err = vp.objs.IP_HANDLE_KBPS_DELAY.Put(ip, hbd)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// UnblockLink 旧接口（向后兼容）
func (e *EBPFem) UnblockLink(source orchestrator.MachineID, target net.IPNet) error {
	return e.UnblockLinkPort(source, 0, target)
}

// UnblockLinkPort 解除指定端口的链接阻塞
func (e *EBPFem) UnblockLinkPort(source orchestrator.MachineID, port int, target net.IPNet) error {
	vp, err := e.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	hbd := vp.getHBD(target)

	ips, err := parseNetToLongs(target)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, ip := range ips {
		log.Tracef("unblocking for %d", ip)
		err = vp.objs.IP_HANDLE_KBPS_DELAY.Put(ip, hbd)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// BlockLink 旧接口（向后兼容）
func (e *EBPFem) BlockLink(source orchestrator.MachineID, target net.IPNet) error {
	return e.BlockLinkPort(source, 0, target)
}

// BlockLinkPort 阻塞指定端口的链接
func (e *EBPFem) BlockLinkPort(source orchestrator.MachineID, port int, target net.IPNet) error {
	vp, err := e.getPort(source, port)
	if err != nil {
		return err
	}

	vp.Lock()
	defer vp.Unlock()

	ips, err := parseNetToLongs(target)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, ip := range ips {
		log.Tracef("blocking for %d", ip)
		err = vp.objs.IP_HANDLE_KBPS_DELAY.Put(ip, &handleKbpsDelay{
			throttleRateKbps: BLOCKED_BANDWIDTH_KBPS,
			delayUs:          BLOCKED_LATENCY_US,
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}