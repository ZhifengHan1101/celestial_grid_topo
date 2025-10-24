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

package orchestrator

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Orchestrator struct {
	State
	machines     map[MachineID]*machine
	machineNames map[string]MachineID
	// 新增：跟踪链接信息
	links        map[LinkID]*LinkInfo
	virt         VirtualizationBackend
	initialized  bool
}

// LinkID 唯一标识一个链接
type LinkID struct {
	Source     MachineID
	SourcePort int
	Target     MachineID
	TargetPort int
}

// LinkInfo 存储链接的详细信息
type LinkInfo struct {
	LinkIdx uint32
	Active  bool
}

func New(vb VirtualizationBackend) *Orchestrator {
	return &Orchestrator{
		virt:  vb,
		links: make(map[LinkID]*LinkInfo),
	}
}

func (o *Orchestrator) GetResources() (availcpus uint32, availram uint64, err error) {
	return uint32(runtime.NumCPU()), memory.TotalMemory(), nil
}

func (o *Orchestrator) Initialize(machineList map[MachineID]MachineConfig,
	machineHosts map[MachineID]Host, machineNames map[MachineID]string) error {

	if o.initialized {
		return errors.Errorf("orchestrator already initialized")
	}

	log.Debugf("initializing orchestrator with %d machines", len(machineList))

	o.machines = make(map[MachineID]*machine)
	o.machineNames = make(map[string]MachineID)

	for m, config := range machineList {
		o.machines[m] = &machine{
			name:   machineNames[m],
			config: config,
		}
		if machineNames[m] != "" {
			o.machineNames[machineNames[m]] = m
		}
	}

	for m, host := range machineHosts {
		o.machines[m].Host = host
	}

	for m, name := range machineNames {
		o.machines[m].name = name
	}

	// init state
	o.State = State{
		NetworkState:  make(NetworkState),
		MachinesState: make(MachinesState),
	}

	// register all machines
	var wg sync.WaitGroup
	var e error
	progressMachines := atomic.Uint32{}

	for m := range o.machines {
		wg.Add(1)
		go func(mid MachineID, mmachine *machine) {
			defer wg.Done()
			err := o.virt.RegisterMachine(mid, mmachine.name, mmachine.Host, mmachine.config)
			if err != nil {
				e = errors.WithStack(err)
			}
			progressMachines.Add(1)
		}(m, o.machines[m])

		o.State.MachinesState[m] = STOPPED
	}

	shown := 0
	total := len(o.machines)
	for state := 0; state < total; state = int(progressMachines.Load()) {
		if state > shown && state%100 == 0 {
			log.Debugf("machine init progress: %d/%d", progressMachines.Load(), total)
			shown = state
		}
	}

	wg.Wait()
	if e != nil {
		return errors.WithStack(e)
	}

	log.Debugf("starting link init")

	// init networking - 默认所有链接都是阻塞的
	wg = sync.WaitGroup{}
	e = nil
	progressLinks := atomic.Uint32{}
	start := time.Now()

	for m := range o.machines {
		o.State.NetworkState[m] = make(map[MachineID]*Link)
		wg.Add(1)
		go func(source MachineID, links map[MachineID]*Link) {
			defer wg.Done()
			for otherMachine := range o.machines {
				if source == otherMachine {
					continue
				}

				// 默认阻塞（但不实际调用BlockLink，因为还没建立链接）
				links[otherMachine] = &Link{
					Blocked: true,
				}
				progressLinks.Add(1)
			}
		}(m, o.State.NetworkState[m])
	}

	shown = 0
	total = len(o.machines) * (len(o.machines) - 1)
	for state := 0; state < total; state = int(progressLinks.Load()) {
		if state > shown && state%100 == 0 {
			log.Debugf("link init progress: %d/%d", progressLinks.Load(), total)
			shown = state
		}
	}

	wg.Wait()
	if e != nil {
		return errors.WithStack(e)
	}

	log.Debugf("done initializing network state in %s", time.Since(start))

	o.initialized = true
	log.Info("orchestrator initialized")

	return nil
}

// EstablishLink 建立两个VM之间的物理链接
func (o *Orchestrator) EstablishLink(source MachineID, sourcePort int,
	target MachineID, targetPort int, linkIdx uint32) error {

	if !o.initialized {
		return errors.New("orchestrator not initialized")
	}

	linkID := LinkID{
		Source:     source,
		SourcePort: sourcePort,
		Target:     target,
		TargetPort: targetPort,
	}

	// 检查链接是否已存在
	if _, exists := o.links[linkID]; exists {
		return errors.Errorf("link already exists: %s:%d -> %s:%d",
			source.String(), sourcePort, target.String(), targetPort)
	}

	// 调用虚拟化后端建立链接
	err := o.virt.EstablishLink(source, sourcePort, target, targetPort, linkIdx)
	if err != nil {
		return errors.Wrapf(err, "failed to establish link in virt backend")
	}

	// 记录链接信息
	o.links[linkID] = &LinkInfo{
		LinkIdx: linkIdx,
		Active:  false, // 初始时链接是阻塞的
	}

	// 同时记录反向链接
	reverseLinkID := LinkID{
		Source:     target,
		SourcePort: targetPort,
		Target:     source,
		TargetPort: sourcePort,
	}
	o.links[reverseLinkID] = &LinkInfo{
		LinkIdx: linkIdx,
		Active:  false,
	}

	log.Infof("Established link: %s:%d <-> %s:%d (idx=%d)",
		source.String(), sourcePort, target.String(), targetPort, linkIdx)

	return nil
}

// TeardownLink 拆除链接
func (o *Orchestrator) TeardownLink(source MachineID, sourcePort int,
	target MachineID, targetPort int) error {

	if !o.initialized {
		return errors.New("orchestrator not initialized")
	}

	linkID := LinkID{
		Source:     source,
		SourcePort: sourcePort,
		Target:     target,
		TargetPort: targetPort,
	}

	if _, exists := o.links[linkID]; !exists {
		return errors.Errorf("link does not exist: %s:%d -> %s:%d",
			source.String(), sourcePort, target.String(), targetPort)
	}

	// 调用虚拟化后端拆除链接
	err := o.virt.TeardownLink(source, sourcePort)
	if err != nil {
		return errors.Wrapf(err, "failed to teardown link in virt backend")
	}

	// 删除链接记录
	delete(o.links, linkID)

	// 删除反向链接
	reverseLinkID := LinkID{
		Source:     target,
		SourcePort: targetPort,
		Target:     source,
		TargetPort: sourcePort,
	}
	delete(o.links, reverseLinkID)

	log.Infof("Tore down link: %s:%d <-> %s:%d",
		source.String(), sourcePort, target.String(), targetPort)

	return nil
}

func (o *Orchestrator) Stop() error {
	log.Debugf("stopping orchestrator")
	err := o.virt.Stop()
	if err != nil {
		log.Error(err.Error())
		return errors.WithStack(err)
	}
	return nil
}

func (o *Orchestrator) Update(s *State) error {
	linkUpdateStart := time.Now()
	var wg sync.WaitGroup
	var e error

	for m, ls := range s.NetworkState {
		wg.Add(1)
		go func(source MachineID, links map[MachineID]*Link) {
			defer wg.Done()
			for target, l := range links {
				currentLink := o.State.NetworkState[source][target]

				// 处理链接阻塞/解除阻塞
				if l.Blocked && !currentLink.Blocked {
					log.Tracef("blocking link %s -> %s", source, target)
					err := o.virt.BlockLink(source, target)
					if err != nil {
						e = errors.WithStack(err)
					}
					o.State.NetworkState[source][target].Blocked = true
				}
				if !l.Blocked && currentLink.Blocked {
					log.Tracef("unblocking link %s -> %s", source, target)
					err := o.virt.UnblockLink(source, target)
					if err != nil {
						e = errors.WithStack(err)
					}
					o.State.NetworkState[source][target].Blocked = false
				}

				if l.Blocked {
					continue
				}

				// 更新链接参数
				log.Tracef("updating link %s -> %s", source, target)
				if l.Next != currentLink.Next {
					log.Tracef("setting next hop %s -> %s to %s", source, target, l.Next)
					o.State.NetworkState[source][target].Next = l.Next
				}

				if l.LatencyUs != currentLink.LatencyUs {
					log.Tracef("changing latency %s -> %s from %d to %d",
						source, target, l.LatencyUs, currentLink.LatencyUs)
					err := o.virt.SetLatency(source, target, l.LatencyUs)
					if err != nil {
						e = errors.WithStack(err)
					}
					o.State.NetworkState[source][target].LatencyUs = l.LatencyUs
				}

				if l.BandwidthKbps != currentLink.BandwidthKbps {
					log.Tracef("setting bandwidth %s -> %s to %d", source, target, l.BandwidthKbps)
					err := o.virt.SetBandwidth(source, target, l.BandwidthKbps)
					if err != nil {
						e = errors.WithStack(err)
					}
					o.State.NetworkState[source][target].BandwidthKbps = l.BandwidthKbps
				}
			}
		}(m, ls)
	}

	wg.Wait()
	if e != nil {
		return errors.WithStack(e)
	}

	log.Debugf("link update took %s", time.Since(linkUpdateStart))

	// 更新机器状态
	machineUpdateStart := time.Now()
	wg = sync.WaitGroup{}
	e = nil

	for m, state := range s.MachinesState {
		if state == STOPPED && o.State.MachinesState[m] == ACTIVE {
			wg.Add(1)
			go func(machine MachineID) {
				defer wg.Done()
				err := o.virt.StopMachine(machine)
				if err != nil {
					e = errors.WithStack(err)
				}
			}(m)
			o.State.MachinesState[m] = STOPPED
			continue
		}
		if state == ACTIVE && o.State.MachinesState[m] == STOPPED {
			wg.Add(1)
			go func(machine MachineID) {
				defer wg.Done()
				err := o.virt.StartMachine(machine)
				if err != nil {
					e = errors.WithStack(err)
				}
			}(m)
			o.State.MachinesState[m] = ACTIVE
			continue
		}
	}

	wg.Wait()
	if e != nil {
		return errors.WithStack(e)
	}

	log.Debugf("machine update took %s", time.Since(machineUpdateStart))
	log.Info("orchestrator updated")

	return nil
}