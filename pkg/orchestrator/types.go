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

import "fmt"

//type MachineState uint8

// const (
// 	STOPPED MachineState = iota
// 	ACTIVE
// )

// type Link struct {
// 	// Blocked is true if the link is blocked
// 	Blocked bool
// 	// Latency in microseconds
// 	LatencyUs uint32
// 	// Bandwidth in kilobytes per second
// 	BandwidthKbps uint64

// 	// used for path reconstruction
// 	Next MachineID
// }

// type MachineID struct {
// 	// is 0 for ground stations
// 	Group uint8
// 	Id    uint32
// }

// func (m MachineID) String() string {
// 	return fmt.Sprintf("%d.%d", m.Group, m.Id)
// }

// type Host uint8

// type NetworkState map[MachineID]map[MachineID]*Link

// type MachinesState map[MachineID]MachineState

// type State struct {
// 	NetworkState
// 	MachinesState
// }

// type ISL struct {
// 	// Latency in microseconds
// 	Latency uint32
// 	// Bandwidth in bytes per second
// 	Bandwidth uint64
// }

// type machine struct {
// 	name   string
// 	Host   Host
// 	config MachineConfig
// }

// type MachineConfig struct {
// 	VCPUCount uint8
// 	// RAM in bytes
// 	RAM uint64
// 	// DiskSize in bytes
// 	DiskSize uint64
// 	// DiskImage is the path to the disk image
// 	DiskImage string
// 	// Kernel is the path to the kernel
// 	Kernel string
// 	// BootParams are the additional boot parameters
// 	BootParams []string
// }

type MachineState uint8

const (
	STOPPED MachineState = iota
	ACTIVE
)

type Link struct {
	Blocked       bool
	LatencyUs     uint32
	BandwidthKbps uint64
	Next          MachineID
}

type MachineID struct {
	Group uint8
	Id    uint32
}

func (m MachineID) String() string {
	return fmt.Sprintf("%d.%d", m.Group, m.Id)
}

type Host uint8

type NetworkState map[MachineID]map[MachineID]*Link
type MachinesState map[MachineID]MachineState

type State struct {
	NetworkState
	MachinesState
}

type ISL struct {
	Latency   uint32
	Bandwidth uint64
}

type machine struct {
	name   string
	Host   Host
	config MachineConfig
}

type MachineConfig struct {
	VCPUCount  uint8
	RAM        uint64
	DiskSize   uint64
	DiskImage  string
	Kernel     string
	BootParams []string
}

// PortConfig 端口配置（用于拓扑初始化）
type PortConfig struct {
	Port       int
	PeerMachine MachineID
	PeerPort    int
	LinkIdx     uint32
}

// TopologyConfig 拓扑配置（包含所有链接信息）
type TopologyConfig struct {
	Links []LinkConfig
}

// LinkConfig 链接配置
type LinkConfig struct {
	Source     MachineID
	SourcePort int
	Target     MachineID
	TargetPort int
	LinkIdx    uint32
}