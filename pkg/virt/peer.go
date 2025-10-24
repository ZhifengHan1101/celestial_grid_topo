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

import "github.com/OpenFogStack/celestial/pkg/orchestrator"

// func (v *Virt) route(m *machine, host orchestrator.Host) error {
// 	return v.pb.Route(m.network.network, host)
// }

// routePort 为指定端口设置到远程主机的路由
func (v *Virt) routePort(m *machine, port int, host orchestrator.Host) error {
	if port < 0 || port >= NUM_PORTS {
		return nil
	}
	
	// 只有已连接的端口才需要路由
	if !m.networks[port].connected {
		return nil
	}
	
	return v.pb.RoutePort(m.networks[port].linkNetwork, port, host)
}