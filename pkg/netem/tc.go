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
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const DEFAULTRATE = "10.0Gbps"

func getBaseNet(ipNet net.IPNet) *net.IPNet {
	return &net.IPNet{
		IP:   ipNet.IP.Mask(ipNet.Mask),
		Mask: ipNet.Mask,
	}
}

func (vp *vmPort) configureTC() error {
	// tc qdisc del dev [TAP_NAME] root
	cmd := exec.Command(TC_BIN, "qdisc", "del", "dev", vp.netIf, "root")
	_ = cmd.Run()

	// tc qdisc add dev [TAP_NAME] root handle 1: htb default 1 r2q 1
	cmd = exec.Command(TC_BIN, "qdisc", "add", "dev", vp.netIf, "root", "handle", "1:", "htb", "default", "1", "r2q", "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// tc class add dev [TAP_NAME] parent 1: classid 1:1 htb rate [DEFAULTRATE] quantum 1514
	cmd = exec.Command(TC_BIN, "class", "add", "dev", vp.netIf, "parent", "1:", "classid", "1:1", "htb", "rate", DEFAULTRATE, "quantum", "1514")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	vp.handle = 1
	return nil
}

func (vp *vmPort) removeTC() error {
	// tc qdisc del dev [TAP_NAME] root
	cmd := exec.Command(TC_BIN, "qdisc", "del", "dev", vp.netIf, "root")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}
	return nil
}

func (vp *vmPort) createQDisc(target net.IPNet) (uint16, error) {
	vp.handle = vp.handle + 1

	// tc class add dev [TAP_NAME] parent 1: classid 1:[INDEX] htb rate [DEFAULTRATE] quantum 1514
	cmd := exec.Command(TC_BIN, "class", "add", "dev", vp.netIf, "parent", "1:", "classid", fmt.Sprintf("1:%d", vp.handle), "htb", "rate", DEFAULTRATE, "quantum", "1514")
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// tc qdisc add dev [TAP_NAME] parent 1:[INDEX] handle [INDEX]: netem delay 0.0ms limit 1000000
	cmd = exec.Command(TC_BIN, "qdisc", "add", "dev", vp.netIf, "parent", fmt.Sprintf("1:%d", vp.handle), "handle", fmt.Sprintf("%d:", vp.handle), "netem", "delay", "0.0", "limit", "1000000")
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	// tc filter add dev [TAP_NAME] protocol ip parent 1: prio [INDEX] u32 match ip src [DEST_NET] classid 1:[INDEX]
	cmd = exec.Command(TC_BIN, "filter", "add", "dev", vp.netIf, "protocol", "ip", "parent", "1:", "prio", strconv.Itoa(int(vp.handle)), "u32", "match", "ip", "src", getBaseNet(target).String(), "classid", fmt.Sprintf("1:%d", vp.handle))
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	return vp.handle, nil
}

func (vp *vmPort) updateDelay(target net.IPNet, delayUs uint32) error {
	log.Tracef("updating delay on %s for %s to %d", vp.netIf, target.String(), delayUs)

	l, ok := vp.links[fromIPNet(target)]
	if !ok {
		return errors.Errorf("unknown link %s", target.String())
	}

	x := delayUs / 1000
	y := delayUs % 1000 / 10

	// tc qdisc change dev [TAP_NAME] parent 1:[INDEX] handle [INDEX]: netem delay [DELAY].0ms limit 1000000
	cmd := exec.Command(TC_BIN, "qdisc", "change", "dev", vp.netIf, "parent", fmt.Sprintf("1:%d", l.tcIndex), "handle", fmt.Sprintf("%d:", l.tcIndex), "netem", "delay", fmt.Sprintf("%d.%dms", x, y), "limit", "1000000")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	return nil
}

func (vp *vmPort) updateBandwidth(target net.IPNet, bandwidthKbps uint64) error {
	log.Tracef("updating bandwidth on %s for %s to %d", vp.netIf, target.String(), bandwidthKbps)

	l, ok := vp.links[fromIPNet(target)]
	if !ok {
		return errors.Errorf("unknown link %s", target.String())
	}

	rate := fmt.Sprintf("%d.0kbit", bandwidthKbps)

	// tc class change dev [TAP_NAME] parent 1: classid 1:[INDEX] htb rate [RATE] quantum 1514
	cmd := exec.Command(TC_BIN, "class", "change", "dev", vp.netIf, "parent", "1:", "classid", fmt.Sprintf("1:%d", l.tcIndex), "htb", "rate", rate, "quantum", "1514")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.Wrapf(err, "%#v: output: %s", cmd.Args, out)
	}

	return nil
}
