package nodeview

import "math/rand"

func foreignTrustCoordinates() []Coordinate {
	var out []Coordinate
	for _, arm := range []struct {
		name, topology string
		mailbox        uint8
		positions      [2][]int
	}{
		{"echo", "echo", 255, [2][]int{{0}, {0, 1}}},
		{"peer-honest", "peer", 4, [2][]int{{0}, {0, 1}}},
		{"peer-foreign", "peer", 4, [2][]int{{4}, {0, 4}}},
	} {
		for k := 1; k <= 2; k++ {
			for missing := uint8(0); missing <= 2; missing++ {
				settings := echoSettings(0)
				if arm.topology == "peer" {
					settings = peerSettings(false, 0)
				}
				out = append(out, Coordinate{
					ID:               "trust-" + arm.name + "-k" + decimal(k) + "-m" + decimal(int(missing)),
					Topology:         arm.topology,
					Trust:            "foreign",
					Population:       "trust",
					Controlled:       append([]int(nil), arm.positions[k-1]...),
					ForeignPositions: append([]int(nil), arm.positions[k-1]...),
					Missing:          missing,
					Mailbox:          arm.mailbox,
					Placement:        "drawn",
					Setup:            "serial",
					Mode:             "immediate",
					N:                5,
					H:                3,
					Main:             30,
					Settings:         settings,
				})
			}
		}
	}
	out = append(out, Coordinate{
		ID:         "trust-unlisted",
		Topology:   "echo",
		Trust:      "trusted",
		Population: "membership",
		Missing:    2,
		Mailbox:    255,
		Placement:  "unlisted",
		Setup:      "serial",
		Mode:       "immediate",
		N:          5,
		H:          3,
		Main:       30,
		Settings:   echoSettings(0),
	})
	return out
}

func structuralTrustTasks(c Config, coordinates []Coordinate) []executionTask {
	if c.Set != Compromise || c.Phase != Structural {
		return nil
	}
	var tasks []executionTask
	for _, coordinate := range coordinates {
		if coordinate.Population != "trust" && coordinate.Population != "membership" || c.Peer && coordinate.Topology != "peer" {
			continue
		}
		if coordinate.Population == "membership" {
			tasks = append(tasks, executionTask{coordinate: coordinate, missing: coordinate.Missing, structural: true, membership: true})
			continue
		}
		routes := exhaustiveTrustRoutes(coordinate.Topology, coordinate.Mailbox)
		for at, repeat := 0, 0; at < len(routes); repeat++ {
			n := min(maxClients, len(routes)-at)
			task := executionTask{
				coordinate: coordinate,
				repeat:     repeat,
				routes:     append([][3]uint8(nil), routes[at:at+n]...),
				foreign:    append([]int(nil), coordinate.ForeignPositions...),
				missing:    coordinate.Missing,
				structural: true,
			}
			task.coordinate.Controlled = append([]int(nil), coordinate.Controlled...)
			task.coordinate.ForeignPositions = append([]int(nil), coordinate.ForeignPositions...)
			tasks = append(tasks, task)
			at += n
		}
	}
	return tasks
}

func exhaustiveTrustRoutes(topology string, mailbox uint8) [][3]uint8 {
	var routes [][3]uint8
	for first := uint8(0); first < 5; first++ {
		for middle := uint8(0); middle < 5; middle++ {
			if first == middle {
				continue
			}
			if topology == "peer" {
				if first != mailbox && middle != mailbox {
					routes = append(routes, [3]uint8{first, middle, mailbox})
				}
				continue
			}
			for last := uint8(0); last < 5; last++ {
				if last != first && last != middle {
					routes = append(routes, [3]uint8{first, middle, last})
				}
			}
		}
	}
	return routes
}

func conditionedPeerRoutes(seed int64, placement string, sides int) ([][3]uint8, error) {
	if placement != "mailbox-first" && placement != "mailbox-middle" || sides < 2 || sides > maxClients || sides%2 != 0 {
		return nil, ErrInvalid
	}
	r := rand.New(rand.NewSource(seed))
	passing := make([]bool, sides)
	for _, side := range r.Perm(sides)[:sides/2] {
		passing[side] = true
	}
	routes := make([][3]uint8, sides)
	for side := range routes {
		path := [3]uint8{0, 0, 4}
		if passing[side] {
			other := uint8(1 + r.Intn(3))
			if placement == "mailbox-first" {
				path[1] = other
			} else {
				path[0] = other
			}
		} else {
			others := r.Perm(3)
			path[0], path[1] = uint8(others[0]+1), uint8(others[1]+1)
		}
		routes[side] = path
	}
	return routes, nil
}
