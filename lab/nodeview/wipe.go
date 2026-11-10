package nodeview

func (t *privateTruth) wipeMetadata() {
	clear(t.setups[:cap(t.setups)])
	clear(t.messages[:cap(t.messages)])
	clear(t.seals[:cap(t.seals)])
	clear(t.requests[:cap(t.requests)])
	clear(t.fragments[:cap(t.fragments)])
	clear(t.ownership)
	clear(t.clientPacket[:cap(t.clientPacket)])
	t.clientPacket = nil
	if !t.client {
		releaseCapacity(t.setups, t.budget)
		releaseCapacity(t.messages, t.budget)
		releaseCapacity(t.seals, t.budget)
		releaseCapacity(t.requests, t.budget)
		releaseCapacity(t.fragments, t.budget)
	}
	t.client = false
	t.capacity = clientTruthCapacity{}
	t.setups = nil
	t.messages = nil
	t.seals = nil
	t.requests = nil
	t.fragments = nil
	t.ownership = nil
}
func (v *nodeView) wipe() {
	clear(v.connections[:cap(v.connections)])
	clear(v.setups[:cap(v.setups)])
	clear(v.cells[:cap(v.cells)])
	clear(v.frames[:cap(v.frames)])
	clear(v.mailbox[:cap(v.mailbox)])
	clear(v.releases[:cap(v.releases)])
	clear(v.samples[:cap(v.samples)])
	releaseCapacity(v.connections, v.budget)
	releaseCapacity(v.setups, v.budget)
	releaseCapacity(v.cells, v.budget)
	releaseCapacity(v.frames, v.budget)
	releaseCapacity(v.mailbox, v.budget)
	releaseCapacity(v.releases, v.budget)
	releaseCapacity(v.samples, v.budget)
	v.connections = nil
	v.setups = nil
	v.cells = nil
	v.frames = nil
	v.mailbox = nil
	v.releases = nil
	v.samples = nil
	v.arena = nil
}
func (p *predictions) wipe() {
	methods := p.methods[:cap(p.methods)]
	for i := range methods {
		clear(methods[i].values[:cap(methods[i].values)])
		clear(methods[i].matches[:cap(methods[i].matches)])
		methods[i].values = nil
		methods[i].matches = nil
	}
	clear(methods)
	clear(p.seen[:cap(p.seen)])
	if p.layout != nil {
		for population := range p.layout.mail {
			for _, rows := range p.layout.mail[population][:cap(p.layout.mail[population])] {
				clear(rows[:cap(rows)])
			}
			clear(p.layout.mail[population][:cap(p.layout.mail[population])])
			p.layout.mail[population] = nil
		}
		*p.layout = predictionLayout{}
	}
	p.methods = nil
	p.seen = nil
	p.layout = nil
}
func (p *privateCapture) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.keys)
	clear(p.dummy)
	p.keys = nil
	p.dummy = nil
	p.truth.close()
	p.route = [3]uint8{}
	p.side = 0
	p.generation = 0
	p.completeGeneration = 0
	p.nextSetupHop = 255
	p.frozen = true
}
