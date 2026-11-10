package nodeview

func guardReportEmission(r Report) error {
	plan, e := actualOutputMemory(r)
	if e != nil {
		return e
	}
	available, e := availableHostMemory()
	if e != nil {
		return e
	}
	return checkOutputHost(plan, available, 0)
}
