package nodeview

import "reflect"

type outputEmission struct{ total uint64 }

func prepareReportEmission(r *Report, legacy, publication bool) (outputEmission, error) {
	return prepareReportEmissionCore(r, legacy, publication, outputAdmit, nil)
}

func prepareReportEmissionCore(r *Report, legacy, publication bool, admit func(uint64) error, beforeSizing func()) (outputEmission, error) {
	if admit == nil {
		return outputEmission{}, ErrInvalid
	}
	if e := admit(65536); e != nil {
		return outputEmission{}, e
	}
	if r == nil {
		return outputEmission{}, ErrInvalid
	}
	a := &outputArithmetic{}
	headers := outputReportHeaders(r, a)
	rows := outputRowBytes(uint64(len(r.Runs)), uint64(len(r.Audit)), uint64(len(r.Models)), a)
	prefix := a.add(65536, a.mul(24, a.mul(3, headers)), rows, 2400)
	if a.err != nil {
		return outputEmission{}, a.err
	}
	if e := admit(prefix); e != nil {
		return outputEmission{}, e
	}
	if beforeSizing != nil {
		beforeSizing()
	}
	plan, e := actualOutputMemory(*r)
	if e != nil {
		return outputEmission{}, e
	}
	validation, e := outputValidationAllocation(r)
	if e != nil {
		return outputEmission{}, e
	}
	need := a.add(prefix, plan.RetainedBytes, validation)
	if publication {
		need = plan.TotalBytes
		if need < prefix {
			return outputEmission{}, ErrInvalid
		}
	}
	if legacy {
		need = a.add(prefix, plan.LegacyTotalBytes, validation)
	}
	if a.err != nil {
		return outputEmission{}, a.err
	}
	if e := admit(need); e != nil {
		return outputEmission{}, e
	}
	return outputEmission{total: need}, nil
}

func guardPreparedEmission(prepared *outputEmission) error {
	if prepared == nil {
		return ErrInvalid
	}
	return outputAdmit(prepared.total)
}

func outputValidationAllocation(r *Report) (uint64, error) {
	price, _, err := outputValidationAllocationWithSummary(r)
	return price, err
}

type outputValidationSummary struct{ keys, descriptions, maps, values, keyHistory, copies, descriptionHistory, backing uint64 }

func outputValidationAllocationWithSummary(r *Report) (uint64, outputValidationSummary, error) {
	a := &outputArithmetic{}
	v := reflect.ValueOf(r).Elem()
	size := outputSerializedSize(v, a)
	counts := outputActualMethods(v, a)
	plan := outputSerializedSize(reflect.ValueOf(&r.Plan).Elem(), a)
	planCounts := outputActualMethods(reflect.ValueOf(&r.Plan).Elem(), a)
	price := a.add(outputCanonicalAllocation(plan, reflect.TypeFor[Plan](), planCounts, a), outputPlanNoncodec(max(uint64(len(r.Plan.Configurations)), outputCanonicalCount(r.Plan.Set)), a), outputStreamAllocation(size, counts, a), 528, 187)
	for i := range r.Models {
		value := reflect.ValueOf(&r.Models[i]).Elem()
		price = a.add(price, outputCanonicalAllocation(outputSerializedSize(value, a), reflect.TypeFor[FrozenModel](), outputActualMethods(value, a), a))
	}
	c := uint64(len(r.Plan.Configurations))
	descriptions, keys := outputDescriptiveCounts(*r, a)
	var methods uint64
	for i := range r.Runs {
		methods = a.add(methods, uint64(len(r.Runs[i].Methods)))
	}
	values := a.add(methods, a.mul(2, uint64(len(r.Runs))))
	summary := outputValidationSummary{keys: keys, descriptions: descriptions, maps: a.mul(c, a.add(outputMapBytes(keys, 24, 24, a), a.mul(2, outputMapBytes(keys, 24, 8, a)))), values: outputCumulativeSlice(values, 8, descriptions, a), keyHistory: outputCumulativeSlice(keys, 24, c, a), copies: a.add(a.mul(24, values), a.mul(64, descriptions)), descriptionHistory: outputCumulativeSlice(descriptions, uint64(reflect.TypeFor[DescriptiveSummary]().Size()), 1, a)}
	noncodec := a.add(summary.maps, summary.values, summary.keyHistory, summary.copies, summary.descriptionHistory)
	s := outputShape{strings: max(uint64(128), size.longest)}
	descriptive := plannedOutputSlice(reflect.TypeFor[[]DescriptiveSummary](), descriptions, s, a)
	summary.backing = descriptive.backing
	noncodec = a.add(noncodec, summary.backing, outputMapFamily(a.mul(c, 4), a.mul(c, 2), 24, 1, a), outputMapFamily(52, 4, 16, 1, a), outputMapFamily(a.mul(uint64(len(r.Models)), 4), 4, 16, 1, a), a.mul(2, outputCodecMetadata(reflect.TypeFor[Report](), a)), outputCodecMetadata(reflect.TypeFor[Plan](), a), 22*512+8*512)
	catalog := s
	catalog.catalog = true
	coordinate := plannedOutputType(reflect.TypeFor[Coordinate](), catalog, a)
	catalogRows := a.mul(4, max(c, uint64(27)))
	noncodec = a.add(noncodec, outputCumulativeSlice(catalogRows, uint64(reflect.TypeFor[Coordinate]().Size()), 4, a), a.mul(catalogRows, coordinate.backing-uint64(reflect.TypeFor[Coordinate]().Size())))
	price = a.add(price, noncodec, outputPrefix(reflect.TypeFor[Report](), a), outputAux(reflect.TypeFor[Report](), a))
	return price, summary, a.err
}

func outputFrozenPreparation(p *Plan, models []FrozenModel) error {
	return outputFrozenPreparationCore(p, models, outputAdmit, nil)
}

func outputFrozenPreparationCore(p *Plan, models []FrozenModel, admit func(uint64) error, beforeSizing func()) error {
	if admit == nil {
		return ErrInvalid
	}
	if !outputSelectedBackend() {
		return nil
	}
	if e := admit(65536); e != nil {
		return e
	}
	a := &outputArithmetic{}
	headers := a.mul(3, outputPlanHeaders(p, a))
	for i := range models {
		headers = a.add(headers, a.mul(3, outputModelHeaders(&models[i], a)))
	}
	prefix := a.add(65536, 320, a.mul(24, headers), a.mul(3, outputAux(reflect.TypeFor[Plan](), a)), a.mul(uint64(len(models)), outputAux(reflect.TypeFor[FrozenModel](), a)))
	if a.err != nil {
		return a.err
	}
	if e := admit(prefix); e != nil {
		return e
	}
	if beforeSizing != nil {
		beforeSizing()
	}
	value := reflect.ValueOf(p).Elem()
	price := a.add(prefix, a.mul(2, outputCanonicalAllocation(outputSerializedSize(value, a), reflect.TypeFor[Plan](), outputActualMethods(value, a), a)), a.mul(2, outputPlanNoncodec(max(uint64(len(p.Configurations)), outputCanonicalCount(p.Set)), a)))
	for i := range models {
		v := reflect.ValueOf(&models[i]).Elem()
		price = a.add(price, outputCanonicalAllocation(outputSerializedSize(v, a), reflect.TypeFor[FrozenModel](), outputActualMethods(v, a), a))
	}
	if a.err != nil {
		return a.err
	}
	return admit(price)
}

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
