package nodeview

import (
	"math"
	"math/big"
	"slices"
)

type fitInterval struct{ lo, hi float64 }

func outwardFit(lo, hi float64) fitInterval {
	return fitInterval{math.Nextafter(lo, math.Inf(-1)), math.Nextafter(hi, math.Inf(1))}
}
func pointFit(v float64) fitInterval      { return fitInterval{v, v} }
func addFit(a, b fitInterval) fitInterval { return outwardFit(a.lo+b.lo, a.hi+b.hi) }
func subFit(a, b fitInterval) fitInterval { return outwardFit(a.lo-b.hi, a.hi-b.lo) }
func mulFit(a, b fitInterval) fitInterval {
	p := [4]float64{a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi}
	return outwardFit(slices.Min(p[:]), slices.Max(p[:]))
}
func squareFit(a fitInterval) fitInterval {
	b := absFit(a)
	return outwardFit(b.lo*b.lo, b.hi*b.hi)
}
func divFit(a, b fitInterval) fitInterval {
	if b.lo <= 0 && b.hi >= 0 {
		return fitInterval{math.Inf(-1), math.Inf(1)}
	}
	return mulFit(a, outwardFit(1/b.hi, 1/b.lo))
}
func sqrtFit(a fitInterval) fitInterval {
	if a.lo < 0 {
		return fitInterval{math.NaN(), math.NaN()}
	}
	return outwardFit(math.Sqrt(a.lo), math.Sqrt(a.hi))
}
func finiteFit(a fitInterval) bool {
	return !math.IsNaN(a.lo) && !math.IsNaN(a.hi) && !math.IsInf(a.lo, 0) && !math.IsInf(a.hi, 0)
}
func absFit(a fitInterval) fitInterval {
	hi := math.Max(math.Abs(a.lo), math.Abs(a.hi))
	lo := math.Min(math.Abs(a.lo), math.Abs(a.hi))
	if a.lo <= 0 && a.hi >= 0 {
		lo = 0
	}
	return fitInterval{lo, hi}
}

func exactMailboxScatter(sumI, sumJ, cross int64, n int) float64 {
	r := new(big.Rat).SetInt64(cross)
	product := new(big.Int).Mul(big.NewInt(sumI), big.NewInt(sumJ))
	r.Sub(r, new(big.Rat).SetFrac(product, big.NewInt(int64(n))))
	v, _ := r.Float64()
	return v
}
