package shapes

type Rect struct {
	W float64
	H float64
}

func (r *Rect) Area() float64 {
	return r.W * r.H
}

func (r Rect) Perimeter() float64 {
	return 2 * (r.W + r.H)
}

func NewRect(w, h float64) *Rect {
	return &Rect{W: w, H: h}
}
