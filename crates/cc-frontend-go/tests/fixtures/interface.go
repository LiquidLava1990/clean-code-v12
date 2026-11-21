package shapes

type Shape interface {
	Area() float64
	Perimeter() float64
}

type Named interface {
	Shape
	Name() string
}
