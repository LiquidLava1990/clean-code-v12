package main

func sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total += x
	}
	return total
}

func loop3() {
	for i := 0; i < 3; i++ {
		_ = i
	}
}

func whileStyle(n int) int {
	for n > 0 {
		n--
	}
	return n
}
