package main

import "fmt"

func describe(i interface{}) string {
	switch v := i.(type) {
	case int:
		return fmt.Sprintf("int=%d", v)
	case string:
		return fmt.Sprintf("string=%s", v)
	default:
		return "unknown"
	}
}

func selectExample(ch chan int) int {
	select {
	case x := <-ch:
		return x
	default:
		return -1
	}
}
