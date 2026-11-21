package main

import "fmt"

func spawner() {
	go worker()
	go func() {
		fmt.Println("inline")
	}()
}

func worker() {
	fmt.Println("work")
}

func plain() {
	fmt.Println("no goroutine here")
}
