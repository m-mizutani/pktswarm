package main

import (
	"fmt"
	"log"

	flags "github.com/jessevdk/go-flags"
)

func main() {
	var opts struct {
		Version bool `short:"v" long:"version" description:"Show version"`
	}

	args, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(args)
}
