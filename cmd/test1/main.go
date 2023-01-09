package main

import (
	"fmt"
	"net"

	uuid "github.com/satori/go.uuid"
)

func CheckWildcard(domain string) (ok bool) {
	for i := 0; i < 2; i++ {
		i, err := net.LookupHost(uuid.NewV4().String() + "." + domain)
		fmt.Println(i)
		if err == nil {
			return true
		}
	}
	return false
}

func main() {
	CheckWildcard("baidu.com")
}
