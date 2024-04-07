package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/miekg/dns"
)

func main() {
	// 监听 127.0.0.1:5345
	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 5345}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Printf("DNS server listening on %s\n", addr)

	for {
		buf := make([]byte, 512)
		n, remoteAddr, _ := conn.ReadFromUDP(buf)
		// 为每个请求启动一个goroutine进行处理,实现并发
		go handleDNSRequest(conn, remoteAddr, buf[:n])
	}
}

func handleDNSRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, reqBytes []byte) {
	// 解析请求数据
	req := new(dns.Msg)
	req.Unpack(reqBytes)
	handle(req)
	respBytes, _ := req.Pack()
	conn.WriteToUDP(respBytes, remoteAddr)
}

func handle(req *dns.Msg) {
	// 遍历请求的问题
	for _, q := range req.Question {
		// 如果是A记录查询
		if q.Qtype == dns.TypeA {
			ip := parseIP(q.Name)
			// 如果域名匹配特定模式,直接返回对应IP
			if ip != nil {
				req.Answer = append(req.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip,
				})
				continue
			}
		}
		// 将其他查询请求转发到上游DNS服务器 8.8.8.8
		systemResp, err := dns.Exchange(req, "8.8.8.8:53")
		if err == nil {
			// 将上游DNS服务器的应答添加到响应中
			req.Answer = append(req.Answer, systemResp.Answer...)
		}
		fmt.Println(err)
	}
}

// 匹配类似：1.1.1.1.domain.com 的特殊域名
var ipv4Regex = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.([\w-]+\.)+\w+\.`)

func parseIP(name string) net.IP {
	// 用正则表达式匹配域名
	if match := ipv4Regex.FindStringSubmatch(name); match != nil {
		ip := make(net.IP, 4)
		// 解析IP地址的4个部分
		for i := 0; i < 4; i++ {
			n, _ := strconv.Atoi(match[i+1])
			ip[i] = byte(n)
		}
		return ip
	}
	return nil
}
