package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type ftpProtoConfig struct {
	Version string `yaml:"version"`
	Banner  string `yaml:"banner"`
}

type serverConfig struct {
	Port    string `yaml:"port"`
	Address string `yaml:"address"`
}

type Config struct {
	FTP_PROTO ftpProtoConfig `yaml:"ftp-proto"`
	SERVER    serverConfig   `yaml:"server"`
}

// Load YAML config file
func chkYaml(file *string) Config {
	var config Config
	_, err := os.Stat(*file)
	if err != nil {
		log.Fatal("[!] Config file not found:", *file)
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal(err)
	}
	log.Println("[*] Config file loaded")
	return config
}

// Apply defaults if config fields are empty
func chkConfig(file *string) Config {
	config := chkYaml(file)

	if config.FTP_PROTO.Version == "" {
		config.FTP_PROTO.Version = "220 FTP Server Ready"
	}
	if config.FTP_PROTO.Banner == "" {
		config.FTP_PROTO.Banner = "Welcome to FTP server."
	}
	if config.SERVER.Port == "" {
		config.SERVER.Port = "21"
	}
	if config.SERVER.Address == "" {
		config.SERVER.Address = "0.0.0.0"
	}

	return config
}

// Check if flag is present
func chkFlag(name string) bool {
	found := false

	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})

	return found
}

// This is for logging.
func setLogger(logfile *string) (*os.File, error) {
	var logfd *os.File
	var err error

	logfd, err = os.OpenFile(*logfile, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644) // Create and open file to append data

	if err != nil {
		log.Fatal("[!] Error opening file:", err)

	}

	log.SetOutput(logfd)

	return logfd, nil

}

// Log JSON for each login attempt
func writeJson(outputfile *string, remoteAddr, user, password string) {
	data, err := json.Marshal(struct {
		RemoteAddr string `json:"remote_addr"`
		User       string `json:"user"`
		Password   string `json:"password"`
	}{
		RemoteAddr: remoteAddr,
		User:       user,
		Password:   password,
	})

	if err != nil {
		log.Fatal("[!] Error creating JSON:", err)
	}

	file, err := os.OpenFile(*outputfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatal("[!] Error opening file:", err)
	}
	defer file.Close()

	data = append(data, '\n')

	if _, err := file.Write(data); err != nil {
		log.Fatal("[!] Error writing JSON:", err)
	}

	log.Println("[*] Logged JSON to:", *outputfile)
}

// Log connection accept errors
func writeAcceptError(err error, remoteAddr string) {
	log.Println("[!] Error accepting connection:", err, remoteAddr)

}

// Handle incoming FTP connections
func handleConn(conn net.Conn, banner string, outputfile *string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	// Send banner
	conn.Write([]byte(fmt.Sprintf("%s\r\n", banner)))
	time.Sleep(50 * time.Millisecond)

	reader := bufio.NewReader(conn)

	// USER command
	data, err := reader.ReadString('\n')
	if err != nil {
		log.Println("[!] Error reading USER:", err)
		return
	}

	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "USER") {
		conn.Write([]byte("500 Command not found.\r\n"))
		return
	}

	username := strings.TrimSpace(strings.SplitN(data, " ", 2)[1])
	conn.Write([]byte("331 User name ok, password required.\r\n"))

	// PASS command
	data, err = reader.ReadString('\n')
	if err != nil {
		log.Println("[!] Error reading PASS:", err)
		return
	}

	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "PASS") {
		conn.Write([]byte("500 Command not found.\r\n"))
		return
	}

	password := strings.TrimSpace(strings.SplitN(data, " ", 2)[1])
	conn.Write([]byte("530 Incorrect password, not logged in.\r\n"))

	// Log attempt
	log.Println("[*] Login attempt from", remoteAddr, "User:", username, "Password:", password)

	// Write JSON if outputfile is specified
	if chkFlag("o") {
		writeJson(outputfile, remoteAddr, username, password)
	}
}

func main() {

	var file *string
	var outputfile *string
	var logfile *string

	var logfd *os.File
	var err error

	file = flag.String("f", "", "Specify config yaml file")
	outputfile = flag.String("o", "", "Specify log file to save results in as json")
	logfile = flag.String("l", "", "Specify log file to save results in as a text file")
	flag.Parse()

	flag.Parse()

	if !chkFlag("f") {
		log.Println("[!] No config file specified")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if chkFlag("l") {
		fmt.Println("[*] Logging to:", *logfile)
		logfd, err = setLogger(logfile)

	}

	// Pretty sure this is wrong. I don't remember what and why I did this.
	if err != nil {
		log.Fatal("[!] Error opening log file:", err)
	}

	defer logfd.Close()

	config := chkConfig(file)

	listener, err := net.Listen("tcp", config.SERVER.Address+":"+config.SERVER.Port)
	if err != nil {
		log.Fatal("[!] Failed to listen:", err)
	}
	defer listener.Close()
	log.Println("[*] FTP Server listening on", config.SERVER.Address+":"+config.SERVER.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			writeAcceptError(err, "")
			continue
		}
		go handleConn(conn, config.FTP_PROTO.Banner, outputfile)
	}
}
