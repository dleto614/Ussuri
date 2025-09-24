package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type sshProtoConfig struct {
	Version string `yaml:"version"`
	Banner  string `yaml:"banner"`
}

type serverConfig struct {
	Port    string `yaml:"port"`
	Address string `yaml:"address"`

	Keys struct {
		Private string `yaml:"private"`
		Public  string `yaml:"public"`
	} `yaml:"keys"`
}

type Config struct {
	SSH_PROTO sshProtoConfig `yaml:"ssh-proto"`

	SERVER serverConfig `yaml:"server"`
}

// Generate a private key.
func generatePrivateKey(filename string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err

	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	file, err := os.Create(filename)
	if err != nil {
		return err

	}
	defer file.Close()

	log.Println("[*] Generated private key:", filename)

	return pem.Encode(file, privateKeyPEM)
}

// Generate a public key.
func generatePublicKey(privateKeyFilename, publicKeyFilename string) error {
	privateKeyBytes, err := os.ReadFile(privateKeyFilename)
	if err != nil {
		return err

	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("failed to decode PEM private key")

	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return err

	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err

	}

	log.Println("[*] Generated public key:", publicKeyFilename)
	return os.WriteFile(publicKeyFilename, ssh.MarshalAuthorizedKey(publicKey), 0644)
}

// This checks the yaml file.
func chkYaml(file *string) Config {
	var config Config
	_, err := os.Stat(*file)
	if err == nil {
		data, err := os.ReadFile(*file)
		if err != nil {
			log.Fatal(err)
		}
		if err := yaml.Unmarshal(data, &config); err != nil {
			log.Fatal(err)
		}
	}

	log.Println("[*] Config file loaded")
	return config
}

// This checks the keys.

// TODO: Generate in directories and/or allow that option?
func chkKeys(private string, public string) ssh.Signer {
	privateKeyFileInfo, privateKeyErr := os.Stat(private)
	publicKeyFileInfo, publicKeyErr := os.Stat(public)

	// I guess this logic checks if the keys exist or not without regenerating if private and public keys do exist.
	if privateKeyErr != nil || publicKeyErr != nil || privateKeyFileInfo == nil || publicKeyFileInfo == nil {

		log.Println("[*] Generating keys...")

		err := generatePrivateKey(private)
		if err != nil {
			log.Fatal("[!] Error generating private key:", err)

		} else {
			log.Println("[*]Private key generated")

		}

		err = generatePublicKey(private, public)
		if err != nil {
			log.Fatal("[!] Error generating public key:", err)

		} else {
			log.Println("[*] Public key generated")

		}
		log.Println("[*] Keys generated")
	}

	privateKeyData, err := os.ReadFile(private)
	if err != nil {
		log.Fatal("[!] Error reading private key:", err)

	} else {
		log.Println("[*] Private key read")
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyData)
	if err != nil {
		log.Fatal("[!] Error parse private key:", err)

	} else {
		log.Println("[*] Private key parsed")
	}

	log.Println("[*] Keys checked")
	return privateKey
}

// Some defaults. Probably can be coded differently and better.
func chkConfig(file *string) Config {
	config := chkYaml(file)

	if config.SSH_PROTO.Version == "" {
		config.SSH_PROTO.Version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2"
	}

	if config.SERVER.Port == "" {
		config.SERVER.Port = "22"
	}

	if config.SERVER.Address == "" {
		config.SERVER.Address = "0.0.0.0"
	}

	return config
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s: \n", os.Args[0])
	fmt.Println()
	flag.PrintDefaults()
}

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

func writeAcceptError(error error, remoteAddr string) {
	log.Println("[!] Error:", error, remoteAddr)

}

// Write the results in json format in a file. (This is for easy parsing of the attemps made by the attacker)
func writeJson(outputfile *string, remoteAddr string, clientVersion string, user string, password string) {
	data, err := json.Marshal(struct {
		RemoteAddr    string `json:"remote_addr"`
		ClientVersion string `json:"client_version"`
		User          string `json:"user"`
		Password      string `json:"password"`
	}{
		RemoteAddr:    remoteAddr,
		ClientVersion: clientVersion,
		User:          user,
		Password:      password,
	})

	if err != nil {
		log.Fatal("[!] Error creating json:", err)

	}

	file, err := os.OpenFile(*outputfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // Create and open file to append data

	if err != nil {
		log.Fatal("[!] Error opening file:", err)

	}
	defer file.Close()

	data = append(data, '\n')

	_, err = file.Write(data)
	if err != nil {
		log.Fatal("[!] Error writing json:", err)

	}

	log.Println("[*] Logged json to:", *outputfile)
}

// Handle incoming connections.
func handleConn(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer conn.Close()
	ssh.NewServerConn(conn, serverConfig)

}

func main() {

	bear := `
	⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⣀⡀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠈⢻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠛⠻⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠂⠀⠀⠀⢡⣾⣿⣻⣿⣿⣭⣿⣿⣿⣦⡀⠀⠀⠹⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀
⠀⠀⣀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⡀⠉⣡⣼⣿⣿⣿⣿⣿⣿⣿⣿⢷⣦⠀⠀⢻⣿⣿⣿⣿⡇⠀⠀⠀⠀
⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠀⡴⠑⢺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣧⡀⣿⣿⣿⣿⣿⣿⣶⣀⣴⡄
⣦⣿⣿⣿⣿⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⣘⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣻⡿⣟⡷⠾⠿⡿⣿⣿⠻⠷⢻⣿⣿⣿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⠀⠉⠀⠋⠈⠀⠂⢹⣿⣏⠀⠀⠉⠻⢾⣿⠧⢹⣿⣿⣿⣿⣿⣿⣿⣻⣤⡄
⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⠄⠀⠀⠀⠀⠀⢀⣾⣿⣿⢄⠀⠀⠀⠀⠉⢣⠀⣻⣿⣿⣿⣿⣿⣿⣿⣿⢻
⣿⣿⣿⣿⣿⣻⢿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠁⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⡀⠀⠀⠀⠀⣌⠈⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀
⣿⣿⣿⡿⣻⡿⢿⡿⣿⣿⣿⠟⣿⣯⣾⣿⣯⣾⣿⣿⡇⠀⠁⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣇⠀⠀⠀⡀⢳⣦⣽⣿⣿⣿⣿⣿⣿⣿⠇⠘
⣿⣿⠛⣼⣟⡇⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡂⠀⠀⠀⠀⠀⠀⢹⡟⡿⣿⣿⣿⣿⡇⠀⢠⣀⠈⡟⢸⣿⣿⣿⣿⣿⣿⡿⠀⠀
⣿⠋⣻⣿⡿⠀⡿⣿⣿⣿⣻⢃⣿⣿⡿⢻⡟⠃⢻⣇⡅⠠⠀⠀⠀⠔⠀⢨⠀⠀⠀⠈⢽⣿⠃⠐⠾⠘⠶⠁⣿⣿⣿⣿⡿⣿⡿⠃⠀⠀
⣠⣴⣿⠟⠀⡰⣧⢺⣿⣏⣟⣾⣿⣻⣂⡄⢛⡅⠀⠃⠀⠀⠀⠀⠀⠀⠀⢸⡀⠀⠀⠀⢸⣿⠀⠄⠀⠀⠀⣸⣿⣿⣿⣷⣦⠛⠀⠀⠀⠀
⣿⢋⠁⠀⡴⠁⠊⢀⣿⡿⢣⢿⣿⣾⡏⠀⣸⢰⠂⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⠀⣿⠇⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⡄⠀⣶⠀⠀
⢱⠃⠀⢀⡄⠀⠂⣼⣿⡧⢋⣼⡿⡿⡁⡆⠈⠎⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠀⠴⠊⠀⠆⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⢸⡏⠀⠀
⠊⠀⢠⡾⠁⠀⠀⣿⣿⣾⠟⣩⡇⢐⣏⣴⠀⠇⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠆⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⡿⠛⠘⠁⠀⠀
⠀⠀⠈⠀⠀⠀⢰⣿⡟⠻⢠⡟⠀⢸⣿⡇⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠘⠈⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣼⢿⣿⡀⢸⠀⠀⠘⣿⠂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣿⣿⣿⡏⢹⣿⠁⠀⠸⠀⢀⠀
	`

	fmt.Println("|-------------------------------------------------------------------|")
	fmt.Println(bear)
	fmt.Println("|-------------------------------------------------------------------|")
	fmt.Println("|                             SSH Honeypot                          |")
	fmt.Println("|-------------------------------------------------------------------|")
	fmt.Println("")

	fmt.Println("[*] Checking arguments...")
	fmt.Println("")

	var errBadPassword = errors.New("permission denied")

	var file *string
	var outputfile *string
	var logfile *string

	var logfd *os.File
	var err error

	file = flag.String("f", "", "Specify config yaml file")
	outputfile = flag.String("o", "", "Specify log file to save results in as json")
	logfile = flag.String("l", "", "Specify log file to save results in as a text file")
	flag.Parse()

	// Yaml is required??? Might need to change this some other time
	// since techically we can do without it and just set defaults in chkConfig() function.
	if !chkFlag("f") {
		log.Println("[!] No config file specified")
		usage()
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
	privateKey := chkKeys(config.SERVER.Keys.Private, config.SERVER.Keys.Public)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Println("[*]", conn.RemoteAddr(), string(conn.ClientVersion()), conn.User(), string(password))
			time.Sleep(100 * time.Millisecond)

			if chkFlag("o") {
				writeJson(outputfile, conn.RemoteAddr().String(), string(conn.ClientVersion()), conn.User(), string(password))
			}

			return nil, errBadPassword
		},
		ServerVersion: config.SSH_PROTO.Version,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return config.SSH_PROTO.Banner
		},
	}

	serverConfig.AddHostKey(privateKey)

	listener, err := net.Listen("tcp", config.SERVER.Address+":"+config.SERVER.Port)
	if err != nil {
		log.Fatal("[!] Failed to listen:", err)

	}
	defer listener.Close()

	log.Println("[*] Listening for connections...")

	// Accept connections and handle them.
	// This is an infinite loop that will run until the program is killed.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[!] Failed to accept:", err)
			writeAcceptError(err, conn.RemoteAddr().String())

		} else {
			go handleConn(conn, serverConfig)

		}
	}
}
