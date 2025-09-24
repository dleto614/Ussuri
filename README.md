# Ussuri: Collection of honeypots and related utils

### Background:

This idea came from wanting to see if I could write my own ssh honeypot in Go which I've been able to do and it runs pretty well.
I haven't had a chance to test these honeypot(s) out in the wild yet, but from my understanding it should work well.

I also plan on adding a golang password util to work alongside these honeypots since the general idea for offensive is to build
wordlists from the scanners/bots that attack the honeypots which is what I did a long time ago when I ran cowrie for 3 months.

Ussuri are a type of bear and you can learn more about them here: https://en.wikipedia.org/wiki/Ussuri_brown_bear

I thought it was fitting to name this repository after a bear because of honey and the stereotype that bears like honey which is mostly true.

------

### SSH Honeypot:

This is a pretty simple go program and it takes config file in YAML format. I've included an example, but I couldn't figure out how to change the banner using the library so I ended up using the config file idea so any SSH version/banner could be used to help blend in more. The example from `openssh.yaml`:

```yaml

ssh-proto:
  version: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2"

server:
  server: 127.0.0.1
  port: "2222"

  keys:
    private: "id_rsa"
    public: "id_rsa.pub"
```

Currently the yaml is required, but in the future, I might get rid of the requirenment and just use the defaults in chkConfig() or something like that if the YAML config is never specified, but I think it is more proper to require the config.

The output file is optional, but output is written as JSON to make it easier to parse and extract data that is wanted. This is because I remember cowrie really didn't have a friendlier format to parse and extract the data I wanted.

There is a logfile command line option, but if not specified, any logging message goes to STDOUT aka the terminal.

---

Usage:

```bash
$ ./ssh-honeypot -h
Usage of ./ssh-honeypot:
  -f string
        Specify config yaml file
  -l string
        Specify log file to save results in as a text file
  -o string
        Specify log file to save results in as json
```

---

To compile and run:

```bash
cd ssh-honeypot && go build
./ssh-honeypot -f openssh.yaml -o test-ssh.json
```

---

In my local testing I used medusa and used the very small wordlists in `test-wordlists` directory.

Medusa command:

```bash
medusa -M ssh -h 127.0.0.1 -n 2222 -P test-wordlists/password.txt -U test-wordlists/username.txt
```

------

### FTP Honeypot"

This is the same as the ssh honeypot above with the same yaml config file. I have an example `ftp.yaml`:

```yaml
ftp-proto:
  version: "FTP-1.0"
  banner: "220 Welcome to My FTP Honeypot Server"

server:
  address: "0.0.0.0"
  port: "2121"

```

------

To compile and run:

```bash
cd ftp-honeypot && go build
./ftp-honeypot -f ftp.yaml -o test-ftp.json
```

------

In my local testing I've used medusa and small wordlists in `test-wordlists` directory.

Medusa command:

```bash
medusa -M ftp -h 127.0.0.1 -n 2121 -U test-wordlists/username.txt -P test-wordlists/password.txt 
```

------

Usage:

```bash
Usage:
  -f string
        Specify config yaml file
  -l string
        Specify log file to save results in as a text file
  -o string
        Specify log file to save results in as json
```

------

Future plans:

~~- Write FTP honeypot~~ Done!
- Write honeypots for various databases
- Write honeypot for SMB
- Write the password util
- Add other protocols as I feel like or whatever I'm researching at the time