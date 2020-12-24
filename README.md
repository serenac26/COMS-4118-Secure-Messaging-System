# The Silmailion

Group name: Secur(s)ed
Group members:
Serena "Froggins Baggins" Cheng (stc2137)
William "Samgee Gamgee" Chiu (wnc2105)
Stacy "Pook Took" Tao (syt2111)
Meribuck "Harrison Wang" Brandybuck (hbw2118)

## Usage

Setup:
`sudo rm -rf <treename> && make clean && make install TREE=<treename>`

Start the server as root:
`sudo cd <treename>/server/bin`
`sudo ./pemithor`

Send client requests:
`cd <treename>/client/bin`
`./genkey.sh <key output file>`
`./getcert`
`./changepw`
`./sendmsg`
`./recvmsg`

## Testing

Refer to `test` directory

## Notes

If you run into an error with `/usr/share/dict/words`, please try:

```sudo apt-get install --reinstall wamerican```

If you are missing libssl-dev ```fatal error: openssl/ssl.h: No such file or directory```, please try:

```sudo apt-get install libssl-dev```


## TODO:
uncomment line "# chown -hR root:root \$1/server" in install-priv.sh
remove line "echo "$cred" >> creds.txt" in install-unpriv.sh

## Design Documentation
need to convert to markdown
https://docs.google.com/document/d/1J0lWIIuWZit5dgo3vR-ZorzSi4Fs7MPWzHYjdcN2mhU/edit?usp=sharing