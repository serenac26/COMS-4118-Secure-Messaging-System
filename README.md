# The Silmailion

Serena "Froggins Baggins" Cheng (stc2137)

William "Samgee Gamgee" Chiu (wnc2105)

Stacy "Pook Took" Tao (syt2111)

Meribuck "Harrison Wang" Brandybuck (hbw2118)


`make install TREE=<name>`

## Notes

If you run into an error with /usr/share/dict/words, please try:
`sudo apt-get install --reinstall wamerican`

Missing libssl-dev:

```fatal error: openssl/ssl.h: No such file or directory```

```sudo apt-get install libssl-dev```



TODO:
uncomment line "# chown -hR root:root $1/server" in install-priv.sh \
remove line "echo "$cred" >> creds.txt" in install-unpriv.sh