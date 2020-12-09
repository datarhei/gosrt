Implementation of the SRT protocol in pure go

- [SRT reference implementation](https://github.com/Haivision/srt)
- [SRT RFC](https://haivision.github.io/srt-rfc/draft-sharabayko-mops-srt.txt)
- [SRT Technical Overview](https://github.com/Haivision/srt/files/2489142/SRT_Protocol_TechnicalOverview_DRAFT_2018-10-17.pdf)

# TODO

Everything

- nicer API <- done
- less CPU <- the ticker per connection uses up a lot of CPU because it is in a tight loop

# Try it out

Do this only on your own risk. You should have:

## Setup

- macOS (something recent)
- Homebrew
- go

Install ffmpeg and libsrt:

```
brew install ffmpeg
brew install srt
```

Build the binary of the server:

```
cd server
go build
```

You should end up with the `gosrt` binary.

Build the client:

```
cd contrib
clang -Wall -O2 -o client client.c -lsrt -L/usr/local/Cellar/openssl@1.1/1.1.1h/lib -lssl -lcrypto
```

You may need to adjust the path to the OpenSSL libs as the version might change meanwhile.

## Connect the pieces

Start ffmpeg pumping a mpegts stream to an UDP address:

```
ffmpeg -f lavfi -re -i testsrc2=rate=25:size=640x360 -codec:v libx264 -b:v 1024k -maxrate:v 1024k -bufsize:v 1024k -preset ultrafast -r 25 -g 50 -pix_fmt yuv420p -vsync 1 -flags2 local_header -f mpegts "udp://127.0.0.1:6000?pkt_size=1316"
```

Then start the server:

```
./server
```

The server will listen on udp://127.0.0.1:6001 (this is currently hard-coded).

Now send the video data to the server:

```
srt-live-transmit udp://:6000 'srt://127.0.0.1:6001?streamid=publish' -v
```

You should see some messages on the screen like

```
Media path: 'udp://:6000' --> 'srt://127.0.0.1:6001?streamid=publish'
SRT parameters specified:

    streamid = 'publish'
Opening SRT target caller on 127.0.0.1:6001
Connecting to 127.0.0.1:6001
SRT target connected 
```

The console where the `gosrt` server is running should also show something about handshake and so on.

Now start the client to get the stream from the server and pipe it into ffplay:

```
cd contrib
./client 127.0.0.1 6001 subscribe | ffplay -f mpegts -i -
```

You will first see some error messages from ffplay because the stream will most likely not start at a key frame. But then the window
with the video stream should pop up.

