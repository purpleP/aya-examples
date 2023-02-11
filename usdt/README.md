Check that tracepoint is present
```sh
$ readelf -n ./target/release/usdt

Displaying notes found in: .note.gnu.property
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_PROPERTY_TYPE_0
      Properties: x86 ISA needed: x86-64-baseline

Displaying notes found in: .note.gnu.build-id
  Owner                Data size 	Description
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 69f2454147ab0999f77b0a90a2fcb62b74b47cc6

Displaying notes found in: .note.ABI-tag
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0

Displaying notes found in: .note.stapsdt
  Owner                Data size 	Description
  stapsdt              0x00000035	NT_STAPSDT (SystemTap probe descriptors)
    Provider: hello_provider
    Name: hello
    Location: 0x000000000000887b, Base: 0x0000000000045006, Semaphore: 
    0x0000000000051032
    Arguments: -8@%rax
```

Run the program

```sh

$ ./target/debug/usdt | head -n10
Hello, world! 0
elapsed 12851 ns
Hello, world! 1
elapsed 1467 ns
Hello, world! 2
elapsed 1466 ns
Hello, world! 3
elapsed 1886 ns
Hello, world! 4
elapsed 1396 ns
```


Withot probe
```sh
$ ./target/release/usdt | grep loop | head -n10
loop took 9568 ns
loop took 2444 ns
loop took 1885 ns
loop took 2374 ns
loop took 2375 ns
loop took 1885 ns
loop took 1886 ns
loop took 1886 ns
loop took 1885 ns
loop took 1885 ns
```
With probe
```
sudo trace-bpfcc -p $(pidof usdt) 
'u:/home/m/code/aya-examples/usdt/target/release/usdt:hello_provider:hello "%d", 
arg1' -T


loop took 2375 ns
loop took 908 ns
loop took 2794 ns
loop took 1396 ns
loop took 1955 ns
loop took 978 ns
loop took 978 ns
loop took 2374 ns
loop took 2305 ns
loop took 1956 ns
loop took 1467 ns

```
