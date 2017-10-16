HSR-CPU-Miner
=============

HSR-CPU-Miner for Hshare
This is a multi-threaded CPU miner, fork of [pooler](//github.com/pooler), [luoam](//github.com/luoam).


Build
=====
```
  git clone https://github.com/emozonic/HSR-CPU-Miner && cd HSR-CPU-Miner && chmod +x autogen.sh && ./autogen.sh && ./configure CFLAGS="-O3" && make
```

Usage
=====
```
  ./minerd -a -o x14 stratum+tcp://hsr.mine.zpool.ca:7433#xnsub -u HF4DRBxF3wnRpv4cfFkWUHaBD66NtxSEtY -p c=HSR -t 2
```


**HSR:** ```HF4DRBxF3wnRpv4cfFkWUHaBD66NtxSEtY```

**ETH:** ```0xBe04c9939b5D340AF5e8C5883cD7797c406e2641```
