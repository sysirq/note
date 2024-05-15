```sh
sysirq@sysirq-machine:~$ cat /etc/systemd/logind.conf 
......
HandleLidSwitch=ignore
......
```

```sh
sysirq@sysirq-machine:~$ cat /etc/NetworkManager/conf.d/default-wifi-powersave-on.conf 
[connection]
wifi.powersave = 2
```

```sh
sysirq@sysirq-machine:~$ iwconfig 
lo        no wireless extensions.

enp63s0   no wireless extensions.

wlp0s20f3  IEEE 802.11  ESSID:"ziroom502"  
          Mode:Managed  Frequency:2.447 GHz  Access Point: 30:AE:7B:E2:84:95   
          Bit Rate=115.6 Mb/s   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:off
          Link Quality=45/70  Signal level=-65 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:30   Missed beacon:0

wg0       no wireless extensions.

sysirq@sysirq-machine:~$ 
```


# 资料

1.Losing network connectivity when laptop lid is cloed

https://unix.stackexchange.com/questions/764765/losing-network-connectivity-when-laptop-lid-is-cloed