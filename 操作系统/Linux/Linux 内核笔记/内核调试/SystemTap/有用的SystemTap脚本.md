# 网络

nettop.stp
```
#! /usr/bin/env stap

global ifxmit, ifrecv
global ifmerged

probe netdev.transmit
{
  ifxmit[pid(), dev_name, execname(), uid()] <<< length
  ifmerged[pid(), dev_name, execname(), uid()] <<< 1
}

probe netdev.receive
{
  ifrecv[pid(), dev_name, execname(), uid()] <<< length
  ifmerged[pid(), dev_name, execname(), uid()] <<< 1
}

function print_activity()
{
  printf("%5s %5s %-12s %7s %7s %7s %7s %-15s\n",
         "PID", "UID", "DEV", "XMIT_PK", "RECV_PK",
         "XMIT_KB", "RECV_KB", "COMMAND")

  foreach ([pid, dev, exec, uid] in ifmerged-) {
    n_xmit = @count(ifxmit[pid, dev, exec, uid])
    n_recv = @count(ifrecv[pid, dev, exec, uid])
    printf("%5d %5d %-12s %7d %7d %7d %7d %-15s\n",
           pid, uid, dev, n_xmit, n_recv,
           @sum(ifxmit[pid, dev, exec, uid])/1024,
           @sum(ifrecv[pid, dev, exec, uid])/1024,
           exec)
  }

  print("\n")

  delete ifxmit
  delete ifrecv
  delete ifmerged
}

probe timer.ms(5000), end, error
{
  print_activity()
}
```