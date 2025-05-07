# 0x00

```sh
curl -k https://192.168.31.182/dana-cached/hc/hc_launcher.22.7.2.3431.jar -o out
```

```sh
bash-4.2# ls /home/webserver/htdocs/dana-cached/hc/
ESAP				 dsHostCheckerSetup.exe
HostCheckerInstaller.osx	 epupdate_hist.xml
HostCheckerInstaller_arm64.osx	 hc_launcher.22.7.2.3431.jar
HostCheckerInstaller_x86_64.osx  hc_launcher.jar
HttpNarSetup.exe.cab		 hcimc.jar
HttpNarSetup.ini		 hostchecker.jar
HttpNarSetupApplet.ini		 neoHCLauncherApplet.ini
HttpNarSetupApplet.osx.ini	 pdmisc.xml
OPSWAT.conf			 personalfirewall.zip
RemoteIMVServerInstall.exe	 tncHCLauncherApplet.ini
StandAloneHttpNarInstall.exe	 tncc.jar
avupdate.xsd			 tncc_service.jar
```

# 0x01

```ruby
def get_productversion(ip,port)
  res = HTTParty.get("https://#{ip}:#{port}/dana-na/auth/url_admin/welcome.cgi?type=inter")

  return nil unless res&.code == 200

  m = res.body.match(/name="productversion"\s+value="(\d+.\d+.\d+.\d+)"/i)

  return nil unless m&.length == 2

  m[1]
end
```