# Debian-Image-Tester

Tool to measure the differences between Debian images with the official database

## Build Vagrant virtual machine

```
vagrant box add debian/jessie64
vagrant up
```

## Usage

```Shell
> ./dit.rb --help
dit: Debian Image Tester vX.X.X alpha in Ruby Y.Y.Y

Copyright © 2016 Cloudscreener SAS, MIT License [...]

Usage: dit [options] target_host
  Where target_host is the remote host name used by ssh command.
  When 'vagrant' is specified as target_host, 'vagrant ssh-config' will
  be used.

Options:
    -o, --output-directory=DIR       output directory (default to $PWD/output)
    -v, --[no-]verbose               run verbosely
    -d, --[no-]debug                 run and print (lots of) debug
    -t, --[no]-dry-run               run but only print commands
    -h, --help                       print help (this message) and exit
    -V, --version                    print version and exit
```

```Shell
> ./dit.rb -v -d vagrant
2016-12-06T00:24:47.743Z dit(1130) [00:00.113ms] DEBUG: debug mode set to true
2016-12-06T00:24:47.743Z dit(1130) [00:00.113ms] DEBUG: dry run mode set to 
2016-12-06T00:24:51.404Z dit(1130) [00:03.775ms] DEBUG: remote> LC_ALL=C LANG=C id -u
2016-12-06T00:24:51.446Z dit(1130) [00:03.816ms] DEBUG: 1000
2016-12-06T00:24:51.446Z dit(1130) [00:03.817ms] DEBUG: ssh cmd exec done
[1] pry(main)> prober.run!
2016-12-06T00:25:19.394Z dit(1130) [00:31.765ms] INFO: starting sysctl_dump step…
2016-12-06T00:25:19.477Z dit(1130) [00:31.848ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E sysctl -a
2016-12-06T00:25:19.518Z dit(1130) [00:31.889ms] DEBUG: abi.vsyscall32 = 1
crypto.fips_enabled = 0
debug.exception-trace = 1
[...]
vm.vfs_cache_pressure = 100
vm.zone_reclaim_mode = 0
2016-12-06T00:25:19.520Z dit(1130) [00:31.891ms] DEBUG: ssh cmd exec done
2016-12-06T00:25:19.521Z dit(1130) [00:31.891ms] INFO: sysctl_dump step finished
2016-12-06T00:25:19.521Z dit(1130) [00:31.891ms] INFO: starting dpkg_list step…
2016-12-06T00:25:19.603Z dit(1130) [00:31.974ms] DEBUG: remote> LC_ALL=C LANG=C dpkg -l
2016-12-06T00:25:19.646Z dit(1130) [00:32.017ms] DEBUG: Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                           Version                     Architecture Description
+++-==============================-===========================-============-===============================================================================
ii  acl                            2.2.52-2                    amd64        Access control list utilities
ii  acpi                           1.7-1                       amd64        displays information on ACPI devices
ii  acpi-support-base              0.142-6                     all          scripts for handling base ACPI events such as the power button
[...]
ii  xz-utils                       5.1.1alpha+20120614-2+b3    amd64        XZ-format compression utilities
ii  zlib1g:amd64                   1:1.2.8.dfsg-2+b1           amd64        compression library - runtime
2016-12-06T00:25:19.651Z dit(1130) [00:32.022ms] DEBUG: ssh cmd exec done
2016-12-06T00:25:19.652Z dit(1130) [00:32.022ms] INFO: dpkg_list step finished
2016-12-06T00:25:19.652Z dit(1130) [00:32.022ms] INFO: starting etc_tarball step…
2016-12-06T00:25:19.732Z dit(1130) [00:32.103ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E tar cfJ - /etc
2016-12-06T00:25:20.200Z dit(1130) [00:32.571ms] DEBUG: ssh cmd exec done
2016-12-06T00:25:20.201Z dit(1130) [00:32.571ms] INFO: etc_tarball step finished
2016-12-06T00:25:20.201Z dit(1130) [00:32.571ms] INFO: starting install_cruft_and_debootstrap step…
2016-12-06T00:25:20.274Z dit(1130) [00:32.645ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E apt-get install -y cruft debootstrap
2016-12-06T00:25:20.314Z dit(1130) [00:32.684ms] DEBUG: Reading package lists...
2016-12-06T00:25:20.314Z dit(1130) [00:32.684ms] DEBUG: 
2016-12-06T00:25:20.314Z dit(1130) [00:32.685ms] DEBUG: Building dependency tree...
2016-12-06T00:25:20.403Z dit(1130) [00:32.774ms] DEBUG: 
Reading state information...
2016-12-06T00:25:20.403Z dit(1130) [00:32.774ms] DEBUG: 
2016-12-06T00:25:20.482Z dit(1130) [00:32.853ms] DEBUG: cruft is already the newest version.
debootstrap is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 20 not upgraded.
2016-12-06T00:25:20.483Z dit(1130) [00:32.853ms] DEBUG: ssh cmd exec done
2016-12-06T00:25:20.483Z dit(1130) [00:32.854ms] INFO: install_cruft_and_debootstrap step finished
=> [{:name=>:sysctl_dump, :cmd=>"sysctl -a", :sudo=>true, :store=>true},
 {:name=>:dpkg_list, :cmd=>"dpkg -l", :sudo=>false, :store=>true},
 {:name=>:etc_tarball, :cmd=>"tar cfJ - /etc", :sudo=>true, :store=>true, :nolog=>true, :filename=>"etc.tar.xz"},
 {:name=>:install_cruft_and_debootstrap, :cmd=>"apt-get install -y cruft debootstrap", :sudo=>true, :store=>false}]
[2] pry(main)> ^D
> ls -R output/
output/:
vagrant

output/vagrant:
dpkg_list  etc.tar.xz  sysctl_dump
> 
```
