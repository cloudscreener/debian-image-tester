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
2016-12-06T22:45:20.567Z dit(5680) [00:00.095ms] DEBUG: debug mode set to true
2016-12-06T22:45:21.599Z dit(5680) [00:01.127ms] DEBUG: remote> LC_ALL=C LANG=C id -u
2016-12-06T22:45:21.639Z dit(5680) [00:01.167ms] DEBUG: 1000
2016-12-06T22:45:21.639Z dit(5680) [00:01.167ms] DEBUG: ssh cmd exec done
[1] pry(main)> prober.run!
2016-12-06T22:45:39.900Z dit(5680) [00:19.428ms] INFO: starting sysctl_dump step…
2016-12-06T22:45:39.976Z dit(5680) [00:19.503ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E sysctl -a
2016-12-06T22:45:40.015Z dit(5680) [00:19.543ms] DEBUG: abi.vsyscall32 = 1
crypto.fips_enabled = 0
debug.exception-trace = 1
[...]
vm.vfs_cache_pressure = 100
vm.zone_reclaim_mode = 0
2016-12-06T22:45:40.018Z dit(5680) [00:19.546ms] DEBUG: ssh cmd exec done
2016-12-06T22:45:40.019Z dit(5680) [00:19.547ms] INFO: sysctl_dump step finished
2016-12-06T22:45:40.019Z dit(5680) [00:19.547ms] INFO: starting dpkg_list step…
2016-12-06T22:45:40.091Z dit(5680) [00:19.619ms] DEBUG: remote> LC_ALL=C LANG=C dpkg -l
2016-12-06T22:45:40.131Z dit(5680) [00:19.659ms] DEBUG: Desired=Unknown/Install/Remove/Purge/Hold
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
2016-12-06T22:45:40.136Z dit(5680) [00:19.664ms] DEBUG: ssh cmd exec done
2016-12-06T22:45:40.136Z dit(5680) [00:19.664ms] INFO: dpkg_list step finished
2016-12-06T22:45:40.136Z dit(5680) [00:19.664ms] INFO: starting etc_tarball step…
2016-12-06T22:45:40.208Z dit(5680) [00:19.735ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E tar cfJ - /etc
2016-12-06T22:45:40.664Z dit(5680) [00:20.192ms] DEBUG: ssh cmd exec done
2016-12-06T22:45:40.664Z dit(5680) [00:20.192ms] INFO: etc_tarball step finished
2016-12-06T22:45:40.665Z dit(5680) [00:20.192ms] INFO: starting install_cruft step…
2016-12-06T22:45:40.736Z dit(5680) [00:20.263ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E apt-get install -y cruft
2016-12-06T22:45:40.775Z dit(5680) [00:20.303ms] DEBUG: Reading package lists...
2016-12-06T22:45:40.775Z dit(5680) [00:20.303ms] DEBUG: 
2016-12-06T22:45:40.775Z dit(5680) [00:20.303ms] DEBUG: Building dependency tree...
2016-12-06T22:45:40.845Z dit(5680) [00:20.373ms] DEBUG: 
Reading state information...
2016-12-06T22:45:40.846Z dit(5680) [00:20.373ms] DEBUG: 
2016-12-06T22:45:40.905Z dit(5680) [00:20.433ms] DEBUG: cruft is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 20 not upgraded.
2016-12-06T22:45:40.906Z dit(5680) [00:20.434ms] DEBUG: ssh cmd exec done
2016-12-06T22:45:40.906Z dit(5680) [00:20.434ms] INFO: install_cruft step finished
2016-12-06T22:45:40.906Z dit(5680) [00:20.434ms] INFO: starting cruft step…
2016-12-06T22:45:40.976Z dit(5680) [00:20.503ms] DEBUG: remote> LC_ALL=C LANG=C sudo -E cruft --ignore '/dev /home /run /tmp /vagrant /var/cache/apt/archives' -d /
2016-12-06T22:45:58.294Z dit(5680) [00:37.821ms] DEBUG: cruft report: Tue Dec  6 21:45:56 GMT 2016

---- unexplained: / ----
        /etc/apt/apt.conf.d/00CDMountPoint
        /etc/apt/apt.conf.d/00aptitude
[...]
        /var/log/syslog
        /var/log/user.log
---- broken symlinks: / ----
        /usr/lib/python2.6/dist-packages/python-support.pth

end.
2016-12-06T22:45:58.294Z dit(5680) [00:37.822ms] DEBUG: ssh cmd exec done
2016-12-06T22:45:58.295Z dit(5680) [00:37.823ms] INFO: cruft step finished
=> [{:name=>:sysctl_dump, :cmd=>"sysctl -a", :sudo=>true, :store=>true},
 {:name=>:dpkg_list, :cmd=>"dpkg -l", :sudo=>false, :store=>true},
 {:name=>:etc_tarball, :cmd=>"tar cfJ - /etc", :sudo=>true, :store=>true, :nolog=>true, :filename=>"etc.tar.xz"},
 {:name=>:install_cruft, :cmd=>"apt-get install -y cruft", :sudo=>true, :store=>false},
 {:name=>:cruft, :cmd=>"cruft --ignore '/dev /home /run /tmp /vagrant /var/cache/apt/archives' -d /", :sudo=>true, :store=>true}]
[2] pry(main)> prober.reports
=> {:cruft=>{:unexplained=>60, :broken_symlinks=>1}, :packages_diff=>{:official=>163, :target=>437, :shared=>163, :unshared=>274, :added=>274, :removed=>0}}
[3] pry(main)> prober.results
=> {:cruft=>
  {:unexplained=>
    ["/etc/apt/apt.conf.d/00CDMountPoint",
     "/etc/apt/apt.conf.d/00aptitude",
[...]
     "xz-utils"],
   :removed=>[]}}
[4] pry(main)> prober.results.keys
=> [:cruft, :packages_diff]
[5] pry(main)> prober.results.each { |k, v| puts "#{k}: #{v.keys}" }; nil
cruft: [:unexplained, :broken_symlinks]
packages_diff: [:official, :target, :shared, :unshared, :added, :removed]
=> nil
[6] pry(main)> ^D
> ls -R output/
output/:
vagrant

output/vagrant:
cruft  dpkg_list  etc.tar.xz  sysctl_dump
> 
```
