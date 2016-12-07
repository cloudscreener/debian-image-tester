# -*- mode:ruby;tab-width:2;indent-tabs-mode:nil;coding:utf-8 -*-
# vim: ft=ruby syn=ruby fileencoding=utf-8 sw=2 ts=2 ai eol et si

VAGRANT_CPU = (ENV['VAGRANT_CPU'] || '2').freeze
VAGRANT_RAM = (ENV['VAGRANT_RAM'] || '1024').freeze

Vagrant.configure(2) do |config|
  config.vm.hostname = 'dit-vagrant'
  config.vm.box_check_update = true

  config.ssh.username = 'vagrant'
  config.ssh.forward_x11 = false
  config.ssh.forward_agent = false

  config.vm.provider :virtualbox do |vb, override|
    override.vm.box = 'debian/jessie64'

    vb.customize ['modifyvm', :id, '--cpus',     VAGRANT_CPU]
    vb.customize ['modifyvm', :id, '--memory',   VAGRANT_RAM]
    # Enabling the I/O APIC is required for 64-bit guest operating systems.
    # it is also required if you want to use more than one virtual CPU in a VM.
    vb.customize ['modifyvm', :id, '--ioapic',   'on']
    # Enable the use of hardware virtualization extensions (Intel VT-x or AMD-V)
    # in the processor of your host system
    vb.customize ['modifyvm', :id, '--hwvirtex', 'on']
    # Disable audio
    vb.customize ['modifyvm', :id, '--audio',    'none']
  end
end
