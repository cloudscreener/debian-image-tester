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

    vb.customize ['modifyvm', :id, '--cpus',   VAGRANT_CPU]
    vb.customize ['modifyvm', :id, '--memory', VAGRANT_RAM]
  end
end
