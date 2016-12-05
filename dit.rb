#!/usr/bin/env ruby
# -*- mode:ruby;tab-width:2;indent-tabs-mode:nil;coding:utf-8 -*-
# vim: ft=ruby syn=ruby fileencoding=utf-8 sw=2 ts=2 ai eol et si
#
# dit.rb: Debian Image Tester
# (c) 2016 CloudScreener SAS, MIT License (see LICENSE file)
#
# Authors:
#   Laurent Vallar <laurent@cloudscreener.com>
#
# frozen_string_literal: true
# encoding: UTF-8

BEGIN {
  $PROGRAM_NAME = File.basename(__FILE__).gsub(/\.rb$/, '')
  START_TIME = Time.now
}

require 'fileutils'
require 'logger'
require 'open3'
require 'optparse'
require 'ostruct'
require 'pathname'
require 'singleton'

gem 'net-ssh'
require 'net/ssh'

VERSION = '0.0.1 alpha'

class CustomLogger < Logger
  def initialize(logdev = STDOUT, **args)
    super(logdev, args)

    self.level = Logger::WARN
    self.formatter = proc do |severity, timestamp, progname, msg|
      format("%s %s(%d) [%s] %s: %s\n",
             timestamp.strftime('%FT%T.%LZ'),
             $PROGRAM_NAME,
             Process.pid,
             Time.at(timestamp.utc - START_TIME + (3600 * 23))
                 .strftime('%M:%S.%Lms'),
             CustomLogger.color(severity),
             msg)
    end
  end

  private

  def self.color(severity)
    color = case severity
            when 'DEBUG'
              '0;37' # gray
            when 'INFO'
              '0;32' # green
            when 'WARN'
              '0;33' # yellow
            when 'ERROR'
              '0;31' # red
            when 'FATAL'
              '1;31' # light red
            when 'UNKNOWN'
              '1;35' # light purple
            else
              raise "invalid logger severity: #{severity.inspect}"
            end
    "\e[#{color}m#{severity}\e[0;0m"
  end
end

class Settings < OpenStruct
  def self.parse!(args, logger)
    settings = self.new
    settings.logger = logger

    # defaults
    settings.verbose = !!ENV['VERBOSE']
    settings.debug = !!ENV['DEBUG']
    settings.test = !!ENV['TEST']
    settings.debian_mirror = ENV['DEBIAN_MIRROR'] \
      || 'http://http.debian.org/debian'
    settings.debian_dist = ENV['DEBIAN_DIST'] || 'jessie'

    settings.option_parser = OptionParser.new do |opts|
      opts.program_name = $PROGRAM_NAME

      opts.banner = <<-EOS
#{$PROGRAM_NAME}: Debian Image Tester v#{::VERSION} in Ruby #{RUBY_VERSION}

Copyright © 2016 Cloudscreener SAS, MIT License (see LICENSE file).

Author(s):
  Laurent Vallar <laurent@cloudscreener.com>

Usage: #{opts.program_name} [options] target_host
  Where target_host is the remote host name used by ssh command.
  When 'vagrant' is specified as target_host, 'vagrant ssh-config' will
  be used.

      EOS

      opts.separator 'Options:'

      opts.on('-oDIR', '--output-directory=DIR', String,
              'output directory (default to $PWD/output)' ) do |path|
        settings.logger.debug "output_dir set to #{path}"
        settings.output_directory = Pathname.new(path)
      end

      opts.on("-v", "--[no-]verbose", "run verbosely") do |bool|
        logger = settings.logger
        logger.level = Logger::INFO unless logger.debug?
        logger.debug "verbose mode set to #{bool}"
        settings.verbose = bool
      end

      opts.on('-d', '--[no-]debug', 'run and print (lots of) debug') do |bool|
        logger = settings.logger
        logger.level = Logger::DEBUG
        logger.debug "debug mode set to #{bool}"
        settings.debug = bool
      end

      opts.on('-t', '--[no]-dry-run', 'run but only print commands') do |bool|
        settings.logger.debug "dry run mode set to #{bool}"
        settings.test = bool
      end

      opts.on_tail('-h', '--help', 'print help (this message) and exit') do
        puts opts
        exit
      end

      opts.on_tail('-V', '--version', 'print version and exit') do
        puts "#{$PROGRAM_NAME} v#{::VERSION}"
        exit
      end
    end

    settings.banner = "#{settings.option_parser.to_s}\n"

    args = settings.option_parser.parse!(args)
    settings.error("wrong target_host argument: #{args.inspect}") \
      unless args.size == 1

    settings.target_host = args.first
    settings.output_directory ||= (Pathname.new(__dir__) + 'output')
    settings
  end

  def error(message)
    STDERR.puts <<-EOS
\u001b[1;91mERROR\u001b[0m \u001b[1m#{message}\u001b[0m

#{self.banner}
    EOS
    exit 1
  end
end

class CommandController
  include Singleton
  include Open3

  attr_reader :settings, :logger

  def initialize(args = ARGV)
    @logger = ::CustomLogger.new
    @settings = ::Settings.parse!(args, @logger)
    @settings.sudo = !root?(sudo: false)
    @settings.freeze
  end

  def run_local(cmd, sudo: @settings.sudo, nolog: false)
    run_cmd cmd, sudo: sudo, nolog: nolog
  end

  def run_remote(cmd, sudo: @settings.sudo, nolog: false)
    ::Net::SSH.start(*ssh_opts) do |ssh|
      run_cmd cmd, sudo: sudo, nolog: nolog, ssh: ssh
    end
  end

  def check_access(command = 'cat /etc/passwd', sudo: false)
    begin
      run_remote(command, sudo: sudo)
      true
    rescue Errno::ECONNRESET, Net::SSH::Disconnect => exception
      log.error(exception.message)
      false
    end
  end

  def check_sudo_access(command = 'cat /etc/shadow')
    check_access(command, sudo: true)
  end

  def root?(sudo: (@settings.sudo || false))
    run_remote('id -u', sudo: sudo) == '0'
  end

  private

  NEED_ROOT_CMD = 'cat /etc/shadow'

  def log
    @logger
  end

  def snake_case_symbol_for(string)
    g = string.gsub!(/(.)([A-Z])/,'\1_\2')
    d = string.downcase!
    (g || d).to_sym
  end

  def vagrant_ssh_config
    Hash[`vagrant ssh-config default`.split("\n")
                                     .grep(/^  /)
                                     .map do |s|
                                       a = s.gsub(/^  /, '').split(' ')
                                       [snake_case_symbol_for(a[0]),
                                        a[1].gsub(/(^"|"$)/, '')]
                                     end]
  end

  def ssh_opts
    @ssh_options ||= build_ssh_opts
  end

  def build_ssh_opts
    return [@settings.target_host] unless @settings.target_host == 'vagrant'

    config = vagrant_ssh_config
    [ config[:host_name],
      config[:user],
      { auth_methods: %w(publickey),
        port: config[:port],
        user_known_hosts_file: config[:user_known_hosts_file],
        paranoid: false,
        keys_only: true,
        keys: config[:identity_file],
        logger: nil } ]
  end

  def run_cmd(cmd, sudo: @settings.sudo, nolog: false, ssh: nil)
    orig_cmd = cmd.strip
    cmd = sanitize_cmd orig_cmd, sudo: sudo
    log.debug "\e[1;33m#{ssh ? :remote : ''}\e[0;0m> \e[1;36m#{cmd}\e[0;0m"
    stdout, stderr, status, sig = if ssh
                                    ssh_exec_cmd(ssh, cmd, nolog)
                                  else
                                    exec_cmd(cmd, nolog)
                                  end
    unless status == 0
      log.error(stdout) unless stdout.empty?
      log.fatal(stderr) unless stderr.empty?
      fail("#{'remote ' if ssh}failed: #{orig_cmd.inspect}")
    end
    stdout
  end

  def sanitize_cmd(cmd, sudo: @settings.sudo)
    "LC_ALL=C LANG=C " + (sudo ? "sudo -E #{cmd}" : cmd)
  end

  def ssh_exec_cmd(ssh, cmd, nolog)
    out, err, status, signal = [], [], nil, nil
    channel = ssh.open_channel do |channel|
      channel.exec(cmd) do |ch, success|
        raise "could not execute command #{cmd.inspect}" unless success
        log_stream_from_channel(out, ch, :on_data, :stdout, nolog)
        log_stream_from_channel(err, ch, :on_extended_data, :stderr, nolog)
        ch.on_request('exit-status') { |c, data| status = data.read_long }
        ch.on_request('exit-signal') { |c, data| signal = data.read_long }
        ch.on_close { log.debug 'ssh cmd exec done' }
      end
    end
    channel.wait
    [ out.join("\n"), err.join("\n"), status, signal ]
  end

  def exec_cmd(cmd, nolog)
    out, err, process_status, out_thread, err_thread = [], [], nil, nil, nil
    popen3(cmd) do |stdin, stdout, stderr, wait_thr|
      out_thread = log_stream_in_thread(out, stdout, :stdout, nolog)
      err_thread = log_stream_in_thread(err, stderr, :stderr, nolog)
      stdin.close
      process_status = wait_thr.value
      out_thread.join
      err_thread.join
    end
    [ out.join("\n"), err.join("\n"), process_status.exitstatus ]
  end

  def log_stream_in_thread(tab, stream, type, nolog)
    raise "invalid stream type #{type}" unless %i(stdout stderr).include?(type)
    Thread.new do
      stream.each_line do |line|
        tab << line
        log_stream(line, type, nolog)
      end
    end
  end

  def log_stream(string, type, nolog)
    raise "invalid stream type #{type}" unless %i(stdout stderr).include?(type)
    return if nolog
    type == :stdout ? log.debug(string) : string.empty? && log.error(string)
  end

  def log_stream_from_channel(tab, channel, method, type, nolog)
    raise "invalid stream type #{type}" unless %i(stdout stderr).include?(type)
    channel.send(method) do |_, data|
      string = data.to_s.chomp
      tab << string
      log_stream(string, type, nolog)
    end
  end
end

class Prober
  include FileUtils
  include Singleton

  STEPS = [
    { name: :sysctl_dump, cmd: 'sysctl -a', sudo: true, store: true },
    { name: :dpkg_list, cmd: 'dpkg -l', sudo: false, store: true },
    { name: :etc_tarball,
      cmd: 'tar cfJ - /etc',
      sudo: true,
      store: true,
      nolog: true,
      filename: 'etc.tar.xz' },
    { name: :install_cruft_and_debootstrap,
      cmd: 'apt-get install -y cruft debootstrap',
      sudo: true,
      store: false }
  ]

  attr_reader :command_controller, :settings, :steps_data
  alias :cc :command_controller

  def initialize
    @command_controller = CommandController.instance
    @settings = cc.settings
    @logger = cc.logger
  end

  def run!
    initialize_output_directory!
    @steps_data = {}
    begin
      STEPS.each { |step| run_step!(step) }
    rescue Exception => exception
      log.fatal(exception.message)
      log.fatal(exception.backtrace.join("\n"))
      exit(-1)
    end
  end

  def store_directory
    @out_dir ||= settings.output_directory + settings.target_host
  end

  private

  def log
    @logger
  end

  def run_step!(hash)
    name = hash[:name]
    log.info("starting #{name} step…")
    data = @steps_data[name] = cc.run_remote(hash[:cmd],
                                             sudo: (hash[:sudo] || false),
                                             nolog: (hash[:nolog] || false))
    if hash[:store] == true
      (store_directory + (hash[:filename] || name.to_s)).write(data)
    end
    log.info("#{name} step finished")
  end

  def initialize_output_directory!
    unless store_directory.exist?
      mkdir_p(store_directory)
      log.info("#{store_directory} created")
    end
  end
end

prober = Prober.instance

gem 'pry'
require 'pry'
Pry.start
