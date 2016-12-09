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

BEGIN { START_TIME = Time.now }

require 'fileutils'
require 'logger'
require 'open3'
require 'optparse'
require 'ostruct'
require 'pathname'
require 'singleton'
require 'set'
require 'securerandom'

gem 'net-ssh'
require 'net/ssh'

VERSION = '0.0.1 alpha'

class CustomLogger < Logger
  COLORS = {
    'DEBUG'   => '0;37', # gray
    'INFO'    => '0;32', # green
    'WARN'    => '0;33', # yellow
    'ERROR'   => '0;31', # red
    'FATAL'   => '1;31', # light red
    'UNKNOWN' => '1;35'  # light purple
  }

  def initialize(logdev = STDERR, **args)
    super(logdev, args)

    self.level = Logger::WARN
    self.formatter = proc do |severity, timestamp, progname, msg|
      format("%s %s(%d) [%s] %s: %s\n",
             timestamp.strftime('%FT%T.%LZ'),
             progname,
             Process.pid,
             Time.at(timestamp.utc - START_TIME + (3600 * 23))
                 .strftime('%M:%S.%Lms'),
             CustomLogger.color(severity),
             msg)
    end
  end

  def self.color(severity)
    color = COLORS[severity]
    raise "invalid logger severity: #{severity.inspect}" if color.nil?

    "\e[#{color}m#{severity}\e[0;0m"
  end
end

class Settings < OpenStruct
  USER_HOST_RG = /^(([a-z0-9_-]+(\.[a-z0-9_-]+)*)@([a-z0-9_-]+(\.[a-z0-9_-]+)*)|
                    vagrant)$/x

  # rubocop:disable Metrics/MethodLength
  # rubocop:disable Metrics/CyclomaticComplexity
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

Usage: #{opts.program_name} [options] user@host
  Where <host> is the remote host name of fqdn used by ssh command and
  <user> is the login.
  When 'vagrant' is specified in place of <user@host>, 'vagrant ssh-config' will
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

      opts.on('-t', '--[no-]dry-run', 'run but only print commands') do |bool|
        settings.logger.debug "dry run mode set to #{bool}"
        settings.test = bool
      end

      opts.on('-p', '--[no-]prompt', 'enable pry console at exit') do |bool|
        settings.logger.debug "at exit pry console set to #{bool}"
        settings.console = bool
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

    settings.banner = "#{settings.option_parser}\n"

    args = settings.option_parser.parse!(args)
    settings.error("wrong user@host argument: #{args.inspect}") \
      if args.size != 1 || !args.first.match(USER_HOST_RG)

    settings.user = Regexp.last_match(2)
    settings.host = Regexp.last_match(4) || Regexp.last_match(1)
    settings.output_directory ||= (Pathname.new(__dir__) + 'output')
    settings
  end
  # rubocop:enable Metrics/CyclomaticComplexity
  # rubocop:enable Metrics/MethodLength

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
    if @settings.test
      return '<dry-run>'
    end

    run_cmd cmd, sudo: sudo, nolog: nolog
  end

  def run_remote(cmd, sudo: @settings.sudo, nolog: false)
    if @settings.test
      return '<dry-run>'
    end

    ::Net::SSH.start(*ssh_opts) do |ssh|
      run_cmd cmd, sudo: sudo, nolog: nolog, ssh: ssh
    end
  end

  def check_access(command = 'cat /etc/passwd', sudo: false)
    return true if @settings.test

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
    return true if @settings.test

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
    return [@settings.host, @settings.user] unless @settings.host == 'vagrant'

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

  # rubocop:disable Metrics/CyclomaticComplexity
  def run_cmd(cmd, sudo: @settings.sudo, nolog: false, ssh: nil)
    orig_cmd = cmd.strip
    cmd = sanitize_cmd orig_cmd, sudo: sudo
    log.debug "\e[1;33m#{ssh ? :remote : ''}\e[0;0m> \e[1;36m#{cmd}\e[0;0m"
    stdout, stderr, status, _sig = if ssh
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
  # rubocop:enable Metrics/CyclomaticComplexity

  def sanitize_cmd(cmd, sudo: @settings.sudo)
    'LC_ALL=C LANG=C DEBIAN_FRONTEND=noninteractive ' +
      (sudo ? "sudo -E #{cmd}" : cmd)
  end

  def ssh_exec_cmd(ssh, cmd, nolog)
    out, err, status, signal = [], [], nil, nil
    channel = ssh.open_channel do |chan|
      chan.exec(cmd) do |ch, success|
        raise "could not execute command #{cmd.inspect}" unless success
        log_stream_from_channel(out, ch, :on_data, :stdout, nolog)
        log_stream_from_channel(err, ch, :on_extended_data, :stderr, nolog)
        ch.on_request('exit-status') { |_c, data| status = data.read_long }
        ch.on_request('exit-signal') { |_c, data| signal = data.read_long }
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

  IGNORES_DIRS = %w(/dev
                    /home
                    /run
                    /tmp
                    /vagrant
                    /var/cache/apt/archives)

  STEPS = [
    { name: :sysctl_dump, cmd: 'sysctl -a', sudo: true, store: true },
    { name: :dpkg_list, cmd: 'dpkg -l', sudo: false, store: true },
    { name: :etc_tarball,
      cmd: 'tar cfz - /etc',
      sudo: true,
      store: true,
      nolog: true,
      filename: 'etc.tgz' },
    { name: :install_cruft,
      cmd: 'apt-get install -y cruft',
      sudo: true,
      store: false },
    { name: :cruft,
      cmd: "cruft --ignore '#{IGNORES_DIRS.join(' ')}' -d /",
      sudo: true,
      store: true },
    { name: :install_debsums,
      cmd: 'apt-get install -y debsums',
      sudo: true,
      store: false },
    { name: :debsums,
      cmd: "debsums -a -c -l",
      sudo: true,
      store: true }
  ]

  attr_reader :command_controller, :settings, :steps_data
  alias :cc :command_controller

  def initialize
    @command_controller = CommandController.instance
    @settings = cc.settings
    @logger = cc.logger
    @steps_data = {}
  end

  def base_packages_path
    @bpp ||= settings.output_directory + "#{settings.debian_dist}_base_packages"
  end

  def base_packages_symbol
    @bps ||= base_packages_path.basename.to_s.to_sym
  end

  def run!
    @steps_data.clear
    initialize_output_directory!
    build_base_packages_list!

    # rubocop:disable Lint/RescueException
    begin
      STEPS.each { |step| run_step!(step) }
    rescue Exception => exception
      log.fatal(exception.message)
      log.fatal(exception.backtrace.join("\n"))
      exit(-1)
    end
    # rubocop:enable Lint/RescueException
  end

  def store_directory
    @out_dir ||= settings.output_directory + settings.host
  end

  def packages_diff_stats
    packages_diff.map { |k, v| [k.to_sym, v.size ] }.to_h
  end

  def packages_diff
    return @packages_diff if @packages_diff

    raise 'no data collected' \
      unless steps_data.key?(base_packages_symbol) && steps_data.key?(:dpkg_list)

    official = SortedSet.new(steps_data[base_packages_symbol].split(' ').sort)
    target =
      SortedSet.new(steps_data[:dpkg_list].split("\n")
                                          .map! do |line|
                                            next if line !~ /^ii  ([0-9a-z+.-]+)(\s|:)/
                                            Regexp.last_match(1)
                                          end
                                          .compact!
                                          .sort!)
    shared = target & official
    unshared = target ^ official

    @packages_diff = { official: official.to_a,
                       target: target.to_a,
                       shared: shared.to_a,
                       unshared: unshared.to_a,
                       added: (unshared & target).to_a,
                       removed: (unshared & official).to_a }
  end

  def cruft_stats
    cruft.map { |k, v| [k.to_sym, v.size ] }.to_h
  end

  # rubocop:disable Metrics/CyclomaticComplexity
  def cruft
    return @cruft if @cruft

    raise 'no data collected' unless steps_data.key?(:cruft)

    @cruft = Hash.new { |h, k| h[k] = [] }
    key = nil

    steps_data[:cruft].split("\n").each do |line|
       case line
       when /^---- (\w+(\s+\w+)*): [A-Za-z0-9_\/-] ----$/
         key = Regexp.last_match(1).tr(' ', '_').to_sym
       when /^(cruft report: .*|end\.|)$/
       when /^    (.+)$/
         @cruft[key] << Regexp.last_match(1).lstrip
       else
         raise "unparsable #{line.inspect}" unless @settings.test
       end
    end

    @cruft
  end
  # rubocop:enable Metrics/CyclomaticComplexity

  def results
    { cruft: cruft, packages_diff: packages_diff }
  end

  def reports
    { cruft: cruft_stats, packages_diff: packages_diff_stats }
  end

  private

  def log
    @logger
  end

  # rubocop:disable Metrics/CyclomaticComplexity
  def run_step!(hash)
    name = hash[:name]
    log.info("starting #{name} step…")

    params = [hash[:cmd], { sudo: (hash[:sudo] || false),
                            nolog: (hash[:nolog] || false) }]

    data = @steps_data[name] =
        hash[:local] ? cc.run_local(*params) : cc.run_remote(*params)

    case hash[:store]
    when :common
      (settings.output_directory + (hash[:filename] || name.to_s)).write(data)
    when true
      (store_directory + (hash[:filename] || name.to_s)).write(data)
    end
    log.info("#{name} step finished")
  end
  # rubocop:enable Metrics/CyclomaticComplexity

  def initialize_output_directory!
    unless store_directory.exist?
      mkdir_p(store_directory)
      log.info("#{store_directory} created")
    end
  end

  def build_base_packages_list!
    if base_packages_path.exist?
      @steps_data[base_packages_symbol] = base_packages_path.read
      return
    end

    cmd = %W(/usr/sbin/debootstrap
             --include=openssh-server
             --print-debs
             #{settings.debian_dist}
             /tmp/#{SecureRandom.hex}).join(' ')

    STEPS.unshift({ name: base_packages_symbol,
                    local: true,
                    cmd: cmd,
                    store: :common })
  end
end

if __FILE__ == $0
  prober = Prober.instance
  steps = prober.run!

  require 'json'
  puts JSON.pretty_generate({
    steps: steps,
    results: prober.results,
    reports: prober.reports
  })

  if prober.settings.console
    require 'pry'
    Pry.start
  end
end
