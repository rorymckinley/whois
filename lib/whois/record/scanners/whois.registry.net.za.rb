#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++

require 'whois/record/scanners/base'

module Whois
  class Record
    module Scanners

      class WhoisRegistryNetZa < Base
        self.tokenizers += [
          :get_domain_name,
          :get_registrant_details,
          :get_registrant_address,
          :get_registrar_details,
          :catchall
        ]

        tokenizer :get_domain_name do
          if @input.skip_until(/    Domain Name:\n/)
            @ast[:domain_name] = @input.scan_until(/(?=\n    [A-Z])/).strip
          end
        end

        tokenizer :get_registrant_details do
          if @input.skip_until(/    Registrant:\n/)
            registrant_data = @input.scan_until(/(?=\n    [A-Z])/).strip
            registrant_lines = registrant_data.split("\n")
            @ast[:registrant_name] = registrant_lines.shift
            @ast[:registrant_email] = registrant_lines.shift.split(":").last.strip
            @ast[:registrant_telephone] = registrant_lines.shift.split(":").last.strip
            @ast[:registrant_fax] = registrant_lines.shift.split(":").last.strip
          end
        end

        tokenizer :get_registrant_address do
          if @input.skip_until(/    Registrant's Address:\n/)
            @ast[:registrant_address] = @input.scan_until(/(?=\n    [A-Z])/).strip.gsub(/\n\s+/, " ")
          end
        end

        tokenizer :get_registrar_details do
          if @input.skip_until(/    Registrar:\n/)
            @input.scan_until(/(?=\n    [A-Z])/).strip =~ /(.+) \[ ID = (.+) \]/
            @ast[:registrar_name] = $1.strip
          end
        end

        tokenizer :catchall do
          @input.scan_until(/.*/m)
        end
      end
    end
  end
end

