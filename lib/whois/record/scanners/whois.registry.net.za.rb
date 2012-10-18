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
          :get_dates,
          :get_status,
          :get_pending_timer_events,
          :get_nameservers,
          :get_disclaimer,
          :catchall
        ]

        tokenizer :get_domain_name do
          if @input.skip_until(/    Domain Name:\n/)
            @ast[:domain_name] = content_in_category.strip
          end
        end

        tokenizer :get_registrant_details do
          if @input.skip_until(/    Registrant:\n/)
            registrant_data = content_in_category.strip
            registrant_lines = registrant_data.split("\n")
            @ast[:registrant_name] = registrant_lines.shift
            @ast[:registrant_email] = registrant_lines.shift.split(":").last.strip
            @ast[:registrant_telephone] = registrant_lines.shift.split(":").last.strip
            @ast[:registrant_fax] = registrant_lines.shift.split(":").last.strip
          end
        end

        tokenizer :get_registrant_address do
          if @input.skip_until(/    Registrant's Address:\n/)
            @ast[:registrant_address] = content_in_category.strip.gsub(/\n\s+/, " ")
          end
        end

        tokenizer :get_registrar_details do
          if @input.skip_until(/    Registrar:\n/)
            content_in_category.strip =~ /(.+) \[ ID = (.+) \]/
            @ast[:registrar_name] = $1.strip
            @ast[:registrar_id] = $2.strip
          end
        end

        tokenizer :get_dates do
          if @input.skip_until(/    Relevant Dates:\n/)
            dates = content_in_category.split("\n")
            @ast[:registration_date] = dates.shift.split(":").last.strip
            @ast[:renewal_date] = dates.shift.split(":").last.strip
          end
        end

        tokenizer :get_status do
          if @input.skip_until(/    Domain Status:\n/)
            statuses = content_in_category.strip
            @ast[:status] = statuses.split(", ")
          end
        end

        tokenizer :get_pending_timer_events do
          if @input.skip_until(/    Pending Timer Events:\n/)
            @ast[:pending_timer_events] = content_in_category.strip
          end
        end

        tokenizer :get_nameservers do
          if @input.skip_until(/    Name Servers:\n/)
            @ast[:nameservers] = content_in_category.strip.gsub(/\n\s+/, ",").split(",")
          end
        end

        tokenizer :get_disclaimer do
          @ast[:disclaimer] = @input.scan_until(/\n--\n.*$/m)
        end

        tokenizer :catchall do
        end

        private

        def content_in_category
          @input.scan_until(/(?=\n    [A-Z])/)
        end
      end
    end
  end
end

