require 'whois/record/parser/base'


module Whois
  class Record
    class Parser
      class WhoisRegistryNetZa < Base
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end

        property_supported :registrar do
          if content_for_scanner =~ /Registrar:\n(.+)\[ ID = (.+) \]\s*\n/
            Whois::Record::Registrar.new(:name => $1.strip, :id => $2.strip)
          end
        end

        property_supported :registrant_contacts do
          if content_for_scanner =~ /Registrant:\n((.+\n)+)\n/
            reg_details = $1.split("\n")
            name = reg_details[0].strip
            email = $1.strip if reg_details[1].strip =~ /^Email: (.+)$/
          end
          [Whois::Record::Contact.new(:type => Whois::Record::Contact::TYPE_REGISTRANT, :name => name, :email => email)]
        end
      end
    end
  end
end
