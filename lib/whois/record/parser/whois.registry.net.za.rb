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
            email = get_email(reg_details[1])
            telephone = get_telephone(reg_details[2])
            fax = get_fax(reg_details[3])
          end

          if content_for_scanner =~ /Registrant's Address:\n((.+\n)+)\n/
            address = ($1.split("\n").map { |part| part.strip }).join(" ")
          end

          [Whois::Record::Contact.new(:type => Whois::Record::Contact::TYPE_REGISTRANT, :name => name, :email => email, :phone => telephone, :fax => fax, :address => address)]
        end

        private

        def get_email(email_candidate)
          $1.strip if email_candidate.strip =~ /^Email: (.+)$/
        end

        def get_telephone(telephone_candidate)
          $1.strip if telephone_candidate.strip =~ /^Tel: (.+)$/
        end

        def get_fax(fax_candidate)
          $1.strip if fax_candidate.strip =~ /^Fax: (.+)$/
        end
      end
    end
  end
end
